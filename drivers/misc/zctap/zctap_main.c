#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/uio.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/memory.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/anon_inodes.h>
#include <linux/indirect_call_wrapper.h>

#include <net/tcp.h>
#include <net/transp_v6.h>

#include <net/zctap.h>
#include <uapi/misc/zctap.h>
#include "zctap_priv.h"

static struct mutex zctap_lock;
static const struct file_operations zctap_fops;
static void zctap_free_ctx(struct zctap_ctx *ctx);

INDIRECT_CALLABLE_DECLARE(dma_addr_t
	zctap_host_get_dma(struct zctap_dmamap *map, unsigned long addr));
INDIRECT_CALLABLE_DECLARE(int
	zctap_host_get_page(struct zctap_dmamap *map, unsigned long addr,
			     struct page **page, dma_addr_t *dma));
INDIRECT_CALLABLE_DECLARE(int
	zctap_host_get_pages(struct zctap_region *r, struct page **pages,
			      unsigned long addr, int count));

#if IS_MODULE(CONFIG_ZCTAP)
#define MODULE_EXPORT_SYMBOL(s)
#else
#define MODULE_EXPORT_SYMBOL(s)	EXPORT_SYMBOL(s)
#endif

#define ZCTAP_CACHE_COUNT	63

enum zctap_match_id {
	ZCTAP_MATCH_TCP6,
	ZCTAP_MATCH_UDP6,
	ZCTAP_MATCH_TCP,
	ZCTAP_MATCH_UDP,
};

struct zctap_sock_match {
	u16 family;
	u16 type;
	u16 protocol;
	u16 initialized;
	struct proto *base_prot;
	const struct proto_ops *base_ops;
	struct proto prot;
	struct proto_ops ops;
};

static struct zctap_sock_match zctap_match_tbl[] = {
	[ZCTAP_MATCH_TCP6] = {
		.family		= AF_INET6,
		.type		= SOCK_STREAM,
		.protocol	= IPPROTO_TCP,
	},
	[ZCTAP_MATCH_UDP6] = {
		.family		= AF_INET6,
		.type		= SOCK_DGRAM,
		.protocol	= IPPROTO_UDP,
	},
	[ZCTAP_MATCH_TCP] = {
		.family		= AF_INET,
		.type		= SOCK_STREAM,
		.protocol	= IPPROTO_TCP,
	},
	[ZCTAP_MATCH_UDP] = {
		.family		= AF_INET,
		.type		= SOCK_DGRAM,
		.protocol	= IPPROTO_UDP,
	},
};

static void
__zctap_put_page_any(struct zctap_ifq *ifq, struct page *page)
{
	struct zctap_pgcache *cache = ifq->any_cache;
	unsigned count;
	size_t sz;

	/* unsigned: count == -1 if !cache, so the check will fail. */
	count = ifq->any_cache_count;
	if (count < ZCTAP_CACHE_COUNT) {
		cache->page[count] = page;
		ifq->any_cache_count = count + 1;
		return;
	}

	sz = struct_size(cache, page, ZCTAP_CACHE_COUNT);
	cache = kmalloc(sz, GFP_ATOMIC);
	if (!cache) {
		/* XXX fixme */
		pr_err("zct: addr 0x%lx lost to overflow\n",
		       page_private(page));
		return;
	}
	cache->next = ifq->any_cache;

	cache->page[0] = page;
	ifq->any_cache = cache;
	ifq->any_cache_count = 1;
}

static void
zctap_put_page_any(struct zctap_ifq *ifq, struct page *page)
{
	spin_lock(&ifq->pgcache_lock);

	__zctap_put_page_any(ifq, page);

	spin_unlock(&ifq->pgcache_lock);
}

static void
zctap_put_page_napi(struct zctap_ifq *ifq, struct page *page)
{
	struct zctap_pgcache *spare;
	unsigned count;
	size_t sz;

	count = ifq->napi_cache_count;
	if (count < ZCTAP_CACHE_COUNT) {
		ifq->napi_cache->page[count] = page;
		ifq->napi_cache_count = count + 1;
		return;
	}

	spare = ifq->spare_cache;
	if (spare) {
		ifq->spare_cache = NULL;
		goto out;
	}

	sz = struct_size(spare, page, ZCTAP_CACHE_COUNT);
	spare = kmalloc(sz, GFP_ATOMIC);
	if (!spare) {
		pr_err("zct: addr 0x%lx lost to overflow\n",
		       page_private(page));
		return;
	}
	spare->next = ifq->napi_cache;

out:
	spare->page[0] = page;
	ifq->napi_cache = spare;
	ifq->napi_cache_count = 1;
}

void
zctap_put_page(struct zctap_ifq *ifq, struct page *page, bool napi)
{
	if (napi)
		zctap_put_page_napi(ifq, page);
	else
		zctap_put_page_any(ifq, page);
}
MODULE_EXPORT_SYMBOL(zctap_put_page);

static int
zctap_swap_caches(struct zctap_ifq *ifq, struct zctap_pgcache **cachep)
{
	int count;

	spin_lock(&ifq->pgcache_lock);

	count = ifq->any_cache_count;
	*cachep = ifq->any_cache;
	ifq->any_cache = ifq->napi_cache;
	ifq->any_cache_count = 0;

	spin_unlock(&ifq->pgcache_lock);

	return count;
}

static struct page *
zctap_get_cached_page(struct zctap_ifq *ifq)
{
	struct zctap_pgcache *cache = ifq->napi_cache;
	struct page *page;
	int count;

	count = ifq->napi_cache_count;

	if (!count) {
		if (cache->next) {
			kfree(ifq->spare_cache);
			ifq->spare_cache = cache;
			cache = cache->next;
			count = ZCTAP_CACHE_COUNT;
			goto out;
		}

		/* lockless read of any count - if <= 0, skip */
		count = READ_ONCE(ifq->any_cache_count);
		if (count > 0) {
			count = zctap_swap_caches(ifq, &cache);
			goto out;
		}

		return NULL;
out:
		ifq->napi_cache = cache;
	}

	page = cache->page[--count];
	ifq->napi_cache_count = count;

	return page;
}

/*
 * Free cache structures.  Pages have already been released.
 */
static void
zctap_free_cache(struct zctap_ifq *ifq)
{
	struct zctap_pgcache *cache, *next;

	kfree(ifq->spare_cache);

	for (cache = ifq->napi_cache; cache; cache = next) {
		next = cache->next;
		kfree(cache);
	}

	for (cache = ifq->any_cache; cache; cache = next) {
		next = cache->next;
		kfree(cache);
	}
}

/*
 * Called from iov_iter when addr is provided for TX.
 */
int
zctap_get_pages(void *udata, struct page **pages, unsigned long addr, int count)
{
	struct zctap_skq *skq = udata;
	struct zctap_dmamap *map;

	map = xa_load(&skq->ctx->xa, addr >> PAGE_SHIFT);
	if (!map)
		return -EINVAL;

	return INDIRECT_CALL_1(map->get_pages, zctap_host_get_pages,
			       map->r, pages, addr, count);
}

static int
zctap_get_fill_page(struct zctap_ifq *ifq, dma_addr_t *dma, struct page **page)
{
	struct zctap_dmamap *map;
	u64 *addrp, addr;
	int err;

	addrp = sq_cons_peek(&ifq->fill);
	if (!addrp)
		return -ENOMEM;

	addr = READ_ONCE(*addrp);

	map = xa_load(&ifq->ctx->xa, addr >> PAGE_SHIFT);
	if (!map)
		return -EINVAL;

	err = INDIRECT_CALL_1(map->get_page, zctap_host_get_page,
			      map, addr, page, dma);

	if (!err)
		sq_cons_advance(&ifq->fill);

	return err;
}

dma_addr_t
zctap_frag_for_device(struct zctap_ctx *ctx, skb_frag_t *frag)
{
	struct zctap_dmamap *map;
	dma_addr_t dma_addr;
	unsigned long addr;

	addr = page_private(skb_frag_page(frag));
	map = xa_load(&ctx->xa, addr >> PAGE_SHIFT);
	dma_addr = INDIRECT_CALL_1(map->get_dma, zctap_host_get_dma,
			           map, addr);
	dma_addr += skb_frag_off(frag);
	if (map->flags & ZCTAP_DMAFLAG_SYNC)
		dma_sync_single_range_for_device(map->device, dma_addr, 0,
						 skb_frag_size(frag),
						 DMA_BIDIRECTIONAL);
	return dma_addr;
}
MODULE_EXPORT_SYMBOL(zctap_frag_for_device);

static int
zctap_get_dma(struct zctap_ctx *ctx, dma_addr_t *dma, struct page **page)
{
	struct zctap_dmamap *map;
	unsigned long addr;

	addr = page_private(*page);
	map = xa_load(&ctx->xa, addr >> PAGE_SHIFT);

	*dma = INDIRECT_CALL_1(map->get_dma, zctap_host_get_dma,
			       map, addr);
	*page = zctap_set_page(*page, map->flags & ZCTAP_DMAFLAG_SYNC);
	return 0;
}

int
zctap_get_page(struct zctap_ifq *ifq, struct page **page, dma_addr_t *dma)
{
	*page = zctap_get_cached_page(ifq);
	if (*page) {
		get_page(*page);
		return zctap_get_dma(ifq->ctx, dma, page);
	}
	return zctap_get_fill_page(ifq, dma, page);

}
MODULE_EXPORT_SYMBOL(zctap_get_page);

static int
zctap_shared_queue_validate(struct zctap_user_queue *u, unsigned elt_size,
			    unsigned map_off)
{
	struct zctap_queue_map *map;
	unsigned count;
	size_t size;

	if (u->elt_sz != elt_size)
		return -EINVAL;

	count = roundup_pow_of_two(u->entries);
	if (!count)
		return -EINVAL;
	u->entries = count;
	u->mask = count - 1;
	u->map_off = map_off;

	size = struct_size(map, data, count * elt_size);
	if (size == SIZE_MAX || size > U32_MAX)
		return -EOVERFLOW;
	u->map_sz = size;

	return 0;
}

static void
zctap_shared_queue_free(struct shared_queue *q)
{
	free_pages((uintptr_t)q->map_ptr, get_order(q->map_sz));
}

static int
zctap_shared_queue_create(struct shared_queue *q, struct zctap_user_queue *u)
{
	gfp_t gfp_flags = GFP_KERNEL | __GFP_ZERO | __GFP_NOWARN |
			  __GFP_COMP | __GFP_NORETRY;
	struct zctap_queue_map *map;

	map = (void *)__get_free_pages(gfp_flags, get_order(u->map_sz));
	if (!map)
		return -ENOMEM;

	q->map_ptr = map;
	q->prod = &map->prod;
	q->cons = &map->cons;
	q->data = &map->data[0];
	q->elt_sz = u->elt_sz;
	q->mask = u->mask;
	q->entries = u->entries;
	q->map_sz = u->map_sz;

	memset(&u->off, 0, sizeof(u->off));
	u->off.prod = offsetof(struct zctap_queue_map, prod);
	u->off.cons = offsetof(struct zctap_queue_map, cons);
	u->off.data = offsetof(struct zctap_queue_map, data);

	return 0;
}

static int
__zctap_queue_mgmt(struct net_device *dev, struct zctap_ifq *ifq,
		    u32 *queue_id)
{
	struct netdev_bpf cmd;
	bpf_op_t ndo_bpf;
	int err;

	ndo_bpf = dev->netdev_ops->ndo_bpf;
	if (!ndo_bpf)
		return -EINVAL;

	cmd.command = XDP_SETUP_ZCTAP;
	cmd.zct.ifq = ifq;
	cmd.zct.queue_id = *queue_id;

	err = ndo_bpf(dev, &cmd);
	if (!err)
		*queue_id = cmd.zct.queue_id;

	return err;
}

static int
zctap_open_queue(struct zctap_ifq *ifq, u32 *queue_id)
{
	return __zctap_queue_mgmt(ifq->ctx->dev, ifq, queue_id);
}

static int
zctap_close_queue(struct zctap_ifq *ifq, u32 queue_id)
{
	return __zctap_queue_mgmt(ifq->ctx->dev, NULL, &queue_id);
}

static int
zctap_mmap(void *priv, struct vm_area_struct *vma,
	    void *(*validate_request)(void *priv, loff_t, size_t))
{
	size_t sz = vma->vm_end - vma->vm_start;
	unsigned long pfn;
	void *ptr;

	ptr = validate_request(priv, vma->vm_pgoff, sz);
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);

	pfn = virt_to_phys(ptr) >> PAGE_SHIFT;
	return remap_pfn_range(vma, vma->vm_start, pfn, sz, vma->vm_page_prot);
}

static void *
zctap_validate_ifq_mmap_request(void *priv, loff_t pgoff, size_t sz)
{
	struct zctap_ifq *ifq = priv;
	struct page *page;
	void *ptr;

	/* each returned ptr is a separate allocation. */
	switch (pgoff << PAGE_SHIFT) {
	case ZCTAP_OFF_FILL_ID:
		ptr = ifq->fill.map_ptr;
		break;
	default:
		return ERR_PTR(-EINVAL);
	}

	page = virt_to_head_page(ptr);
	if (sz > page_size(page))
		return ERR_PTR(-EINVAL);

	return ptr;
}

static int
zctap_ifq_mmap(struct file *file, struct vm_area_struct *vma)
{
	return zctap_mmap(file->private_data, vma,
			   zctap_validate_ifq_mmap_request);
}

static void
zctap_free_ifq(struct zctap_ifq *ifq)
{
	/* assume ifq has been released from ifq list */
	if (ifq->queue_id != -1)
		zctap_close_queue(ifq, ifq->queue_id);
	zctap_shared_queue_free(&ifq->fill);
	zctap_free_cache(ifq);
	kfree(ifq);
}

static int
zctap_ifq_release(struct inode *inode, struct file *file)
{
	struct zctap_ifq *ifq = file->private_data;
	struct zctap_ctx *ctx = ifq->ctx;

	/* CTX LOCKING */
	list_del(&ifq->ifq_node);
	zctap_free_ifq(ifq);

	zctap_free_ctx(ctx);
	return 0;
}

#if 0
static int
zctap_ifq_wakeup(struct zctap_ifq *ifq)
{
	struct net_device *dev = ifq->ctx->dev;
	int err;

	rcu_read_lock();
	err = dev->netdev_ops->ndo_xsk_wakeup(dev, ifq->queue_id, flags);
	rcu_read_unlock();

	return err;
}
#endif

static __poll_t
zctap_ifq_poll(struct file *file, poll_table *wait)
{
	struct zctap_ifq *ifq = file->private_data;
	__poll_t mask = 0;

	poll_wait(file, &ifq->fill_wait, wait);

	if (sq_prod_space(&ifq->fill))
		mask = EPOLLOUT | EPOLLWRNORM;

#if 0
	if (driver is asleep because fq is/was empty)
		zctap_ifq_wakeup(ifq);
#endif

	return mask;
}

static const struct file_operations zctap_ifq_fops = {
	.owner =		THIS_MODULE,
	.mmap =			zctap_ifq_mmap,
	.poll =			zctap_ifq_poll,
	.release =		zctap_ifq_release,
};

static int
zctap_create_fd(struct zctap_ifq *ifq, struct file **filep)
{
	struct file *file;
	unsigned flags;
	int fd;

	flags = O_RDWR | O_CLOEXEC;
	fd = get_unused_fd_flags(flags);
	if (fd < 0)
		return fd;

	file = anon_inode_getfile("[zct]", &zctap_ifq_fops, ifq, flags);
	if (IS_ERR(file)) {
		put_unused_fd(fd);
		return PTR_ERR(file);
	}

	*filep = file;
	return fd;
}

/* This callback is attached to skbs which contain pages allocated from
 * the ifq page pool.  Normally, the skb receive routine will detach the
 * pages and deliver them to userspace.  On error or shutdown, the
 * undelivered pages are unreferenced here.
 *
 * TX skbs do not arrive at this point unless they were forwarded from
 * the RX path.
 *
 * XXX if they are forwarded, then uarg is a tx uarg, not a rx uarg.
 * XXX no ifq in that case.  fix.
 */
static void
zctap_rx_callback(struct sk_buff *skb, struct ubuf_info *uarg, bool success)
{
	struct zctap_ifq *ifq = container_of(uarg, struct zctap_ifq, uarg);
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	struct page *page;
	int i;

	for (i = 0; i < shinfo->nr_frags; i++) {
		page = skb_frag_page(&shinfo->frags[i]);
		if (page && page_ref_dec_return(page) <= 2)
			zctap_put_page_any(ifq, page);
	}
	shinfo->nr_frags = 0;
}

static struct zctap_ifq *
zctap_alloc_ifq(struct zctap_ctx *ctx)
{
	struct zctap_ifq *ifq;
	size_t sz;

	ifq = kzalloc(sizeof(*ifq), GFP_KERNEL);
	if (!ifq)
		return NULL;

	sz = struct_size(ifq->napi_cache, page, ZCTAP_CACHE_COUNT);
	ifq->napi_cache = kmalloc(sz, GFP_KERNEL);
	if (!ifq->napi_cache)
		goto out;
	ifq->napi_cache->next = NULL;

	ifq->ctx = ctx;
	ifq->queue_id = -1;
	ifq->any_cache_count = -1;
	spin_lock_init(&ifq->pgcache_lock);
	ifq->uarg.callback = zctap_rx_callback;
	ifq->uarg.zc_flags = SKBZC_FRAGMENTS | SKBZC_FIXED;
	ifq->uarg.zerocopy = true;
	ifq->uarg.ctx = ctx;		/* XXX */

	return ifq;

out:
	kfree(ifq->napi_cache);
	kfree(ifq);

	return NULL;
}

static int
zctap_split_validate(const struct zctap_ifq_param *p, struct zctap_ifq *ifq)
{
	switch (p->hdsplit) {
	case ZCTAP_SPLIT_NONE:
		ifq->split_offset = 0;
		break;
	case ZCTAP_SPLIT_OFFSET:
		if (p->split_offset > U8_MAX)
			return -EINVAL;
		ifq->split_offset = p->split_offset;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int
zctap_bind_queue(struct zctap_ctx *ctx, void __user *arg)
{
	struct zctap_ifq_param p;
	struct file *file = NULL;
	struct zctap_ifq *ifq;
	int err;

	if (!ctx->dev)
		return -ENODEV;

	if (copy_from_user(&p, arg, sizeof(p)))
		return -EFAULT;

	if (p.resv != 0)
		return -EINVAL;

	if (p.queue_id != -1) {
		list_for_each_entry(ifq, &ctx->ifq_list, ifq_node)
			if (ifq->queue_id == p.queue_id)
				return -EALREADY;
	}

	err = zctap_shared_queue_validate(&p.fill, sizeof(u64),
					  ZCTAP_OFF_FILL_ID);
	if (err)
		return err;

	ifq = zctap_alloc_ifq(ctx);
	if (!ifq)
		return -ENOMEM;

	err = zctap_split_validate(&p, ifq);
	if (err)
		goto out;

	err = zctap_shared_queue_create(&ifq->fill, &p.fill);
	if (err)
		goto out;

	err = zctap_open_queue(ifq, &p.queue_id);
	if (err)
		goto out;
	ifq->queue_id = p.queue_id;

	p.ifq_fd = zctap_create_fd(ifq, &file);
	if (p.ifq_fd < 0) {
		err = p.ifq_fd;
		goto out;
	}

	if (copy_to_user(arg, &p, sizeof(p))) {
		err = -EFAULT;
		goto out;
	}

	fd_install(p.ifq_fd, file);
	list_add(&ifq->ifq_node, &ctx->ifq_list);
	refcount_inc(&ctx->ref);

	return 0;

out:
	if (file) {
		fput(file);
		put_unused_fd(p.ifq_fd);
	}
	zctap_free_ifq(ifq);

	return err;
}

static bool
zctap_region_overlap(struct zctap_ctx *ctx, struct zctap_dmamap *map)
{
	unsigned long index, last;

	index = map->start >> PAGE_SHIFT;
	last = index + map->nr_pages - 1;

	return xa_find(&ctx->xa, &index, last, XA_PRESENT) != NULL;
}

struct zctap_dmamap *
zctap_ctx_detach_region(struct zctap_ctx *ctx, struct zctap_region *r)
{
	struct zctap_dmamap *map;
	unsigned long start;

	start = r->start >> PAGE_SHIFT;
	map = xa_load(&ctx->xa, start);
	xa_store_range(&ctx->xa, start, start + r->nr_pages - 1,
		       NULL, GFP_KERNEL);

	return map;
}

static int
zctap_attach_region(struct zctap_ctx *ctx, void __user *arg)
{
	struct zctap_attach_param p;
	struct zctap_dmamap *map;
	struct zctap_mem *mem;
	unsigned long start;
	struct fd f;
	int err;

	if (!ctx->dev)
		return -ENODEV;

	if (copy_from_user(&p, arg, sizeof(p)))
		return -EFAULT;

	f = fdget(p.mem_fd);
	if (!f.file)
		return -EBADF;

	if (f.file->f_op != &zctap_mem_fops) {
		fdput(f);
		return -EOPNOTSUPP;
	}

	mem = f.file->private_data;
	map = zctap_mem_attach_ctx(mem, p.mem_idx, ctx);
	if (IS_ERR(map)) {
		fdput(f);
		return PTR_ERR(map);
	}

	/* XXX "should not happen", validate anyway */
	if (zctap_region_overlap(ctx, map)) {
		zctap_map_detach_ctx(map, ctx);
		return -EEXIST;
	}

	start = map->start >> PAGE_SHIFT;
	err = xa_err(xa_store_range(&ctx->xa, start, start + map->nr_pages - 1,
				    map, GFP_KERNEL));
	if (err)
		zctap_map_detach_ctx(map, ctx);

	return err;
}

static int
zctap_attach_dev(struct zctap_ctx *ctx, void __user *arg)
{
	struct net_device *dev;
	int ifindex;
	int err;

	if (copy_from_user(&ifindex, arg, sizeof(ifindex)))
		return -EFAULT;

	dev = dev_get_by_index(&init_net, ifindex);
	if (!dev)
		return -ENODEV;

	if (ctx->dev) {
		err = dev == ctx->dev ? 0 : -EALREADY;
		dev_put(dev);
		return err;
	}

	ctx->dev = dev;

	return 0;
}

struct zctap_read_desc {
	read_descriptor_t desc;
	void *data;
	void *limit;
};

static inline struct iovec *
zctap_next_vec(struct zctap_read_desc *rd)
{
	struct zctap_skq *skq = rd->desc.arg.data;
	void *ptr, *next;

	/* TCP does not have a metadata area, use RX queue directly */
	ptr = rd->data;
	if (!ptr)
		return sq_prod_reserve(&skq->rx);

	next = ptr + sizeof(struct iovec);
	if (unlikely(next > rd->limit))
		return NULL;

	rd->data = next;
	return ptr;
}

static inline bool
zctap_skb_ours(struct sk_buff *skb)
{
	struct ubuf_info *uarg = skb_zcopy(skb);

	return uarg && uarg->callback == zctap_rx_callback;
}

/* Our version of __skb_datagram_iter  -- should work for UDP also. */
static int
zctap_recv_skb(read_descriptor_t *desc, struct sk_buff *skb,
	       unsigned int offset, size_t len)
{
	struct zctap_read_desc *rd;
	struct sk_buff *frag_iter;
	struct iovec *iov;
	struct page *page;
	unsigned start;
	int i, used;
	u64 addr;

	rd = container_of(desc, struct zctap_read_desc, desc);

	if (skb_headlen(skb) || !zctap_skb_ours(skb)) {
		pr_err_ratelimited("zc socket seeing non-zc data, len:%d",
				   skb_headlen(skb));
		return -EFAULT;
	}

	used = 0;
	start = 0;

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		skb_frag_t *frag;
		int end, off, frag_len;

		frag = &skb_shinfo(skb)->frags[i];
		frag_len = skb_frag_size(frag);

		end = start + frag_len;
		if (offset < end) {
			off = offset - start;

			iov = zctap_next_vec(rd);
			if (!iov)
				break;

			page = skb_frag_page(frag);
			addr = (u64)page_private(page) + off;

			iov->iov_base = (void *)(addr + skb_frag_off(frag));
			iov->iov_len = frag_len - off;

			used += (frag_len - off);
			offset += (frag_len - off);

			put_page(page);
			__skb_frag_set_page(frag, NULL);
		}
		start = end;
	}

	skb_walk_frags(skb, frag_iter) {
		int end, off, ret;

		end = start + frag_iter->len;
		if (offset < end) {
			off = offset - start;
			len = frag_iter->len - off;

			ret = zctap_recv_skb(desc, frag_iter, off, len);
			if (ret < 0) {
				if (!used)
					used = ret;
				goto out;
			}
			used += ret;
			if (ret < len)
				goto out;
			offset += ret;
		}
		start = end;
	}

out:
	return used;
}

static void
zctap_read_sock(struct sock *sk, struct zctap_skq *skq)
{
	struct zctap_read_desc rd;
	int used;

	rd.desc.arg.data = skq;
	rd.desc.count = 1;
	rd.data = NULL;
	used = tcp_read_sock(sk, &rd.desc, zctap_recv_skb);
	if (used > 0)
		sq_prod_submit(&skq->rx);

}

/*
 * UDP read is all or none - no partial read of the packet.
 *  need to figure out how this works.	For now, assume that each packet
 *  can have MAX_SKB_FRAGS, and only come here if there are that many
 *  rx slots available.  If there are more (listification?), handle it later.
 *  Reserve one slot for data?
 *
 * layout:
 *	iovec[iov_count]	// data len
 *	socket name		// name len
 *	cmsg			// cmsg len
 */
struct udp_meta {
	u16	data_len;	// XXX redundant?  sum iov[].iov_len instead?
	u8	iov_count;
	u8	name_len;
	u8	cmsg_len;
	u8	_pad;
	u16	flags;
	u8	data[];
};

struct zctap_meta {
	struct shared_queue q;
	unsigned long start;
	unsigned long nr_pages;
	void *kaddr;
	struct page **page;
	int meta_len;
};

static void *
zctap_metadata_kaddr(struct zctap_meta *m, u64 addr)
{
	unsigned long off;

	off = addr - m->start;
	if (addr < m->start || off >= (m->nr_pages << PAGE_SHIFT))
		return NULL;
	return m->kaddr + off;
}

static int
zctap_copy_sockaddr(struct zctap_read_desc *rd, struct sock *sk,
		    struct sk_buff *skb, bool is_udp4)
{
	DECLARE_SOCKADDR(struct sockaddr_in6 *, sin6, rd->data);
	int len;

	len = rd->limit - rd->data;
	if (len < sizeof(*sin6))
		return 0;
	rd->data += sizeof(*sin6);

	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = udp_hdr(skb)->source;
	sin6->sin6_flowinfo = 0;

	if (is_udp4) {
		ipv6_addr_set_v4mapped(ip_hdr(skb)->saddr, &sin6->sin6_addr);
		sin6->sin6_scope_id = 0;
	} else {
		sin6->sin6_addr = ipv6_hdr(skb)->saddr;
		sin6->sin6_scope_id =
			ipv6_iface_scope_id(&sin6->sin6_addr, inet6_iif(skb));
	}

	return sizeof(*sin6);
}

int
zctap_deliver_udp(struct sock *sk, struct sk_buff *skb)
{
	struct zctap_skq *skq = sk->sk_user_data;
	struct zctap_meta *m = skq->meta;
	struct zctap_read_desc rd;
	struct udp_meta *meta;
	struct msghdr msg;
	u64 *addrp, addr;
	int used, len;
	bool is_udp4;

	if (skb_headlen(skb) || !zctap_skb_ours(skb)) {
		pr_err_ratelimited("zctap_deliver_udp error, len:%d",
				   skb_headlen(skb));
		return -EFAULT;
	}
	if (skb->len == 0) {
		pr_err_ratelimited("0 length skb??\n");
		return -EFAULT;
	}
	if (!m) {
		pr_err_ratelimited("no skq metadata\n");
		return -EFAULT;
	}

	spin_lock(&sk->sk_receive_queue.lock);

	len = m->meta_len;
	addrp = sq_cons_peek(&m->q);
	if (!addrp) {
		used = -ENOMEM;
		goto drop;
	}
	addr = READ_ONCE(*addrp);

	meta = zctap_metadata_kaddr(m, addr);
	if (!meta) {
		used = -EFAULT;
		goto drop;
	}

	is_udp4 = (skb->protocol == htons(ETH_P_IP));

	rd.desc.written = 0;
	rd.desc.count = 1;
	rd.data = meta->data;
	rd.limit = meta + len;

	used = zctap_recv_skb(&rd.desc, skb, 0, skb->len);
	if (used < 0)
		goto drop;

	meta->iov_count = (rd.data - (void *)meta->data) / sizeof(struct iovec);
	meta->data_len = used;
	meta->flags = used == skb->len ? 0 : MSG_TRUNC;

//	SNMP_INC_STATS(mib, UDP_MIB_INDATAGRAMS);

	meta->name_len = zctap_copy_sockaddr(&rd, sk, skb, is_udp4);

	msg.msg_flags = 0;
	msg.msg_control_is_user = false;
	msg.msg_control = rd.data;
	msg.msg_controllen = rd.limit - rd.data;

	sock_recv_ts_and_drops(&msg, sk, skb);

	if (udp_sk(sk)->gro_enabled)
		udp_cmsg_recv(&msg, sk, skb);

	if (inet6_sk(sk)->rxopt.all) {
		ip6_datagram_recv_common_ctl(sk, &msg, skb);
		ip6_datagram_recv_specific_ctl(sk, &msg, skb);
	}

	meta->flags |= msg.msg_flags;
	meta->cmsg_len = rd.data - msg.msg_control;

	addrp = sq_prod_reserve(&skq->rx);
	if (!addrp) {
		used = -ENOBUFS;
		goto drop;
	}

	*addrp = addr;
	sq_prod_submit(&skq->rx);
	sq_cons_advance(&m->q);
	sq_cons_complete(&m->q);	/* should probably batch this */

	spin_unlock(&sk->sk_receive_queue.lock);

	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_data_ready(sk);

	kfree_skb(skb);
	return 0;

drop:
	spin_unlock(&sk->sk_receive_queue.lock);
	/* caller drops skb on error */
	atomic_inc(&sk->sk_drops);
	return used;
}

static void
zctap_data_ready(struct sock *sk)
{
	struct zctap_skq *skq = sk->sk_user_data;

	if (skq->rx.entries)
		zctap_read_sock(sk, skq);

	skq->sk_data_ready(sk);
}

static bool
zctap_stream_memory_read(const struct sock *sk)
{
	struct zctap_skq *skq = sk->sk_user_data;

	return !sq_is_empty(&skq->rx);
}

static bool
zctap_stream_memory_rdband(const struct sock *sk)
{
	struct zctap_skq *skq = sk->sk_user_data;

	return !sq_is_empty(&skq->cq);
}

static void *
zctap_validate_skq_mmap_request(void *priv, loff_t pgoff, size_t sz)
{
	struct zctap_skq *skq = priv;
	struct page *page;
	void *ptr;

	/* each returned ptr is a separate allocation. */
	switch (pgoff << PAGE_SHIFT) {
	case ZCTAP_OFF_RX_ID:
		ptr = skq->rx.map_ptr;
		break;
	case ZCTAP_OFF_CQ_ID:
		ptr = skq->cq.map_ptr;
		break;
	case ZCTAP_OFF_META_ID:
		if (!skq->meta)
			return ERR_PTR(-EEXIST);
		ptr = skq->meta->q.map_ptr;
		break;
	default:
		return ERR_PTR(-EINVAL);
	}

	page = virt_to_head_page(ptr);
	if (sz > page_size(page))
		return ERR_PTR(-EINVAL);

	return ptr;
}

int
zctap_socket_mmap(struct file *file, struct socket *sock,
		struct vm_area_struct *vma)
{
	struct sock *sk;

	sk = sock->sk;
	if (!sk || !sk->sk_user_data)
		return -EINVAL;

	return zctap_mmap(sk->sk_user_data, vma,
			   zctap_validate_skq_mmap_request);
}

static void
zctap_release_ubufs(struct zctap_skq *skq)
{
	struct ubuf_info *info, *tmp;

	info = list_last_entry(&skq->info_list, struct ubuf_info, info_node);
	WARN_ON(!refcount_dec_and_test(&info->refcnt));

	list_for_each_entry_safe(info, tmp, &skq->info_list, info_node) {
		WARN_ON(refcount_read(&info->refcnt));
		list_del(&info->info_node);
		kfree(info);
	}
}

/* NOTE: nr_pages may be negative on error. */
static void
zctap_meta_put_pages(struct zctap_meta *m, int nr_pages)
{
	struct page *page;
	int i;

	for (i = 0; i < nr_pages; i++) {
		page = m->page[i];
		put_page(page);
	}
}

static void
zctap_meta_free(struct zctap_meta *m)
{
	if (!m)
		return;

/* blows up because this is in interrupt.  XXX leak for now */
//	vunmap(m->kaddr);
	zctap_meta_put_pages(m, m->nr_pages);
#if 0
	if (mem->account_mem)
		zctap_unaccount_mem(mem->user, r->nr_pages);
#endif
	kvfree(m->page);
	zctap_shared_queue_free(&m->q);
	kfree(m);
}

static void
zctap_release_sk(struct sock *sk)
{
	struct zctap_skq *skq = sk->sk_user_data;
	struct zctap_sock_match *m;

	m = container_of(sk->sk_prot, struct zctap_sock_match, prot);

	sk->sk_destruct = skq->sk_destruct;
	sk->sk_data_ready = skq->sk_data_ready;
	sk->sk_prot = m->base_prot;
	sk->sk_user_data = NULL;

	/* XXX reclaim and recycle pending data? */
	zctap_shared_queue_free(&skq->rx);
	zctap_shared_queue_free(&skq->cq);
	zctap_meta_free(skq->meta);
	zctap_release_ubufs(skq);
	kfree(skq);
}

static void
zctap_skq_destruct(struct sock *sk)
{
	struct zctap_skq *skq = sk->sk_user_data;
	struct zctap_ctx *ctx = skq->ctx;

	zctap_release_sk(sk);

	if (sk->sk_destruct)
		sk->sk_destruct(sk);

	zctap_free_ctx(ctx);
}

/* XXX move this to networking core. */
static void sock_rdband_ready(struct sock *sk)
{
	struct socket_wq *wq;

	rcu_read_lock();
	wq = rcu_dereference(sk->sk_wq);
	if (skwq_has_sleeper(wq))
		wake_up_interruptible_sync_poll(&wq->wait, EPOLLRDBAND);
	sk_wake_async(sk, SOCK_WAKE_WAITD, POLL_IN);
	rcu_read_unlock();
}

static void
__zctap_tx_callback(struct ubuf_info *info)
{
	struct zctap_skq *skq = info->ctx;
	struct ubuf_info *tmp;
	unsigned long flags;
	unsigned count = 0;

	spin_lock_irqsave(&skq->cq_lock, flags);
	list_for_each_entry_safe(info, tmp, &skq->info_list, info_node) {
		if (refcount_read(&info->refcnt))
			break;
		list_del(&info->info_node);
		kfree(info);
		count++;
	}

	if (count)
		sq_prod_submit_n(&skq->cq, count);

	spin_unlock_irqrestore(&skq->cq_lock, flags);

	if (count)
		sock_rdband_ready(skq->sk);
}

/* called by skb_zcopy_clear() and skb_zcopy_put() */
static void
zctap_tx_callback(struct sk_buff *skb, struct ubuf_info *uarg, bool success)
{
	if (refcount_dec_and_test(&uarg->refcnt))
		__zctap_tx_callback(uarg);
}

static struct ubuf_info *
zctap_alloc_tx_ubuf(struct zctap_skq *skq)
{
	struct ubuf_info *info;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return NULL;

	info->ctx = skq;
	info->callback = zctap_tx_callback;
	info->zc_flags = SKBZC_FRAGMENTS | SKBZC_FIXED;
	info->zerocopy = true;
	refcount_set(&info->refcnt, 1);

	return info;
}

/*
 * add new epoch notifier at end of list.
 * drop refcount of prior entry, so it can be released.
 */
int
zctap_tx_add_notifier(struct sock *sk, struct cmsghdr *cmsg)
{
	struct zctap_skq *skq = sk->sk_user_data;
	struct ubuf_info *info;
	unsigned long flags;
	u64 *ptr;

	if (cmsg->cmsg_len != CMSG_LEN(sizeof(*ptr)))
		return -EINVAL;

	info = zctap_alloc_tx_ubuf(skq);
	if (!info)
		return -ENOMEM;

	spin_lock_irqsave(&skq->cq_lock, flags);
	ptr = sq_prod_reserve(&skq->cq);
	if (!ptr) {
		spin_unlock_irqrestore(&skq->cq_lock, flags);
		kfree(info);
		return -ENOSPC;
	}

	*ptr = *(u64 *)CMSG_DATA(cmsg);

	list_add_tail(&info->info_node, &skq->info_list);
	info = list_prev_entry(info, info_node);

	spin_unlock_irqrestore(&skq->cq_lock, flags);

	skb_zcopy_put(info);

	return 0;
}

struct ubuf_info *
zctap_get_notifier(struct sock *sk)
{
	struct zctap_skq *skq = sk->sk_user_data;
	struct ubuf_info *info;

	info = list_last_entry(&skq->info_list, struct ubuf_info, info_node);
	skb_zcopy_get(info);

	return info;
}

static struct zctap_skq *
zctap_create_skq(struct zctap_socket_param *p)
{
	struct ubuf_info *info = NULL;
	struct zctap_skq *skq;
	int err = -ENOMEM;

	skq = kzalloc(sizeof(*skq), GFP_KERNEL);
	if (!skq)
		goto out;

	info = zctap_alloc_tx_ubuf(skq);
	if (!info)
		goto out;

	err = zctap_shared_queue_create(&skq->rx, &p->rx);
	if (err)
		goto out;

	err = zctap_shared_queue_create(&skq->cq, &p->cq);
	if (err)
		goto out;

	spin_lock_init(&skq->cq_lock);
	INIT_LIST_HEAD(&skq->info_list);
	list_add(&info->info_node, &skq->info_list);

	return skq;

out:
	zctap_shared_queue_free(&skq->rx);
	zctap_shared_queue_free(&skq->cq);
	zctap_meta_free(skq->meta);
	kfree(info);
	kfree(skq);

	return ERR_PTR(err);
}

static void
zctap_rebuild_match(struct zctap_sock_match *m, struct sock *sk)
{
	mutex_lock(&zctap_lock);

	if (m->initialized)
		goto out;

	m->base_ops = sk->sk_socket->ops;
	m->base_prot = sk->sk_prot;

	m->ops = *m->base_ops;
	m->prot = *m->base_prot;

	m->prot.stream_memory_read = zctap_stream_memory_read;
	m->prot.stream_memory_rdband = zctap_stream_memory_rdband;
	m->ops.mmap = zctap_socket_mmap;

	smp_wmb();
	m->initialized = 1;

out:
	mutex_unlock(&zctap_lock);
}

static int
zctap_match_socket(struct sock *sk)
{
	struct zctap_sock_match *m;
	int i;

	for (i = 0; i < ARRAY_SIZE(zctap_match_tbl); i++) {
		m = &zctap_match_tbl[i];

		if (m->family != sk->sk_family ||
		    m->type != sk->sk_type ||
		    m->protocol != sk->sk_protocol)
			continue;

		if (!m->initialized)
			zctap_rebuild_match(m, sk);

		if (m->base_prot != sk->sk_prot)
			return -EPROTO;

		if (m->base_ops != sk->sk_socket->ops)
			return -EPROTO;

		return i;
	}
	return -EOPNOTSUPP;
}

static struct zctap_meta *
zctap_add_meta(const struct iovec *iov)
{
	struct zctap_meta *m;
	int err, nr_pages;
	u64 addr, len;
	int count = 0;

	err = -ENOMEM;
	m = kzalloc(sizeof(struct zctap_meta), GFP_KERNEL);
	if (!m)
		return ERR_PTR(err);

	addr = (u64)iov->iov_base;
	m->start = round_down(addr, PAGE_SIZE);
	len = round_up(addr - m->start + iov->iov_len, PAGE_SIZE);
	nr_pages = len >> PAGE_SHIFT;

	m->nr_pages = nr_pages;
	m->page = kvmalloc_array(nr_pages, sizeof(struct page *), GFP_KERNEL);
	if (!m->page)
		goto out;

#if 0
	if (mem->account_mem) {
		err = zctap_account_mem(mem->user, nr_pages);
		if (err) {
			nr_pages = 0;
			goto out;
		}
	}
#endif

	mmap_read_lock(current->mm);
	count = pin_user_pages(m->start, nr_pages,
			       FOLL_WRITE | FOLL_LONGTERM,
			       m->page, NULL);
	mmap_read_unlock(current->mm);

	if (count != nr_pages) {
		err = count < 0 ? count : -EFAULT;
		goto out;
	}

	m->kaddr = vmap(m->page, nr_pages, VM_MAP, PAGE_KERNEL);
	if (!m->kaddr)
		goto out;

	return m;

out:
	vunmap(m->kaddr);
	zctap_meta_put_pages(m, count);
#if 0
	if (mem->account_mem && nr_pages)
		zctap_unaccount_mem(mem->user, nr_pages);
#endif
	kvfree(m->page);
	kfree(m);

	return ERR_PTR(err);
}

static int
zctap_attach_meta(struct zctap_skq *skq, struct zctap_socket_param *p)
{
	struct zctap_meta *meta;
	int err;

	if (p->resv != 1)
		return -EINVAL;

	if (skq->meta)
		return -EALREADY;

	err = zctap_shared_queue_validate(&p->meta, sizeof(u64),
					  ZCTAP_OFF_META_ID);
	if (err)
		return err;

	meta = zctap_add_meta(&p->iov);
	if (IS_ERR(meta))
		return PTR_ERR(meta);
	meta->meta_len = p->meta_len;

	err = zctap_shared_queue_create(&meta->q, &p->meta);
	if (err)
		goto out;

	skq->meta = meta;
	return 0;

out:
	zctap_meta_free(meta);
	return err;
}

static int
__zctap_attach_socket(struct zctap_ctx *ctx, struct sock *sk,
		      struct zctap_socket_param *p)
{
	struct zctap_skq *skq;
	int id, err;

	/* XXX second call to bind metadata - new ioctl? */
	if (sk->sk_user_data)
		return zctap_attach_meta(sk->sk_user_data, p);

	if (p->resv != 0)
		return -EINVAL;

	err = zctap_shared_queue_validate(&p->rx, sizeof(struct iovec),
					  ZCTAP_OFF_RX_ID);
	if (err)
		return err;

	err = zctap_shared_queue_validate(&p->cq, sizeof(u64),
					  ZCTAP_OFF_CQ_ID);
	if (err)
		return err;

	id = zctap_match_socket(sk);
	if (id < 0)
		return id;

	skq = zctap_create_skq(p);
	if (IS_ERR(skq))
		return PTR_ERR(skq);

	refcount_inc(&ctx->ref);
	skq->ctx = ctx;

	skq->sk = sk;
	skq->sk_destruct = sk->sk_destruct;
	skq->sk_data_ready = sk->sk_data_ready;

	sk->sk_destruct = zctap_skq_destruct;
	if (id != ZCTAP_MATCH_UDP6)
		sk->sk_data_ready = zctap_data_ready;
	sk->sk_prot = &zctap_match_tbl[id].prot;
	sk->sk_socket->ops = &zctap_match_tbl[id].ops;

	sk->sk_user_data = skq;

	return 0;
}

static int
zctap_attach_socket(struct zctap_ctx *ctx, void __user *arg)
{
	struct zctap_socket_param p;
	struct socket *sock;
	int err;

	if (copy_from_user(&p, arg, sizeof(p)))
		return -EFAULT;

	sock = sockfd_lookup(p.fd, &err);
	if (!sock)
		return err;

	err = __zctap_attach_socket(ctx, sock->sk, &p);

	if (!err) {
		if (copy_to_user(arg, &p, sizeof(p))) {
			zctap_release_sk(sock->sk);
			err = -EFAULT;
		}
	}
	fput(sock->file);

	return err;
}

static struct zctap_ctx *
zctap_file_to_ctx(struct file *file)
{
	return file->private_data;
}

static long
zctap_ioctl(struct file *file, unsigned cmd, unsigned long arg)
{
	struct zctap_ctx *ctx = zctap_file_to_ctx(file);

	switch (cmd) {
	case ZCTAP_CTX_IOCTL_ATTACH_DEV:
		return zctap_attach_dev(ctx, (void __user *)arg);

	case ZCTAP_CTX_IOCTL_BIND_QUEUE:
		return zctap_bind_queue(ctx, (void __user *)arg);

	case ZCTAP_CTX_IOCTL_ATTACH_REGION:
		return zctap_attach_region(ctx, (void __user *)arg);

	case ZCTAP_CTX_IOCTL_ATTACH_SOCKET:
		return zctap_attach_socket(ctx, (void __user *)arg);
	}
	return -ENOTTY;
}

static void
__zctap_free_ctx(struct zctap_ctx *ctx)
{
	struct zctap_dmamap *map;
	unsigned long index;

	xa_for_each(&ctx->xa, index, map) {
		index = (map->start >> PAGE_SHIFT) + map->nr_pages - 1;
		zctap_map_detach_ctx(map, ctx);
	}

	xa_destroy(&ctx->xa);

	if (ctx->dev)
		dev_put(ctx->dev);
	kfree(ctx);

	module_put(THIS_MODULE);
}

static void
zctap_free_ctx(struct zctap_ctx *ctx)
{
	if (refcount_dec_and_test(&ctx->ref))
		__zctap_free_ctx(ctx);
}

static int
zctap_release(struct inode *inode, struct file *file)
{
	struct zctap_ctx *ctx = zctap_file_to_ctx(file);

	zctap_free_ctx(ctx);
	return 0;
}

static struct zctap_ctx *
zctap_alloc_ctx(void)
{
	struct zctap_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	xa_init(&ctx->xa);
	refcount_set(&ctx->ref, 1);
	INIT_LIST_HEAD(&ctx->ifq_list);

	return ctx;
}

static int
zctap_open(struct inode *inode, struct file *file)
{
	struct zctap_ctx *ctx;

	ctx = zctap_alloc_ctx();
	if (!ctx)
		return -ENOMEM;

	file->private_data = ctx;

	__module_get(THIS_MODULE);

	return 0;
}

static const struct file_operations zctap_fops = {
	.owner =		THIS_MODULE,
	.open =			zctap_open,
	.unlocked_ioctl =	zctap_ioctl,
	.release =		zctap_release,
};

static struct miscdevice zctap_dev = {
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= "zctap",
	.fops		= &zctap_fops,
};


#if IS_MODULE(CONFIG_ZCTAP)
#include "zctap_stub.h"
static struct zctap_functions zctap_fcn = {
	.get_dma	= zctap_get_dma,
	.get_page	= zctap_get_page,
	.put_page	= zctap_put_page,
	.get_pages	= zctap_get_pages,
	.socket_mmap	= zctap_socket_mmap,
	.attach_socket	= zctap_attach_socket,
};
#else
#define zctap_fcn_register(x)
#define zctap_fcn_unregister()
#endif

static int __init
zctap_init(void)
{
	misc_register(&zctap_dev);
	misc_register(&zctap_mem_dev);
	zctap_fcn_register(&zctap_fcn);

	return 0;
}

static void __exit
zctap_fini(void)
{
	misc_deregister(&zctap_dev);
	misc_deregister(&zctap_mem_dev);
	zctap_fcn_unregister();
}

module_init(zctap_init);
module_exit(zctap_fini);
MODULE_LICENSE("GPL v2");
