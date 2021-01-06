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
#include <linux/dma-buf.h>

#include <net/tcp.h>
#include <net/transp_v6.h>
#include <net/busy_poll.h>

#include <net/zctap.h>
#include <uapi/misc/zctap.h>
#include "zctap_priv.h"

static struct mutex zctap_lock;
static const struct file_operations zctap_ctx_fops;
static struct zctap_ctx *zctap_get_ctx(int fd);
static void zctap_put_ctx(struct zctap_ctx *ctx);

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
		       zctap_pageptr_addr(page));
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
		       zctap_pageptr_addr(page));
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
EXPORT_SYMBOL(zctap_put_page);

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

static void
zctap_free_cache_entries(struct zctap_pgcache *cache, int count)
{
	struct page *page;

	while (count--) {
		page = zctap_pageptr_page(cache->page[count]);
		put_page(page);
	}
}

/*
 * Free cache structures and release pages.
 */
static void
zctap_free_cache(struct zctap_ifq *ifq)
{
	struct zctap_pgcache *cache, *next;
	int count;

	kfree(ifq->spare_cache);

	count = ifq->napi_cache_count;
	for (cache = ifq->napi_cache; cache; cache = next) {
		zctap_free_cache_entries(cache, count);
		count = ZCTAP_CACHE_COUNT;
		next = cache->next;
		kfree(cache);
	}

	count = ifq->any_cache_count;
	for (cache = ifq->any_cache; cache; cache = next) {
		zctap_free_cache_entries(cache, count);
		count = ZCTAP_CACHE_COUNT;
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
	unsigned long idx;
	struct page *p;
	int i, n;

	map = xa_load(&skq->ctx->xa, addr >> PAGE_SHIFT);
	if (!map)
		return -EINVAL;

	idx = (addr - map->start) >> PAGE_SHIFT;
	n = map->nr_pages - idx + 1;
	n = min(count, n);

	for (i = 0; i < n; i++) {
		p = map->pages[idx + i];
		get_page(p);
		pages[i] = p;
	}

	return n;
}

static int
zctap_get_fill_page(struct zctap_ifq *ifq, dma_addr_t *dma, struct page **page)
{
	struct zctap_dmamap *map;
	unsigned long idx;
	u64 *addrp, addr;
	struct page *p;
	u32 off;

	addrp = sq_cons_peek(&ifq->fill);
	if (!addrp)
		return -ENOMEM;

	addr = READ_ONCE(*addrp);

	map = xa_load(&ifq->ctx->xa, addr >> PAGE_SHIFT);
	if (!map)
		return -EINVAL;

	idx = (addr - map->start) >> PAGE_SHIFT;
	off = zctap_page_offset(addr);

	/* XXX need to verify length doesn't cross page boundaries */
	/* XXX how to handle errors?  fatal? */
	/* currently returning error just infinite loops the driver */
	addr = (addr & PAGE_MASK) + off;
	addr = (addr - map->start) + (ifq->fill_bufsz - 1);
	if ((addr >> PAGE_SHIFT) != idx) {
		pr_err_ratelimited("bad fill addr: %llx + %d spans pages\n",
				   addr, ifq->fill_bufsz);
		return -EINVAL;
	}

	*dma = map->dma[idx] + off;
	p = map->pages[idx];
	get_page(p);
	*page = zctap_encode_pageptr(p, off, map->flags & ZCTAP_DMAFLAG_SYNC);

	sq_cons_advance(&ifq->fill);

	return 0;
}

static dma_addr_t
zctap_map_get_dma(struct zctap_dmamap *map, unsigned long addr)
{
	unsigned long idx;

	idx = (addr - map->start) >> PAGE_SHIFT;
	return map->dma[idx];
}

/* TX path */
dma_addr_t
zctap_get_frag_dma(struct zctap_ctx *ctx, skb_frag_t *frag)
{
	struct zctap_dmamap *map;
	dma_addr_t dma_addr;
	unsigned long addr;

	addr = page_private(skb_frag_page(frag));
	map = xa_load(&ctx->xa, addr >> PAGE_SHIFT);
	dma_addr = zctap_map_get_dma(map, addr) + skb_frag_off(frag);
	if (map->flags & ZCTAP_DMAFLAG_SYNC)
		dma_sync_single_range_for_device(map->device, dma_addr, 0,
						 skb_frag_size(frag),
						 DMA_BIDIRECTIONAL);
	return dma_addr;
}
EXPORT_SYMBOL(zctap_get_frag_dma);

static void
zctap_get_dma(struct zctap_ctx *ctx, dma_addr_t *dma, struct page *page)
{
	struct zctap_dmamap *map;
	unsigned long addr;

	addr = zctap_pageptr_base(page);
	map = xa_load(&ctx->xa, addr >> PAGE_SHIFT);
	*dma = zctap_map_get_dma(map, addr) + zctap_pageptr_offset(page);
}

/* RX path */
int
zctap_get_page(struct zctap_ifq *ifq, struct page **page, dma_addr_t *dma)
{
	*page = zctap_get_cached_page(ifq);
	if (!*page)
		return zctap_get_fill_page(ifq, dma, page);
	zctap_get_dma(ifq->ctx, dma, *page);
	return 0;
}
EXPORT_SYMBOL(zctap_get_page);

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

	if (!u->map_sz)
		return 0;

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

	zctap_free_ifq(ifq);
	zctap_put_ctx(ctx);

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
	if (test_and_clear_bit(ZCT_ifq_fq_empty, &ifq->flags))
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

int
zctap_create_fd(const char *name, const struct file_operations *fops,
		void *obj, unsigned flags, struct file **filep)
{
	struct file *file;
	int fd;

	fd = get_unused_fd_flags(flags);
	if (fd < 0)
		return fd;

	file = anon_inode_getfile(name, fops, obj, flags);
	if (IS_ERR(file)) {
		put_unused_fd(fd);
		return PTR_ERR(file);
	}

	*filep = file;
	return fd;
}

static void
zctap_rx_callback(struct sk_buff *skb, struct ubuf_info *uarg, bool success)
{
	struct zctap_ifq *ifq = container_of(uarg, struct zctap_ifq, uarg);
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	struct page *page;
	int i;

	for (i = 0; i < shinfo->nr_frags; i++) {
		page = skb_frag_page(&shinfo->frags[i]);
		if (page)
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
	ifq->uarg.flags = SKBFL_ZEROCOPY_FRAG | SKBFL_FIXED_FRAG;
	ifq->uarg.zerocopy = true;
	ifq->uarg.ctx = ctx;		/* XXX */

	return ifq;

out:
	kfree(ifq->napi_cache);
	kfree(ifq);
	return NULL;
}

static int
zctap_validate_ifq_param(struct zctap_ifq_param *p)
{
	int err;

	err = zctap_shared_queue_validate(&p->fill, sizeof(u64),
					  ZCTAP_OFF_FILL_ID);
	if (err)
		return err;

	if (p->split > ZCTAP_SPLIT_L4)
		return -EINVAL;
	if (p->split_offset > U8_MAX)
		return -EINVAL;

	/* buffer size must be multiples of 128 bytes */
	if (!p->fill_bufsz || p->fill_bufsz % 128)
		return -EINVAL;

	return 0;
}

static int
zctap_bind_queue(struct zctap_ctx *ctx, struct zctap_ifq_param *p,
		 void __user *uarg, size_t usize)
{
	struct file *file = NULL;
	struct zctap_ifq *ifq;
	int fd, err;

	err = zctap_validate_ifq_param(p);
	if (err)
		return err;

	ifq = zctap_alloc_ifq(ctx);
	if (!ifq)
		return -ENOMEM;

	ifq->split = p->split;
	ifq->split_offset = p->split_offset;
	ifq->fill_bufsz = p->fill_bufsz;

	err = zctap_shared_queue_create(&ifq->fill, &p->fill);
	if (err)
		goto out;

	err = zctap_open_queue(ifq, &p->queue_id);
	if (err)
		goto out;

	ifq->queue_id = p->queue_id;

	fd = zctap_create_fd("[zctap_ifq]", &zctap_ifq_fops, ifq,
			     O_RDWR | O_CLOEXEC, &file);
	if (fd < 0) {
		err = fd;
		goto out;
	}

	err = zctap_put_param(uarg, usize, p, sizeof(*p));
	if (err) {
		fput(file);
		put_unused_fd(fd);
		goto out;
	}

	fd_install(fd, file);
	get_file(ctx->file);

	return fd;

out:
	zctap_free_ifq(ifq);
	return err;
}

int
zctap_sys_bind_queue(void __user *uarg, size_t usize)
{
	struct zctap_ifq_param p;
	struct zctap_ctx *ctx;
	int err;

	err = zctap_get_param(&p, sizeof(p), uarg, usize);
	if (err)
		return err;

	ctx = zctap_get_ctx(p.zctap_fd);
	if (IS_ERR(ctx))
		return PTR_ERR(ctx);

	err = zctap_bind_queue(ctx, &p, uarg, usize);

	zctap_put_ctx(ctx);
	return err;
}

static bool
zctap_region_overlap(struct xarray *xa, struct zctap_region *r)
{
	unsigned long index, last;

	index = r->start >> PAGE_SHIFT;
	last = index + r->nr_pages - 1;

	return xa_find(xa, &index, last, XA_PRESENT) != NULL;
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

static struct zctap_ctx *
zctap_get_ctx(int fd)
{
	struct file *file;

	file = fget(fd);
	if (!file)
		return ERR_PTR(-EBADF);

	if (file->f_op != &zctap_ctx_fops) {
		fput(file);
		return ERR_PTR(-EOPNOTSUPP);
	}

	return file->private_data;
}

static void
zctap_put_ctx(struct zctap_ctx *ctx)
{
	fput(ctx->file);
}

int
zctap_attach_region(int zctap_fd, int region_fd)
{
	struct zctap_dmamap *map;
	struct zctap_region *r;
	struct zctap_ctx *ctx;
	unsigned long start;
	int err;

	ctx = zctap_get_ctx(zctap_fd);
	if (IS_ERR(ctx))
		return PTR_ERR(ctx);

	r = zctap_get_region(region_fd);
	if (IS_ERR(r)) {
		err = PTR_ERR(r);
		goto out;
	}

	map = zctap_region_map_ctx(r, ctx);
	if (IS_ERR(map)) {
		err = PTR_ERR(map);
		goto out;
	}

	/* XXX "should not happen", validate anyway */
	if (zctap_region_overlap(&ctx->xa, r)) {
		zctap_region_unmap_ctx(ctx, map);
		err = -EEXIST;
		goto out;
	}

	start = map->start >> PAGE_SHIFT;
	err = xa_err(xa_store_range(&ctx->xa, start, start + map->nr_pages - 1,
				    map, GFP_KERNEL));
	if (err)
		zctap_region_unmap_ctx(ctx, map);

out:
	if (!IS_ERR(r))
		zctap_put_region(r);
	zctap_put_ctx(ctx);
	return err;
}

struct zctap_read_desc {
	read_descriptor_t desc;
	void *data;
	void *limit;
};

static inline struct zctap_iovec *
zctap_next_vec(struct zctap_read_desc *rd)
{
	struct zctap_skq *skq = rd->desc.arg.data;
	void *ptr, *next;

	/* TCP does not have a metadata area, use RX queue directly */
	ptr = rd->data;
	if (!ptr)
		return sq_prod_reserve(&skq->rx);

	next = ptr + sizeof(struct zctap_iovec);
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
	struct zctap_iovec *iov;
	struct page *page;
	unsigned start;
	int i, used;

	rd = container_of(desc, struct zctap_read_desc, desc);

	if ((offset < skb_headlen(skb)) ||
	    ((offset < len) && !zctap_skb_ours(skb))) {
		pr_err_ratelimited("zctap rcv error, ours:%d hdr:%d off:%d\n",
				   zctap_skb_ours(skb),
				   skb_headlen(skb), offset);
		return -EFAULT;
	}

	used = 0;
	start = skb_headlen(skb);

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		skb_frag_t *frag;
		int end, off, frag_len;

		frag = &skb_shinfo(skb)->frags[i];
		frag_len = skb_frag_size(frag);

		end = start + frag_len;
		if (offset < end) {
			iov = zctap_next_vec(rd);
			if (!iov)
				break;

			page = skb_frag_page(frag);
			off = offset - start;
			iov->base = zctap_pageptr_addr(page);
			iov->offset = skb_frag_off(frag) + off -
				      zctap_pageptr_offset(page);
			iov->length = frag_len - off;
#if 0
			iov->base = (u64)page_private(page);
			iov->offset = skb_frag_off(frag) + off;
			iov->length = frag_len - off;
#endif
			used += (frag_len - off);
			offset += (frag_len - off);

			put_page(zctap_pageptr_page(page));
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

static int
zctap_tcp_read_sock(struct sock *sk, struct zctap_skq *skq,
		    const char *from)
{
	struct zctap_read_desc rd = {
		.desc.arg.data = skq,
		.desc.count = 1,
	};
	int used;

	used = tcp_read_sock(sk, &rd.desc, zctap_recv_skb);
	if (used > 0)
		sq_prod_submit(&skq->rx);

	return used;
}

static void *
zctap_metadata_kaddr(struct zctap_ctx *ctx, u64 addr)
{
	struct zctap_region *r;
	unsigned long off;

	r = xa_load(&ctx->xa_vmap, addr >> PAGE_SHIFT);
	if (!r)
		return NULL;

	off = addr - r->start;
	if (addr < r->start || off >= (r->nr_pages << PAGE_SHIFT))
		return NULL;

	return r->vmap_addr + off;
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
	struct zctap_read_desc rd;
	struct zctap_pktdata *pkt;
	struct msghdr msg;
	u64 *addrp, addr;
	int used, hdlen;
	bool is_udp4;
	void *start;

	if (skb->len == 0) {
		pr_err_ratelimited("0 length skb??\n");
		return -EFAULT;
	}
	if (!skq->meta.entries) {
		pr_err_ratelimited("no skq metadata\n");
		return -EFAULT;
	}

	/* If the payload is placed in the skb, then no fragments are
	 * present (and no uarg data is attached).
	 */

	spin_lock(&sk->sk_receive_queue.lock);

	addrp = sq_cons_peek(&skq->meta);
	if (!addrp) {
		used = -ENOMEM;
		goto drop;
	}
	addr = READ_ONCE(*addrp);

	pkt = zctap_metadata_kaddr(skq->ctx, addr);
	if (!pkt) {
		used = -EFAULT;
		goto drop;
	}

	start = pkt->data;

	hdlen = skb_headlen(skb);
	if (hdlen) {
		if (hdlen > skq->inline_max)
			hdlen = skq->inline_max;
		memcpy(start, skb->data, hdlen);
		start += ALIGN(hdlen, 8);
	}
	pkt->data_len = hdlen;

	rd.desc.written = 0;
	rd.desc.count = 1;
	rd.data = start;
	rd.limit = (void *)pkt + skq->meta_bufsz;

	used = zctap_recv_skb(&rd.desc, skb, hdlen, skb->len);
	if (used < 0)
		goto drop;

	pkt->iov_count = (rd.data - start) / sizeof(struct zctap_iovec);
	pkt->flags = used == (skb->len - hdlen) ? 0 : MSG_TRUNC;

//	SNMP_INC_STATS(mib, UDP_MIB_INDATAGRAMS);
	is_udp4 = (skb->protocol == htons(ETH_P_IP));

	pkt->name_len = zctap_copy_sockaddr(&rd, sk, skb, is_udp4);

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

	pkt->flags |= msg.msg_flags;
	pkt->cmsg_len = rd.data - msg.msg_control;
	pkt->_pad = 0;

	addrp = sq_prod_reserve(&skq->rx);
	if (!addrp) {
		used = -ENOBUFS;
		goto drop;
	}

	*addrp = addr;
	sq_prod_submit(&skq->rx);
	sq_cons_advance(&skq->meta);
	sq_cons_complete(&skq->meta);	/* should probably batch this */

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
zctap_tcp_data_ready(struct sock *sk)
{
	struct zctap_skq *skq = sk->sk_user_data;

	WARN_ON(skq->complete);

	if (skq->rx.entries)
		zctap_tcp_read_sock(sk, skq, "data_ready");

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

static int
zctap_end_handling(struct sock *sk)
{
	if (sock_flag(sk, SOCK_DONE))
		return 0;

	if (sk->sk_err)
		return sock_error(sk);

	if (sk->sk_shutdown & RCV_SHUTDOWN)
		return 0;

	if (sk->sk_state == TCP_CLOSE)
		return -ENOTCONN;

	return -EAGAIN;
}

static int
zctap_complete(struct zctap_skq *skq, int state)
{
	struct zctap_iovec *iov;

	iov = sq_prod_reserve(&skq->rx);
	if (!iov)
		return -EAGAIN;

	iov->base = 0;
	iov->offset = state;
	iov->length = 0;

	sq_prod_submit(&skq->rx);

	skq->complete = true;
	return 0;
}

static int
zctap_tcp_recvmsg_locked(struct sock *sk)
{
	struct zctap_skq *skq = sk->sk_user_data;
	int ret = 0;

	/* transferred EOF marker, no more data incoming. */
	if (skq->complete)
		return 0;

	/* tcp_read_sock checks for LISTEN */
	if (skq->rx.entries)
		ret = zctap_tcp_read_sock(sk, skq, "recvmsg");

	if (!ret) {
		ret = zctap_end_handling(sk);
		if (!ret)
			ret = zctap_complete(skq, 0);
	}

	return ret;
}

static int
zctap_tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
		  int nonblock, int flags, int *addr_len)
{
	int err;

	if (sk_can_busy_loop(sk) &&
	    skb_queue_empty_lockless(&sk->sk_receive_queue) &&
	    sk->sk_state == TCP_ESTABLISHED)
		sk_busy_loop(sk, nonblock);

	lock_sock(sk);
	err = zctap_tcp_recvmsg_locked(sk);
	release_sock(sk);

	return err;
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
		if (!skq->meta.entries)
			return ERR_PTR(-EEXIST);
		ptr = skq->meta.map_ptr;
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
	zctap_shared_queue_free(&skq->meta);
	zctap_release_ubufs(skq);

	zctap_put_ctx(skq->ctx);
	kfree(skq);
}

static void
zctap_skq_destruct(struct sock *sk)
{

	zctap_release_sk(sk);

	if (sk->sk_destruct)
		sk->sk_destruct(sk);
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

/* called by net_zcopy_clear() and net_zcopy_put() */
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
	info->flags = SKBFL_ZEROCOPY_FRAG | SKBFL_FIXED_FRAG;
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

	net_zcopy_put(info);

	return 0;
}

struct ubuf_info *
zctap_get_notifier(struct sock *sk)
{
	struct zctap_skq *skq = sk->sk_user_data;
	struct ubuf_info *info;

	info = list_last_entry(&skq->info_list, struct ubuf_info, info_node);
	net_zcopy_get(info);

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

	err = zctap_shared_queue_create(&skq->meta, &p->meta);
	if (err)
		goto out;

	skq->meta_bufsz = p->meta_bufsz;
	skq->inline_max = p->inline_max;

	spin_lock_init(&skq->cq_lock);
	INIT_LIST_HEAD(&skq->info_list);
	list_add(&info->info_node, &skq->info_list);

	return skq;

out:
	zctap_shared_queue_free(&skq->rx);
	zctap_shared_queue_free(&skq->cq);
	zctap_shared_queue_free(&skq->meta);
	kfree(info);
	kfree(skq);

	return ERR_PTR(err);
}

static void
zctap_rebuild_match(struct zctap_sock_match *m, struct sock *sk, int match_id)
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
	if (match_id == ZCTAP_MATCH_TCP6 || match_id == ZCTAP_MATCH_TCP)
		m->prot.recvmsg = zctap_tcp_recvmsg;
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
			zctap_rebuild_match(m, sk, i);

		if (m->base_prot != sk->sk_prot)
			return -EPROTO;

		if (m->base_ops != sk->sk_socket->ops)
			return -EPROTO;

		return i;
	}
	return -EOPNOTSUPP;
}

#if 0
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
#endif

int
zctap_attach_meta_region(int zctap_fd, int region_fd)
{
	struct zctap_region *r;
	struct zctap_ctx *ctx;
	unsigned long start;
	int err;

	ctx = zctap_get_ctx(zctap_fd);
	if (IS_ERR(ctx))
		return PTR_ERR(ctx);

	r = zctap_get_region(region_fd);
	if (IS_ERR(r)) {
		err = PTR_ERR(r);
		goto out;
	}

	err = -EINVAL;
	if (!r->host_region)
		goto out;

	err = -EEXIST;
	if (zctap_region_overlap(&ctx->xa_vmap, r))
		goto out;

	err = zctap_region_vmap(r);
	if (err)
		goto out;

	start = r->start >> PAGE_SHIFT;
	err = xa_err(xa_store_range(&ctx->xa_vmap, start,
				    start + r->nr_pages - 1, r, GFP_KERNEL));
	if (err)
		zctap_region_vunmap(r);

out:
	if (!IS_ERR(r))
		zctap_put_region(r);
	zctap_put_ctx(ctx);
	return err;
}

static int
zctap_validate_skq_param(struct zctap_socket_param *p)
{
	int err;

	err = zctap_shared_queue_validate(&p->rx, sizeof(struct iovec),
					  ZCTAP_OFF_RX_ID);
	if (err)
		goto out;

	err = zctap_shared_queue_validate(&p->cq, sizeof(u64),
					  ZCTAP_OFF_CQ_ID);
	if (err)
		goto out;

	if (p->inline_max > p->meta_bufsz)
		return -EINVAL;

	if (!p->meta.entries)
		goto out;

	/* XXX random sanity check */
	if (p->meta_bufsz < 64 || p->meta_bufsz > PAGE_SIZE)
		return -EINVAL;

	err = zctap_shared_queue_validate(&p->meta, sizeof(u64),
					  ZCTAP_OFF_META_ID);
	if (err)
		goto out;

out:
	return err;
}

/*
 * socket may already have data in the socket receive queue.
 * when this completes, user still has to map the queues and
 * populate metadata entries.
 */
static int
zctap_attach_socket(struct zctap_ctx *ctx, struct sock *sk,
		    struct zctap_socket_param *p)
{
	struct zctap_skq *skq;
	int id, err;

	err = zctap_validate_skq_param(p);

	id = zctap_match_socket(sk);
	if (id < 0)
		return id;

	skq = zctap_create_skq(p);
	if (IS_ERR(skq))
		return PTR_ERR(skq);

	get_file(ctx->file);
	skq->ctx = ctx;

	skq->sk = sk;
	skq->sk_destruct = sk->sk_destruct;
	skq->sk_data_ready = sk->sk_data_ready;

	/* XXX locking here ? */

	sk->sk_destruct = zctap_skq_destruct;
	if (id != ZCTAP_MATCH_UDP6)
		sk->sk_data_ready = zctap_tcp_data_ready;
	sk->sk_prot = &zctap_match_tbl[id].prot;
	sk->sk_socket->ops = &zctap_match_tbl[id].ops;

	sk->sk_user_data = skq;

	return 0;
}

int
zctap_sys_attach_socket(void __user *uarg, size_t usize)
{
	struct zctap_socket_param p;
	struct zctap_ctx *ctx;
	struct socket *sock;
	int err;

	err = zctap_get_param(&p, sizeof(p), uarg, usize);
	if (err)
		return err;

	ctx = zctap_get_ctx(p.zctap_fd);
	if (IS_ERR(ctx))
		return PTR_ERR(ctx);

	sock = sockfd_lookup(p.socket_fd, &err);
	if (!sock)
		goto out;

	err = zctap_attach_socket(ctx, sock->sk, &p);
	if (!err) {
		err = zctap_put_param(uarg, usize, &p, sizeof(p));
		if (err)
			zctap_release_sk(sock->sk);
	}

out:
	if (sock)
		sockfd_put(sock);
	zctap_put_ctx(ctx);
	return err;
}

static void
zctap_free_ctx(struct zctap_ctx *ctx)
{
	struct zctap_dmamap *map;
	struct zctap_region *r;
	unsigned long index;

	xa_for_each(&ctx->xa, index, map) {
		index = (map->start >> PAGE_SHIFT) + map->nr_pages - 1;
		zctap_region_unmap_ctx(ctx, map);
	}
	xa_for_each(&ctx->xa_vmap, index, r) {
		index = (r->start >> PAGE_SHIFT) + r->nr_pages - 1;
		zctap_region_vunmap(r);
	}

	xa_destroy(&ctx->xa);
	xa_destroy(&ctx->xa_vmap);

	if (ctx->dev)
		dev_put(ctx->dev);
	kfree(ctx);
}

static int
zctap_release(struct inode *inode, struct file *file)
{
	struct zctap_ctx *ctx = file->private_data;

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
	xa_init(&ctx->xa_vmap);
//	refcount_set(&ctx->ref, 1);

	return ctx;
}

static const struct file_operations zctap_ctx_fops = {
	.owner =		THIS_MODULE,
//	.open =			zctap_open,
//	.unlocked_ioctl =	zctap_ioctl,
	.release =		zctap_release,
};

int
zctap_create_context(int ifindex /*, flags */)
{
	int flags = O_RDWR | O_CLOEXEC;
	struct zctap_ctx *ctx;
	int fd, err;

	ctx = zctap_alloc_ctx();
	if (!ctx)
		return -ENOMEM;

	err = -ENODEV;
	ctx->dev = dev_get_by_index(&init_net, ifindex);
	if (!ctx->dev)
		goto out;

	fd = zctap_create_fd("[zctap]", &zctap_ctx_fops, ctx,
			     flags, &ctx->file);
	if (fd < 0) {
		err = fd;
		goto out;
	}

	fd_install(fd, ctx->file);
	return fd;

out:
	zctap_free_ctx(ctx);
	return err;
}

MODULE_LICENSE("GPL v2");
