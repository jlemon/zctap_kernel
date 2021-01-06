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

#include <net/zctap.h>
#include <uapi/misc/zctap.h>
#include "zctap_priv.h"

static int zctap_region_release(struct inode *inode, struct file *file);

const struct file_operations zctap_region_fops = {
	.release =		zctap_region_release,
};

static inline struct device *
netdev2device(struct net_device *dev)
{
	return dev->dev.parent;			/* from SET_NETDEV_DEV() */
}

static inline void
region_lock(struct zctap_region *r)
{
	mutex_lock(&r->lock);
}

static inline void
region_unlock(struct zctap_region *r)
{
	mutex_unlock(&r->lock);
}

struct zctap_region *
zctap_get_region(int fd)
{
	struct file *file;

	file = fget(fd);
	if (!file)
		return ERR_PTR(-EBADF);

	if (file->f_op != &zctap_region_fops) {
		fput(file);
		return ERR_PTR(-EOPNOTSUPP);
	}

	return file->private_data;
}

bool
zctap_is_region_fd(int fd)
{
	struct fd f;
	bool match;

	f = fdget(fd);
	if (!f.file)
		return false;

	match = f.file->f_op == &zctap_region_fops;
	fdput(f);

	return match;
}
EXPORT_SYMBOL(zctap_is_region_fd);

void
zctap_put_region(struct zctap_region *r)
{
	fput(r->file);
}

static struct zctap_ctx_entry *
__zctap_region_find_ctx(struct zctap_region *r, struct zctap_ctx *ctx)
{
	struct zctap_ctx_entry *ce;

	list_for_each_entry(ce, &r->ctx_entry_list, ctx_entry_node)
		if (ce->ctx == ctx)
			return ce;
	return NULL;
}

static struct zctap_dmamap *
__zctap_region_get_device_mapping(struct zctap_region *r, struct device *device)
{
	struct zctap_dmamap *map;

	list_for_each_entry(map, &r->dma_list, dma_node)
		if (map->device == device) {
			refcount_inc(&map->ref);
			return map;
		}
	return NULL;
}

static int
zctap_import_sgtable_pages(struct zctap_dmamap *map)
{
	struct sg_page_iter iter;
	int i;

	if (map->pages)
		goto out;

	map->pages = kvmalloc_array(map->nr_pages, sizeof(struct page *),
				    GFP_KERNEL);
	if (!map->pages)
		return -ENOMEM;

	i = 0;
	for_each_sgtable_page(map->sgt, &iter, 0)
		map->pages[i++] = sg_page_iter_page(&iter);

out:
	return 0;
}

static int
zctap_import_sgtable(struct zctap_dmamap *map)
{
	struct sg_dma_page_iter iter;
	int i, err;

	map->dma = kvmalloc_array(map->nr_pages, sizeof(dma_addr_t),
				  GFP_KERNEL);
	if (!map->dma)
		return -ENOMEM;

	i = 0;
	for_each_sgtable_dma_page(map->sgt, &iter, 0)
		map->dma[i++] = sg_page_iter_dma_address(&iter);

	err = zctap_import_sgtable_pages(map);
	if (err)
		kvfree(map->dma);

	return err;
}

static int
zctap_OP_dma_buf_map(struct zctap_dmamap *map, struct dma_buf *dmabuf,
		     struct device *device)
{
	struct dma_buf_attachment *at;

	at = dma_buf_attach(dmabuf, device);
	if (IS_ERR(at))
		return PTR_ERR(at);

	map->sgt = dma_buf_map_attachment(at, DMA_BIDIRECTIONAL);
	if (IS_ERR(map->sgt)) {
		dma_buf_detach(dmabuf, at);
		return -EFAULT;
	}

	map->provider_priv = at;
	return 0;
}

static void
zctap_OP_dma_buf_unmap(struct zctap_dmamap *map, struct dma_buf *dmabuf,
		       struct device *device)
{
	struct dma_buf_attachment *at = map->provider_priv;

	dma_buf_unmap_attachment(at, map->sgt, DMA_BIDIRECTIONAL);
	dma_buf_detach(dmabuf, at);
}

static void
zctap_OP_dma_buf_put(struct dma_buf *dmabuf)
{
	if (dmabuf)
		dma_buf_put(dmabuf);
}

static void *
zctap_OP_dma_buf_vmap(struct dma_buf *dmabuf)
{
	struct dma_buf_map map;
	int err;

	err = dma_buf_vmap(dmabuf, &map);
	if (err)
		return ERR_PTR(err);

	if (map.is_iomem) {
		dma_buf_vunmap(dmabuf, &map);
		return ERR_PTR(-EOPNOTSUPP);
	}

	return map.vaddr;
}

static void
zctap_OP_dma_buf_vunmap(struct dma_buf *dmabuf, void *vaddr)
{
	struct dma_buf_map map;

	map.vaddr = vaddr;
	map.is_iomem = false;
	dma_buf_vunmap(dmabuf, &map);
}

static struct zctap_dmamap *
zctap_region_map_device(struct zctap_region *r, struct device *device)
{
	struct zctap_dmamap *map;
	int err;

	map = kzalloc(sizeof(*map), GFP_KERNEL);
	if (!map)
		return ERR_PTR(-ENOMEM);

	err = zctap_OP_dma_buf_map(map, r->dmabuf, device);
	if (err)
		goto out_free;

	map->r = r;
	map->device = device;
	map->start = r->start;
	map->nr_pages = r->nr_pages;
	map->pages = r->pages;
	refcount_set(&map->ref, 1);
	if (r->host_region)
		map->flags = ZCTAP_DMAFLAG_SYNC;

	err = zctap_import_sgtable(map);
	if (err)
		goto out;

	return map;

out:
	zctap_OP_dma_buf_unmap(map, r->dmabuf, device);
out_free:
	kfree(map);
	return ERR_PTR(err);
}

static struct zctap_dmamap *
__zctap_region_get_mapping(struct zctap_region *r, struct zctap_ctx *ctx,
			   struct device *device)
{
	struct zctap_ctx_entry *ce;
	struct zctap_dmamap *map;

	ce = __zctap_region_find_ctx(r, ctx);
	if (ce)
		return ERR_PTR(-EEXIST);

	ce = kmalloc(sizeof(*ce), GFP_KERNEL);
	if (!ce)
		return ERR_PTR(-ENOMEM);

	map = __zctap_region_get_device_mapping(r, device);
	if (!map) {
		map = zctap_region_map_device(r, device);
		if (IS_ERR(map)) {
			kfree(ce);
			return map;
		}

		list_add(&map->dma_node, &r->dma_list);
		if (!r->pages)
			r->pages = map->pages;
	}

	ce->ctx = ctx;
	ce->map = map;
	list_add(&ce->ctx_entry_node, &r->ctx_entry_list);
	get_file(r->file);

	return map;
}

struct zctap_dmamap *
zctap_region_map_ctx(struct zctap_region *r, struct zctap_ctx *ctx)
{
	struct zctap_dmamap *map;
	struct device *device;

	device = netdev2device(ctx->dev);

	region_lock(r);
	map = __zctap_region_get_mapping(r, ctx, device);
	region_unlock(r);

	return map;
}

static void
__zctap_region_put_mapping(struct zctap_region *r, struct zctap_dmamap *map)
{

	if (!refcount_dec_and_test(&map->ref))
		return;

	list_del(&map->dma_node);

	zctap_OP_dma_buf_unmap(map, r->dmabuf, map->device);

	if (!r->host_region && list_empty(&r->dma_list)) {
		kvfree(map->pages);
		r->pages = NULL;
	}
	
	kvfree(map->dma);
	kfree(map);
}

void
zctap_region_unmap_ctx(struct zctap_ctx *ctx, struct zctap_dmamap *map)
{
	struct zctap_region *r = map->r;
	struct zctap_ctx_entry *ce;

	ce = __zctap_region_find_ctx(r, ctx);
	
	region_lock(r);

	list_del(&ce->ctx_entry_node);
	__zctap_region_put_mapping(r, map);

	region_unlock(r);

	kfree(ce);
	fput(r->file);
}

#if 0
/* Called when a region onwer needs to forcibly remove all attachments. */
/* XXX region doesn't go away - caller has a reference and must drop */
void
zctap_revoke_region(struct zctap_region *r)
{
	struct zctap_ctx_entry *ce, *tmp;

	/* caller is not in process context - this needs a spinlock */
	region_lock(r);

	list_for_each_entry_safe(ce, tmp, &r->ctx_entry_list, ctx_entry_node) {
		list_del(&ce->ctx_entry_node);
		zctap_ctx_revoke_mapping(ce->ctx, ce->map);
		__zctap_region_put_mapping(ce->map);
		kfree(ce);
	}

	region_unlock(r);
}
#endif

static void
zctap_free_region(struct zctap_region *r)
{

	WARN_ON_ONCE(!r->host_region && r->pages);
	WARN_ON_ONCE(!list_empty(&r->ctx_entry_list));
	WARN_ON_ONCE(!list_empty(&r->dma_list));
	WARN_ON_ONCE(r->vmap_count);

	zctap_OP_dma_buf_put(r->dmabuf);
	kfree(r);
}

static int
zctap_region_release(struct inode *inode, struct file *file)
{
	struct zctap_region *r = file->private_data;

	zctap_free_region(r);

	return 0;
}

/*
 * mappings may or may not be present in user space.
 * find a way to refer to mappings as (map:offset), not {gpu|user}_addr.
 */
static int
zctap_locate_region(struct zctap_region *r, unsigned long addr)
{
	if (!IS_ALIGNED(addr, PAGE_SIZE))
		return -EINVAL;

	r->start = addr;
	r->nr_pages = r->dmabuf->size >> PAGE_SHIFT;

	return 0;
}

static int
__zctap_region_vmap(struct zctap_region *r)
{
	void *vaddr;

	if (r->vmap_addr)
		goto addref;

	vaddr = zctap_OP_dma_buf_vmap(r->dmabuf);
	if (IS_ERR(vaddr))
		return PTR_ERR(vaddr);

	r->vmap_addr = vaddr;
	r->vmap_count = 0;

addref:
	r->vmap_count++;
	get_file(r->file);

	return 0;
}

int
zctap_region_vmap(struct zctap_region *r)
{
	int err;

	region_lock(r);
	err = __zctap_region_vmap(r);
	region_unlock(r);

	return err;
}

void
zctap_region_vunmap(struct zctap_region *r)
{

	region_lock(r);
	if (--r->vmap_count == 0) {
		zctap_OP_dma_buf_vunmap(r->dmabuf, r->vmap_addr);
		r->vmap_addr = 0;
	}
	region_unlock(r);
	fput(r->file);
}

int
zctap_region_from_dmabuf(int dmabuf_fd /*, int flags*/, unsigned long addr)
{
	int flags = O_RDWR | O_CLOEXEC;
	struct zctap_region *r;
	int fd, err;

	err = -ENOMEM;
	r = kzalloc(sizeof(struct zctap_region), GFP_KERNEL);
	if (!r)
		return err;

	INIT_LIST_HEAD(&r->ctx_entry_list);
	INIT_LIST_HEAD(&r->dma_list);
	mutex_init(&r->lock);

	r->dmabuf = dma_buf_get(dmabuf_fd);
	if (!r->dmabuf)
		goto out;

	err = zctap_locate_region(r, addr);
	if (err)
		goto out;

        fd = zctap_create_fd("[zctap_region]", &zctap_region_fops, r,
                             flags, &r->file);
	if (fd < 0) {
		err = fd;
		goto out;
	}

	fd_install(fd, r->file);
	return fd;

out:
	zctap_free_region(r);
	return err;
}

int
zctap_create_host_region(const struct iovec *iov /*, int flags */)
{
	int flags = O_RDWR | O_CLOEXEC;
	struct zctap_host_region *host;
	struct dma_buf *dmabuf;
	struct zctap_region *r;
	int fd, err;

	err = -ENOMEM;
	r = kzalloc(sizeof(struct zctap_region), GFP_KERNEL);
	if (!r)
		return err;

	INIT_LIST_HEAD(&r->ctx_entry_list);
	INIT_LIST_HEAD(&r->dma_list);
	mutex_init(&r->lock);

	dmabuf = zctap_create_host_dmabuf(iov);
	if (IS_ERR(dmabuf)) {
		err = PTR_ERR(dmabuf);
		goto out;
	}

	r->dmabuf = dmabuf;
	host = r->dmabuf->priv;

	r->start = host->start;
	r->pages = host->pages;
	r->nr_pages = host->nr_pages;
	r->host_region = true;

        fd = zctap_create_fd("[zctap_region]", &zctap_region_fops, r,
                             flags, &r->file);
	if (fd < 0) {
		err = fd;
		goto out;
	}

	fd_install(fd, r->file);
	return fd;

out:
	zctap_free_region(r);
	return err;
}
