#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/uio.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/pci.h>
#include <linux/memory.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/dma-buf.h>

#include <net/zctap.h>
#include <uapi/misc/zctap.h>

#include "zctap_priv.h"

#if 0
static void
zctap_unaccount_mem(struct user_struct *user, unsigned long nr_pages)
{
	atomic_long_sub(nr_pages, &user->locked_vm);
}

static int
zctap_account_mem(struct user_struct *user, unsigned long nr_pages)
{
	unsigned long page_limit, cur_pages, new_pages;

	page_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;

	do {
		cur_pages = atomic_long_read(&user->locked_vm);
		new_pages = cur_pages + nr_pages;
		if (new_pages > page_limit)
			return -ENOMEM;
	} while (atomic_long_cmpxchg(&user->locked_vm, cur_pages,
				     new_pages) != cur_pages);

	return 0;
}
#endif

/*
 * page refcount notes:
 *  the new pin/unpin user pages adds +1024 for pinned mappings.
 *  So pages in the first call to assign_page_addrs will have a page
 *  refcount = 1025 (1 for user mapping, 1024 for zctap pinning).
 *
 *  When calling put_pages, the process vma may have already been torn
 *  down (-1 for user ref), leaving only 1024 for the zctap mapping,
 *  which is released in unpin_user_pages.
 *
 * Chances are that an 'inuse' indication is required, if the stack holds
 * on to a skb with an attached zctap page before it reaches a sk.
 *
 * (skbs attached to the sk are torn down on sk closure).
 */

static void
zctap_host_put_pages(struct zctap_host_region *host, int nr_pages, bool clear)
{
	struct page *page;
	int i;

	if (clear) {
		for (i = 0; i < nr_pages; i++) {
			page = host->pages[i];
			ClearPagePrivate(page);
			set_page_private(page, 0);
		}
	}
	unpin_user_pages(host->pages, nr_pages);
}

static int
zctap_assign_page_addrs(struct zctap_host_region *host)
{
	struct page *page;
	int i;

	for (i = 0; i < host->nr_pages; i++) {
		page = host->pages[i];
		if (PagePrivate(page))
			goto out;
		SetPagePrivate(page);
		set_page_private(page, host->start + i * PAGE_SIZE);
	}

	return 0;

out:
	while (i--) {
		page = host->pages[i];
		ClearPagePrivate(page);
		set_page_private(page, 0);
	}

	return -EEXIST;
}

static struct sg_table *
zctap_get_sg_table(struct device *device, struct dma_buf *dmabuf,
		   enum dma_data_direction dir)
{
	struct zctap_host_region *host = dmabuf->priv;
	struct sg_table *sgt;
	int err;

	sgt = kzalloc(sizeof(*sgt), GFP_KERNEL);
	if (!sgt)
		return ERR_PTR(-ENOMEM);

	err = sg_alloc_table_from_pages(sgt, host->pages, host->nr_pages,
					0, host->nr_pages << PAGE_SHIFT,
					GFP_KERNEL);
	if (err)
		goto out;
	err = dma_map_sgtable(device, sgt, dir, 0);
	if (err)
		goto out;
	return sgt;

out:
	sg_free_table(sgt);
	kfree(sgt);
	return ERR_PTR(err);
}

static void
zctap_put_sg_table(struct device *device, struct sg_table *sgt,
		   enum dma_data_direction dir)
{
	dma_unmap_sgtable(device, sgt, dir, 0);
	sg_free_table(sgt);
	kfree(sgt);
}

static struct sg_table *
zctap_dmabuf_map(struct dma_buf_attachment *bat, enum dma_data_direction dir)
{
	return zctap_get_sg_table(bat->dev, bat->dmabuf, dir);
}

static void
zctap_dmabuf_unmap(struct dma_buf_attachment *bat, struct sg_table *sgt,
		   enum dma_data_direction dir)
{
	return zctap_put_sg_table(bat->dev, sgt, dir);
}

static void
zctap_dmabuf_release(struct dma_buf *dmabuf)
{
	struct zctap_host_region *host = dmabuf->priv;

	zctap_host_put_pages(host, host->nr_pages, true);
#if 0
	if (mem->account_mem)
		zctap_unaccount_mem(mem->user, r->nr_pages);
#endif
	kvfree(host->pages);
	kfree(host);
}

static int
zctap_dmabuf_vmap(struct dma_buf *dmabuf, struct dma_buf_map *map)
{
	struct zctap_host_region *host = dmabuf->priv;

	map->vaddr = vmap(host->pages, host->nr_pages, VM_MAP, PAGE_KERNEL);

	return map->vaddr ? 0 : -EFAULT;
}

static void
zctap_dmabuf_vunmap(struct dma_buf *dmabuf, struct dma_buf_map *map)
{
	vunmap(map->vaddr);
}

static const struct dma_buf_ops zctap_host_dmabuf_ops = {
	.cache_sgt_mapping	= true,
	.map_dma_buf		= zctap_dmabuf_map,
	.unmap_dma_buf		= zctap_dmabuf_unmap,
	.vmap			= zctap_dmabuf_vmap,
	.vunmap			= zctap_dmabuf_vunmap,
	.release		= zctap_dmabuf_release,
};

/*
 * Pins the pages when the dmabuf is created.
 */
struct dma_buf *
zctap_create_host_dmabuf(const struct iovec *iov)
{
	DEFINE_DMA_BUF_EXPORT_INFO(export);
	struct zctap_host_region *host;
	struct dma_buf *dmabuf;
	int err, nr_pages;
	u64 addr, len;
	int count = 0;

	addr = (u64)iov->iov_base;
	len = iov->iov_len;
	nr_pages = len >> PAGE_SHIFT;

	if (!IS_ALIGNED(addr, PAGE_SIZE) ||
	    !IS_ALIGNED(len, PAGE_SIZE) ||
	    !nr_pages)
		return ERR_PTR(-EINVAL);

	err = -ENOMEM;
	host = kzalloc(sizeof(struct zctap_host_region), GFP_KERNEL);
	if (!host)
		return ERR_PTR(err);

	host->pages = kvmalloc_array(nr_pages, sizeof(struct page *),
				     GFP_KERNEL);
	if (!host->pages)
		goto out;

#if 0
	if (mem->account_mem) {
		err = zctap_account_mem(mem->user, nr_pages);
		if (err)
			goto out;
	}
#endif

	host->start = addr;
	host->nr_pages = nr_pages;

	mmap_read_lock(current->mm);
	count = pin_user_pages(host->start, nr_pages,
			       FOLL_WRITE | FOLL_LONGTERM,
			       host->pages, NULL);
	mmap_read_unlock(current->mm);

	if (count != nr_pages) {
		err = count < 0 ? count : -EFAULT;
		goto out;
	}

	err = zctap_assign_page_addrs(host);
	if (err)
		goto out;

	export.ops = &zctap_host_dmabuf_ops;
	export.size = nr_pages << PAGE_SHIFT;
	export.priv = host;
	export.flags = O_RDWR;

	dmabuf = dma_buf_export(&export);
	if (IS_ERR(dmabuf)) {
		err = PTR_ERR(dmabuf);
		goto out;
	}

	return dmabuf;

out:
	if (count > 0)
		zctap_host_put_pages(host, count, false);
#if 0
	if (mem->account_mem && r->nr_pages)
		zctap_unaccount_mem(mem->user, r->nr_pages);
#endif
	kvfree(host->pages);
	kfree(host);

	return ERR_PTR(err);
}
