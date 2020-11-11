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
#include <linux/indirect_call_wrapper.h>

#include <net/zctap.h>
#include <uapi/misc/zctap.h>

#include "zctap_priv.h"

struct zctap_host_region {
	struct zctap_region r;				/* must be first */
	struct page **page;
};

struct zctap_host_dmamap {
	struct zctap_dmamap map;			/* must be first */
	dma_addr_t dma[];
};

static inline struct zctap_host_region *
host_region(struct zctap_region *r)
{
	return (struct zctap_host_region *)r;
}

static inline struct zctap_host_dmamap *
host_map(struct zctap_dmamap *map)
{
	return (struct zctap_host_dmamap *)map;
}

/* Used by the lib/iov_iter to obtain a set of pages for TX */
INDIRECT_CALLABLE_SCOPE int
zctap_host_get_pages(struct zctap_region *r, struct page **pages,
		     unsigned long addr, int count)
{
	unsigned long idx;
	struct page *p;
	int i, n;

	idx = (addr - r->start) >> PAGE_SHIFT;
	n = r->nr_pages - idx + 1;
	n = min(count, n);

	for (i = 0; i < n; i++) {
		p = host_region(r)->page[idx + i];
		get_page(p);
		pages[i] = p;
	}

	return n;
}

INDIRECT_CALLABLE_SCOPE int
zctap_host_get_page(struct zctap_dmamap *map, unsigned long addr,
		    struct page **page, dma_addr_t *dma)
{
	unsigned long idx;
	struct page *p;

	idx = (addr - map->start) >> PAGE_SHIFT;

	*dma = host_map(map)->dma[idx];
	p = host_region(map->r)->page[idx];
	get_page(p);
	*page = zctap_set_page(p, map->flags & ZCTAP_DMAFLAG_SYNC);
	return 0;
}

INDIRECT_CALLABLE_SCOPE dma_addr_t
zctap_host_get_dma(struct zctap_dmamap *map, unsigned long addr)
{
	unsigned long idx;

	idx = (addr - map->start) >> PAGE_SHIFT;
	return host_map(map)->dma[idx];
}

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

static void
zctap_host_unmap_region(struct zctap_dmamap *map)
{
	int i;

	for (i = 0; i < map->nr_pages; i++)
		dma_unmap_page(map->device, host_map(map)->dma[i],
			       PAGE_SIZE, DMA_BIDIRECTIONAL);
}

static struct zctap_dmamap *
zctap_host_map_region(struct zctap_region *r, struct device *device)
{
	struct zctap_dmamap *map;
	struct page *page;
	dma_addr_t dma;
	size_t sz;
	int i;

	sz = struct_size(host_map(map), dma, r->nr_pages);
	map = kvmalloc(sz, GFP_KERNEL);
	if (!map)
		return ERR_PTR(-ENOMEM);

	for (i = 0; i < r->nr_pages; i++) {
		page = host_region(r)->page[i];
		dma = dma_map_page(device, page, 0, PAGE_SIZE,
				   DMA_BIDIRECTIONAL);
		if (unlikely(dma_mapping_error(device, dma)))
			goto out;

		host_map(map)->dma[i] = dma;
	}

	return map;

out:
	while (i--)
		dma_unmap_page(device, host_map(map)->dma[i], PAGE_SIZE,
			       DMA_BIDIRECTIONAL);

	kvfree(map);
	return ERR_PTR(-ENXIO);
}

/* NOTE: nr_pages may be negative on error. */
static void
zctap_host_put_pages(struct zctap_region *r, int nr_pages, bool clear)
{
	struct page *page;
	int i;

	for (i = 0; i < nr_pages; i++) {
		page = host_region(r)->page[i];
		if (clear) {
			ClearPagePrivate(page);
			set_page_private(page, 0);
		}
		put_page(page);
	}
}

static void
zctap_host_free_region(struct zctap_mem *mem, struct zctap_region *r)
{

	zctap_host_put_pages(r, r->nr_pages, true);
	if (mem->account_mem)
		zctap_unaccount_mem(mem->user, r->nr_pages);
	kvfree(host_region(r)->page);
	kfree(r);
}

static int
zctap_assign_page_addrs(struct zctap_region *r)
{
	struct page *page;
	int i;

	for (i = 0; i < r->nr_pages; i++) {
		page = host_region(r)->page[i];
		if (PagePrivate(page))
			goto out;
		SetPagePrivate(page);
		set_page_private(page, r->start + i * PAGE_SIZE);
	}

	return 0;

out:
	while (i--) {
		page = host_region(r)->page[i];
		ClearPagePrivate(page);
		set_page_private(page, 0);
	}

	return -EEXIST;
}

static struct zctap_region *
zctap_host_add_region(struct zctap_mem *mem, const struct iovec *iov)
{
	struct zctap_region *r;
	int err, nr_pages;
	u64 addr, len;
	int count = 0;

	err = -ENOMEM;
	r = kzalloc(sizeof(struct zctap_host_region), GFP_KERNEL);
	if (!r)
		return ERR_PTR(err);

	addr = (u64)iov->iov_base;
	r->start = round_down(addr, PAGE_SIZE);
	len = round_up(addr - r->start + iov->iov_len, PAGE_SIZE);
	nr_pages = len >> PAGE_SHIFT;

	r->mem = mem;
	r->nr_pages = nr_pages;
	INIT_LIST_HEAD(&r->ctx_list);
	INIT_LIST_HEAD(&r->dma_list);
	spin_lock_init(&r->lock);

	host_region(r)->page = kvmalloc_array(nr_pages, sizeof(struct page *),
					      GFP_KERNEL);
	if (!host_region(r)->page)
		goto out;

	if (mem->account_mem) {
		err = zctap_account_mem(mem->user, nr_pages);
		if (err) {
			nr_pages = 0;
			goto out;
		}
	}

	mmap_read_lock(current->mm);
	count = pin_user_pages(r->start, nr_pages,
			       FOLL_WRITE | FOLL_LONGTERM,
			       host_region(r)->page, NULL);
	mmap_read_unlock(current->mm);

	if (count != nr_pages) {
		err = count < 0 ? count : -EFAULT;
		goto out;
	}

	err = zctap_assign_page_addrs(r);
	if (err)
		goto out;

	return r;

out:
	zctap_host_put_pages(r, count, false);
	if (mem->account_mem && nr_pages)
		zctap_unaccount_mem(mem->user, nr_pages);
	kvfree(host_region(r)->page);
	kfree(r);

	return ERR_PTR(err);
}

struct zctap_ops host_ops = {
	.owner		= THIS_MODULE,
	.memtype	= ZCTAP_MEMTYPE_HOST,
	.add_region	= zctap_host_add_region,
	.free_region	= zctap_host_free_region,
	.map_region	= zctap_host_map_region,
	.unmap_region	= zctap_host_unmap_region,
	.get_dma	= zctap_host_get_dma,
	.get_page	= zctap_host_get_page,
	.get_pages	= zctap_host_get_pages,
};
