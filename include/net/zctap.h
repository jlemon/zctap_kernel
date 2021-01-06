#ifndef _NET_ZCTAP_H
#define _NET_ZCTAP_H

#ifdef CONFIG_ZCTAP

#include <linux/skbuff.h>
#include <uapi/misc/zctap.h>		/* IOCTL defines */
#include <uapi/misc/shqueue.h>

#if 0

/* "struct page" has 64 byte alignment, so pointers to the page always have
 * zeros in the lower 6 bits.  These are repurposed in the pageptr encoding:
 *   bits 0:4 = start buffer offset in page
 *   bit  5   = sync required.
 */

#define ZCTAP_PTR_BITS		6
#define ZCTAP_PTR_MASK		((1UL << ZCTAP_PTR_BITS) - 1)	  // 0x3f
#define ZCTAP_OFFSET_BITS	(ZCTAP_PTR_BITS - 1)		  // 5
#define ZCTAP_OFFSET_MASK	((1UL << ZCTAP_OFFSET_BITS) - 1)  // 0x1f
#define ZCTAP_OFFSET_SHIFT	(PAGE_SHIFT - ZCTAP_OFFSET_BITS)  // 7
#define ZCTAP_PAGE_OFFSET_MASK	(ZCTAP_OFFSET_MASK << ZCTAP_OFFSET_SHIFT)
#define ZCTAP_NEED_SYNC		BIT(5)

#define ZCTAP_XOR_PAGEPTR	0x0531000000000000	/* catch errors */

static inline struct page *
__zctap_encode_pageptr(struct page *page, uintptr_t bits)
{
	uintptr_t pptr = (uintptr_t)page;
	return (struct page *)((pptr ^ ZCTAP_XOR_PAGEPTR) | bits);
}

static inline struct page *
__zctap_decode_pageptr(struct page *page)
{
	uintptr_t pptr = (uintptr_t)page;
	return (struct page *)((pptr ^ ZCTAP_XOR_PAGEPTR) & ~ZCTAP_PTR_MASK);
}

static inline struct page *
zctap_encode_pageptr(struct page *page, u32 off, bool sync)
{
	uintptr_t bits;

	WARN_ON_ONCE((uintptr_t)page & ZCTAP_PTR_MASK);	/* 6 bits clear */
	off = off >> ZCTAP_OFFSET_SHIFT;		/* bits 0:4 */
	bits = sync ? off | ZCTAP_NEED_SYNC : off;	/* bit	5   */
	return __zctap_encode_pageptr(page, bits);
}

static inline struct page *
zctap_pageptr_page(struct page *page)
{
	return __zctap_decode_pageptr(page);
}

static inline unsigned long
zctap_pageptr_offset(struct page *page)
{
	return ((uintptr_t)page & ZCTAP_OFFSET_MASK) << ZCTAP_OFFSET_SHIFT;
}

static inline unsigned
zctap_page_offset(unsigned long addr)
{
	return addr & ZCTAP_PAGE_OFFSET_MASK;
}

#else

#define ZCTAP_NEED_SYNC		BIT(5)

static inline struct page *
zctap_encode_pageptr(struct page *page, u32 off, bool sync)
{
	return page;
}

static inline struct page *
zctap_pageptr_page(struct page *page)
{
	return page;
}

static inline unsigned long
zctap_pageptr_offset(struct page *page)
{
	return 0;
}

static inline unsigned
zctap_page_offset(unsigned long addr)
{
	return 0;
}

#endif

static inline unsigned long
zctap_pageptr_base(struct page *page)
{
	return page_private(zctap_pageptr_page(page));
}

static inline unsigned long
zctap_pageptr_addr(struct page *page)
{
	return zctap_pageptr_base(page) + zctap_pageptr_offset(page);
}

static inline bool
zctap_page_sync(struct page *page)
{
	return (uintptr_t)page & ZCTAP_NEED_SYNC;
}

struct zctap_pgcache {
	struct zctap_pgcache *next;
	struct page *page[];
};

struct zctap_ifq {
	struct shared_queue fill;
	struct wait_queue_head fill_wait;
	struct zctap_ctx *ctx;
	struct ubuf_info uarg;
	int flags;
	int queue_id;
	enum zctap_split split;
	int split_offset;
	int fill_bufsz;
	spinlock_t pgcache_lock;
	struct zctap_pgcache *napi_cache;
	struct zctap_pgcache *spare_cache;
	struct zctap_pgcache *any_cache;
	int napi_cache_count;
	int any_cache_count;
	struct list_head ifq_node;
};

struct zctap_skq {
	struct shared_queue rx;
	struct shared_queue cq;		/* for requested completions */
	struct shared_queue meta;
	struct zctap_ctx *ctx;
	struct list_head info_list;
	unsigned meta_bufsz;
	unsigned inline_max;
	spinlock_t cq_lock;		/* completion queue lock */
	bool complete;
	struct sock *sk;
	void (*sk_destruct)(struct sock *sk);
	void (*sk_data_ready)(struct sock *sk);
};

struct zctap_ctx {
	struct xarray xa_vmap;		/* contains vmapped regions */
	struct xarray xa;		/* contains dmamaps */
	struct file *file;
	refcount_t ref;			/* XXX replace w/file */
	struct net_device *dev;
};

struct net_device;
struct zctap_ops;
struct socket;

dma_addr_t zctap_get_frag_dma(struct zctap_ctx *ctx, skb_frag_t *frag);
int zctap_get_page(struct zctap_ifq *ifq, struct page **page, dma_addr_t *dma);
void zctap_put_page(struct zctap_ifq *ifq, struct page *page, bool napi);
int zctap_get_pages(void *udata, struct page **pages, unsigned long addr,
		    int count);

struct ubuf_info *zctap_get_notifier(struct sock *sk);
int zctap_tx_add_notifier(struct sock *sk, struct cmsghdr *cmsg);

int zctap_deliver_udp(struct sock *sk, struct sk_buff *skb);

int zctap_socket_mmap(struct file *file, struct socket *sock,
		      struct vm_area_struct *vma);

int zctap_register(struct zctap_ops *ops);
void zctap_unregister(int memtype);

#else

static inline struct ubuf_info *zctap_get_notifier(struct sock *sk)
{
	return NULL;
}

static inline int zctap_tx_add_notifier(struct sock *sk, struct cmsghdr *cmsg)
{
	return -EOPNOTSUPP;
}

#endif /* CONFIG_ZCTAP */

#endif /* _NET_ZCTAP_H */
