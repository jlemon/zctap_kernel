#ifndef _NET_ZCTAP_H
#define _NET_ZCTAP_H

#ifdef CONFIG_ZCTAP

#include <linux/skbuff.h>
#include <uapi/misc/zctap.h>		/* IOCTL defines */
#include <uapi/misc/shqueue.h>

enum {
	ZCTAP_MEMTYPE_HOST,
	ZCTAP_MEMTYPE_CUDA,

	ZCTAP_MEMTYPE_MAX,
};

struct zctap_pgcache {
	struct zctap_pgcache *next;
	struct page *page[];
};

struct zctap_ifq {
	struct shared_queue fill;
	struct wait_queue_head fill_wait;
	struct zctap_ctx *ctx;
	struct ubuf_info uarg;
	int queue_id;
	int split_offset;
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
	struct zctap_ctx *ctx;
	struct zctap_meta *meta;
	struct list_head info_list;
	spinlock_t cq_lock;		/* completion queue lock */
	struct sock *sk;
	void (*sk_destruct)(struct sock *sk);
	void (*sk_data_ready)(struct sock *sk);
};

struct zctap_ctx {
	struct xarray xa;		/* contains dmamaps */
	refcount_t ref;
	struct net_device *dev;
	struct list_head ifq_list;
};

struct net_device;
struct zctap_ops;
struct socket;

dma_addr_t zctap_frag_for_device(struct zctap_ctx *ctx, skb_frag_t *frag);
int zctap_get_page(struct zctap_ifq *ifq, struct page **page, dma_addr_t *dma);
void zctap_put_page(struct zctap_ifq *ifq, struct page *page, bool napi);
int zctap_get_pages(void *udata, struct page **pages, unsigned long addr,
		    int count);

#define ZCTAP_PAGE		BIT(0)
#define ZCTAP_NEED_SYNC		BIT(1)

static inline bool
zctap_page(struct page *page)
{
	return (uintptr_t)page & ZCTAP_PAGE;
}

static inline bool
zctap_page_sync(struct page *page)
{
	return (uintptr_t)page & ZCTAP_NEED_SYNC;
}

static inline struct page *
zctap_set_page(struct page *page, bool sync)
{
	uintptr_t bits = sync ? ZCTAP_NEED_SYNC | ZCTAP_PAGE : ZCTAP_PAGE;

	return (struct page *)((uintptr_t)page | bits);
}

static inline struct page *
zctap_raw_page(struct page *page)
{
	return (struct page *)((uintptr_t)page & ~3);
}

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
