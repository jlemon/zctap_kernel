#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uio.h>
#include <linux/errno.h>
#include <linux/mutex.h>

#include <net/zctap.h>
#include <uapi/misc/zctap.h>

#include "zctap_stub.h"

static dma_addr_t
zctap_nop_get_dma(struct zctap_ctx *ctx, struct page *page)
{
	return 0;
}

static int
zctap_nop_get_page(struct zctap_ifq *ifq, struct page **page, dma_addr_t *dma)
{
	return -ENXIO;
}

static void
zctap_nop_put_page(struct zctap_ifq *ifq, struct page *page, bool napi)
{
}

static int
zctap_nop_get_pages(struct sock *sk, struct page **pages, unsigned long addr,
		     int count)
{
	return -ENXIO;
}

static int
zctap_nop_socket_mmap(struct file *file, struct socket *sock,
		       struct vm_area_struct *vma)
{
	return -ENOIOCTLCMD;
}

static int
zctap_nop_attach_socket(struct sock *sk, void __user *arg)
{
	return -ENOIOCTLCMD;
}

static struct zctap_functions zctap_nop = {
	.get_dma	= zctap_nop_get_dma,
	.get_page	= zctap_nop_get_page,
	.put_page	= zctap_nop_put_page,
	.get_pages	= zctap_nop_get_pages,
	.socket_mmap	= zctap_nop_socket_mmap,
	.attach_socket	= zctap_nop_attach_socket,
};

static struct zctap_functions *zctap_fcn;
static DEFINE_SPINLOCK(zctap_fcn_lock);

void
zctap_fcn_register(struct zctap_functions *f)
{
	spin_lock(&zctap_fcn_lock);
	rcu_assign_pointer(zctap_fcn, f);
	spin_unlock(&zctap_fcn_lock);

	synchronize_rcu();
}
EXPORT_SYMBOL(zctap_fcn_register);

void
zctap_fcn_unregister(void)
{
	zctap_fcn_register(&zctap_nop);
}
EXPORT_SYMBOL(zctap_fcn_unregister);

dma_addr_t
zctap_get_dma(struct zctap_ctx *ctx, struct page *page)
{
	struct zctap_functions *f;
	dma_addr_t dma;

	rcu_read_lock();
	f = rcu_dereference(zctap_fcn);
	dma = f->get_dma(ctx, page);
	rcu_read_unlock();

	return dma;
}
EXPORT_SYMBOL(zctap_get_dma);

int
zctap_get_page(struct zctap_ifq *ifq, struct page **page,
		dma_addr_t *dma)
{
	struct zctap_functions *f;
	int err;

	rcu_read_lock();
	f = rcu_dereference(zctap_fcn);
	err = f->get_page(ifq, page, dma);
	rcu_read_unlock();

	return err;
}
EXPORT_SYMBOL(zctap_get_page);

void
zctap_put_page(struct zctap_ifq *ifq, struct page *page, bool napi)
{
	struct zctap_functions *f;

	rcu_read_lock();
	f = rcu_dereference(zctap_fcn);
	f->put_page(ifq, page, napi);
	rcu_read_unlock();
}
EXPORT_SYMBOL(zctap_put_page);

int
zctap_get_pages(void *udata, struct page **pages, unsigned long addr, int count)
{
	struct zctap_functions *f;
	int err;

	rcu_read_lock();
	f = rcu_dereference(zctap_fcn);
	err = f->get_pages(udata, pages, addr, count);
	rcu_read_unlock();

	return err;
}

int
zctap_socket_mmap(struct file *file, struct socket *sock,
		   struct vm_area_struct *vma)
{
	struct zctap_functions *f;
	int err;

	rcu_read_lock();
	f = rcu_dereference(zctap_fcn);
	err = f->socket_mmap(file, sock, vma);
	rcu_read_unlock();

	return err;
}

int
zctap_attach_socket(struct sock *sk, void __user *arg)
{
	struct zctap_functions *f;
	int err;

	rcu_read_lock();
	f = rcu_dereference(zctap_fcn);
	err = f->attach_socket(sk, arg);
	rcu_read_unlock();

	return err;
}
