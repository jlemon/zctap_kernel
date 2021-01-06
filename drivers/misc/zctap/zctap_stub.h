#pragma once

/* development-only support for module loading. */

struct zctap_functions {
	dma_addr_t (*get_dma)(struct zctap_ctx *ctx, struct page *page);
	int (*get_page)(struct zctap_ifq *ifq,
			struct page **page, dma_addr_t *dma);
	void (*put_page)(struct zctap_ifq *, struct page *, bool);
	int (*get_pages)(struct sock *, struct page **,
			 unsigned long, int);

	int (*socket_mmap)(struct file *file, struct socket *sock,
			   struct vm_area_struct *vma);
	int (*attach_socket)(struct sock *sk, void __user *arg);
};

void zctap_fcn_register(struct zctap_functions *f);
void zctap_fcn_unregister(void);
