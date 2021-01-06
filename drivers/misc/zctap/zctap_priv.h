#ifndef _ZCTAP_PRIV_H
#define _ZCTAP_PRIV_H

struct zctap_queue_map {
	unsigned prod		____cacheline_aligned_in_smp;
	unsigned cons		____cacheline_aligned_in_smp;
	unsigned char data[]	____cacheline_aligned_in_smp;
};

struct zctap_dmamap {
	struct list_head dma_node;		/* dma map of region */
	struct zctap_region *r;			/* owning region */
	struct device *device;			/* device map is for */
	refcount_t ref;				/* ctxs holding this map */

	/* dma-buf linkages */
	struct sg_table *sgt;
	void *provider_priv;

	unsigned long start ____cacheline_aligned;	/* copies from region */
	unsigned long nr_pages;
	unsigned flags;

	struct page **pages;
	dma_addr_t *dma;
};
#define ZCTAP_DMAFLAG_SYNC	BIT(0)

struct zctap_ctx;

struct zctap_ctx_entry {
	struct list_head ctx_entry_node;
	struct zctap_ctx *ctx;
	struct zctap_dmamap *map;
};

struct zctap_host_region {
	unsigned long start;
	unsigned long nr_pages;
	struct page **pages;
};

struct zctap_region {
	struct list_head dma_list;		/* dma mappings of region */
	struct list_head ctx_entry_list;	/* contexts using region */
	struct dma_buf *dmabuf;
	struct file *file;
	struct mutex lock;

	void *vmap_addr;			/* vmamapp'ed region */
	unsigned vmap_count;

	bool host_region;
	unsigned long start;
	unsigned long nr_pages;
	struct page **pages;
};

struct zctap_region *zctap_get_region(int fd);
void zctap_put_region(struct zctap_region *r);
struct zctap_dmamap *
	zctap_region_map_ctx(struct zctap_region *r, struct zctap_ctx *ctx);
void zctap_region_unmap_ctx(struct zctap_ctx *ctx, struct zctap_dmamap *map);
int zctap_attach_region(int zctap_fd, int region_fd);
int zctap_attach_meta_region(int zctap_fd, int region_fd);
int zctap_region_from_dmabuf(int provider_fd, unsigned long addr);
int zctap_create_host_region(const struct iovec *iov);
int zctap_region_vmap(struct zctap_region *r);
void zctap_region_vunmap(struct zctap_region *r);

int zctap_get_param(void *p, size_t size, void __user *uarg, size_t usize);
int zctap_put_param(void __user *uarg, size_t usize, void *p, size_t size);
int zctap_sys_attach_socket(void __user *uarg, size_t usize);
int zctap_sys_bind_queue(void __user *uarg, size_t usize);
int zctap_sys_attach_meta(void __user *uarg, size_t usize);

int zctap_create_fd(const char *name, const struct file_operations *fops,
		    void *obj, unsigned flags, struct file **filep);

struct dma_buf *zctap_create_host_dmabuf(const struct iovec *iov);
int zctap_create_context(int ifindex);

#if 0
extern const struct file_operations zctap_mem_fops;
extern struct miscdevice zctap_mem_dev;
extern struct zctap_ops host_ops;

struct zctap_dmamap *
	zctap_mem_attach_ctx(struct zctap_mem *mem,
			      int idx, struct zctap_ctx *ctx);
void zctap_map_detach_ctx(struct zctap_dmamap *map, struct zctap_ctx *ctx);
struct zctap_dmamap *
	zctap_ctx_detach_region(struct zctap_ctx *ctx,
				 struct zctap_region *r);
#endif
void zctap_detach_region(struct zctap_region *r);

#endif /* _ZCTAP_PRIV_H */
