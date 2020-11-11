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
	unsigned flags;

	unsigned long start;			/* copies from region */
	unsigned long nr_pages;
	dma_addr_t
		(*get_dma)(struct zctap_dmamap *map, unsigned long addr);
	int	(*get_page)(struct zctap_dmamap *map, unsigned long addr,
			    struct page **page, dma_addr_t *dma);
	int	(*get_pages)(struct zctap_region *r, struct page **pages,
			     unsigned long addr, int count);
};
#define ZCTAP_DMAFLAG_SYNC	BIT(0)

struct zctap_ctx;

struct zctap_ctx_entry {
	struct list_head ctx_node;
	struct zctap_ctx *ctx;
};

struct zctap_region {
	struct list_head dma_list;		/* dma mappings of region */
	struct list_head ctx_list;		/* contexts using region */
	struct list_head mem_node;		/* mem area owning region */
	struct zctap_mem *mem;
	struct zctap_ops *ops;
	unsigned long start;
	unsigned long nr_pages;
	int index;				/* unique per mem */
	spinlock_t lock;
};

/* assign the id on creation, just bump counter and match. */
struct zctap_mem {
	struct file *file;
	struct mutex lock;
	struct user_struct *user;
	int index_generator;
	unsigned account_mem : 1;
	struct list_head region_list;
};

struct zctap_ops {
	int	memtype;
	struct module *owner;

	struct zctap_region *
		(*add_region)(struct zctap_mem *, const struct iovec *);
	void	(*free_region)(struct zctap_mem *, struct zctap_region *);

	struct zctap_dmamap *
		(*map_region)(struct zctap_region *, struct device *);
	void	(*unmap_region)(struct zctap_dmamap *);

	dma_addr_t
		(*get_dma)(struct zctap_dmamap *map, unsigned long addr);
	int	(*get_page)(struct zctap_dmamap *map, unsigned long addr,
			    struct page **page, dma_addr_t *dma);
	int	(*get_pages)(struct zctap_region *r, struct page **pages,
			     unsigned long addr, int count);
};

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
void zctap_detach_region(struct zctap_region *r);

#endif /* _ZCTAP_PRIV_H */
