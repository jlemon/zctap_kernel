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

#include <net/zctap.h>
#include <uapi/misc/zctap.h>

#include "zctap_priv.h"

static struct zctap_ops *zctap_ops[MEMTYPE_MAX] = {
	[MEMTYPE_HOST]	= &host_ops,
};
static const char *zctap_name[] = {
	[MEMTYPE_HOST]	= "host",
	[MEMTYPE_CUDA]	= "cuda",
};
static DEFINE_SPINLOCK(zctap_lock);

int
zctap_register(struct zctap_ops *ops)
{
	int err;

	if (ops->memtype >= MEMTYPE_MAX)
		return -EBADR;

	err = -EEXIST;
	spin_lock(&zctap_lock);
	if (!rcu_dereference_protected(zctap_ops[ops->memtype],
				       lockdep_is_held(&zctap_lock))) {
		rcu_assign_pointer(zctap_ops[ops->memtype], ops);
		err = 0;
	}
	spin_unlock(&zctap_lock);

	return err;
}
EXPORT_SYMBOL(zctap_register);

void
zctap_unregister(int memtype)
{
	BUG_ON(memtype < 0 || memtype >= MEMTYPE_MAX);

	spin_lock(&zctap_lock);
	rcu_assign_pointer(zctap_ops[memtype], NULL);
	spin_unlock(&zctap_lock);

	synchronize_rcu();
}
EXPORT_SYMBOL(zctap_unregister);

static inline struct device *
netdev2device(struct net_device *dev)
{
	return dev->dev.parent;			/* from SET_NETDEV_DEV() */
}

static struct zctap_ctx_entry *
__zctap_region_find_ctx(struct zctap_region *r, struct zctap_ctx *ctx)
{
	struct zctap_ctx_entry *ce;

	list_for_each_entry(ce, &r->ctx_list, ctx_node)
		if (ce->ctx == ctx)
			return ce;
	return NULL;
}

void
zctap_map_detach_ctx(struct zctap_dmamap *map, struct zctap_ctx *ctx)
{
	struct zctap_region *r = map->r;
	struct zctap_ctx_entry *ce;
	bool unmap;

	spin_lock(&r->lock);

	ce = __zctap_region_find_ctx(r, ctx);
	list_del(&ce->ctx_node);

	unmap = refcount_dec_and_test(&map->ref);
	if (unmap)
		list_del(&map->dma_node);

	spin_unlock(&r->lock);

	if (unmap) {
		r->ops->unmap_region(map);
		kvfree(map);
	}

	kfree(ce);
	fput(r->mem->file);
}

static struct zctap_dmamap *
__zctap_region_find_device(struct zctap_region *r, struct device *device)
{
	struct zctap_dmamap *map;

	list_for_each_entry(map, &r->dma_list, dma_node)
		if (map->device == device) {
			refcount_inc(&map->ref);
			return map;
		}
	return NULL;
}

static struct zctap_region *
__zctap_mem_find_region(struct zctap_mem *mem, int idx)
{
	struct zctap_region *r;

	list_for_each_entry(r, &mem->region_list, mem_node)
		if (r->index == idx)
			return r;
	return NULL;
}

struct zctap_region *
zctap_get_region(struct zctap_mem *mem, int idx)
{
	struct zctap_region *r;

	rcu_read_lock();
	r = __zctap_mem_find_region(mem, idx);
	rcu_read_unlock();

	return r;
}

struct zctap_dmamap *
zctap_mem_attach_ctx(struct zctap_mem *mem, int idx, struct zctap_ctx *ctx)
{
	struct zctap_ctx_entry *ce;
	struct zctap_dmamap *map;
	struct zctap_region *r;
	struct device *device;

	rcu_read_lock();
	r = __zctap_mem_find_region(mem, idx);
	rcu_read_unlock();

	if (!r)
		return ERR_PTR(-ENOENT);

	spin_lock(&r->lock);

	ce = __zctap_region_find_ctx(r, ctx);
	if (ce) {
		map = ERR_PTR(-EEXIST);
		goto out_unlock;
	}

	ce = kmalloc(sizeof(*ce), GFP_KERNEL);
	if (!ce) {
		map = ERR_PTR(-ENOMEM);
		goto out_unlock;
	}

	device = netdev2device(ctx->dev);
	map = __zctap_region_find_device(r, device);
	if (!map) {
		map = r->ops->map_region(r, device);
		if (IS_ERR(map)) {
			kfree(ce);
			goto out_unlock;
		}

		map->r = r;
		map->start = r->start;
		map->device = device;
		map->nr_pages = r->nr_pages;
		map->get_dma = r->ops->get_dma;
		map->get_page = r->ops->get_page;
		map->get_pages = r->ops->get_pages;

		refcount_set(&map->ref, 1);

		list_add(&map->dma_node, &r->dma_list);
	}

	ce->ctx = ctx;
	list_add(&ce->ctx_node, &r->ctx_list);
	get_file(mem->file);

out_unlock:
	spin_unlock(&r->lock);
	return map;
}

static void
zctap_mem_free_region(struct zctap_mem *mem, struct zctap_region *r)
{
	struct zctap_ops *ops = r->ops;

	WARN_ONCE(!list_empty(&r->ctx_list), "context list not empty!");
	WARN_ONCE(!list_empty(&r->dma_list), "DMA list not empty!");

	/* removes page mappings, frees r */
	ops->free_region(mem, r);
	module_put(ops->owner);
}

/* region overlaps will fail due to PagePrivate bit */
static int
zctap_mem_add_region(struct zctap_mem *mem, void __user *arg)
{
	struct zctap_region_param p;
	struct zctap_region *r;
	struct zctap_ops *ops;

	if (copy_from_user(&p, arg, sizeof(p)))
		return -EFAULT;

	if (p.memtype < 0 || p.memtype >= MEMTYPE_MAX)
		return -ENXIO;

#ifdef CONFIG_MODULES
	if (!rcu_access_pointer(zctap_ops[p.memtype]))
		request_module("zctap_%s", zctap_name[p.memtype]);
#endif

	rcu_read_lock();
	ops = rcu_dereference(zctap_ops[p.memtype]);
	if (!ops || !try_module_get(ops->owner)) {
		rcu_read_unlock();
		return -ENXIO;
	}
	rcu_read_unlock();

	r = ops->add_region(mem, &p.iov);
	if (IS_ERR(r)) {
		module_put(ops->owner);
		return PTR_ERR(r);
	}

	r->ops = ops;

	mutex_lock(&mem->lock);
	r->index = ++mem->index_generator;
	list_add_rcu(&r->mem_node, &mem->region_list);
	mutex_unlock(&mem->lock);

	return r->index;
}

/* This function is called from the nvidia callback, ick. */
void
zctap_detach_region(struct zctap_region *r)
{
	struct zctap_mem *mem = r->mem;
	struct zctap_ctx_entry *ce, *tmp;
	struct zctap_dmamap *map;

	mutex_lock(&mem->lock);
	list_del(&r->mem_node);
	mutex_unlock(&mem->lock);

	spin_lock(&r->lock);

	list_for_each_entry_safe(ce, tmp, &r->ctx_list, ctx_node) {
		list_del(&ce->ctx_node);
		map = zctap_ctx_detach_region(ce->ctx, r);

		if (refcount_dec_and_test(&map->ref)) {
			list_del(&map->dma_node);
			r->ops->unmap_region(map);
			kvfree(map);
		}

		kfree(ce);
		fput(r->mem->file);
	}

	spin_unlock(&r->lock);
	zctap_mem_free_region(mem, r);

	/* XXX nvidia bug - keeps extra file reference?? */
	fput(mem->file);
}
EXPORT_SYMBOL(zctap_detach_region);

static long
zctap_mem_ioctl(struct file *file, unsigned cmd, unsigned long arg)
{
	struct zctap_mem *mem = file->private_data;

	switch (cmd) {
	case ZCTAP_MEM_IOCTL_ADD_REGION:
		return zctap_mem_add_region(mem, (void __user *)arg);
	}
	return -ENOTTY;
}

static void
__zctap_free_mem(struct zctap_mem *mem)
{
	struct zctap_region *r, *tmp;

	/* no lock needed - no refs at this point */
	list_for_each_entry_safe(r, tmp, &mem->region_list, mem_node)
		zctap_mem_free_region(mem, r);

	free_uid(mem->user);
	kfree(mem);
}

static int
zctap_mem_release(struct inode *inode, struct file *file)
{
	struct zctap_mem *mem = file->private_data;

	__zctap_free_mem(mem);

	module_put(THIS_MODULE);

	return 0;
}

static int
zctap_mem_open(struct inode *inode, struct file *file)
{
	struct zctap_mem *mem;

	mem = kmalloc(sizeof(*mem), GFP_KERNEL);
	if (!mem)
		return -ENOMEM;

	mem->account_mem = !capable(CAP_IPC_LOCK);
	mem->user = get_uid(current_user());
	mem->file = file;
	mem->index_generator = 0;
	mutex_init(&mem->lock);
	INIT_LIST_HEAD(&mem->region_list);

	file->private_data = mem;

	__module_get(THIS_MODULE);

	return 0;
}

const struct file_operations zctap_mem_fops = {
	.owner =		THIS_MODULE,
	.open =			zctap_mem_open,
	.unlocked_ioctl =	zctap_mem_ioctl,
	.release =		zctap_mem_release,
};

struct miscdevice zctap_mem_dev = {
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= "zctap_mem",
	.fops		= &zctap_mem_fops,
};
