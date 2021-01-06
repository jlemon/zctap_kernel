#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uio.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/memory.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/syscalls.h>

#include <net/zctap.h>
#include <uapi/misc/zctap.h>
#include "zctap_priv.h"

static int
zctap_check_param(void __user *arg, size_t actual, size_t expected)
{
	void __user *addr = arg + expected;
	int err;

	if (actual <= expected)
		return 0;

	err = check_zeroed_user(addr, actual - expected);
	if (err < 0)
		return err;
	return err ? 0 : -E2BIG;
}

int
zctap_get_param(void *p, size_t size, void __user *uarg, size_t usize)
{
	int err;

	err = zctap_check_param(uarg, usize, size);
	if (err)
		return err;

	usize = min_t(size_t, usize, size);
	if (copy_from_user(p, uarg, usize))
		return -EFAULT;

	memset(p + usize, 0, size - usize);

	return 0;
}

int
zctap_put_param(void __user *uarg, size_t usize, void *p, size_t size)
{
	int err;

        usize = min_t(size_t, usize, size);
	err = copy_to_user(uarg, p, usize);

	return err ? -EFAULT : 0;
}

static int
zctap_sys_create_host_region(void __user *uarg, size_t usize)
{
	struct zctap_host_param p;
	int err;

	err = zctap_get_param(&p, sizeof(p), uarg, usize);
	if (err)
		return err;

	return zctap_create_host_region(&p.iov);
}

static int
zctap_sys_region_from_dmabuf(void __user *uarg, size_t usize)
{
	struct zctap_dmabuf_param p;
	int err;

	err = zctap_get_param(&p, sizeof(p), uarg, usize);
	if (err)
		return err;

	return zctap_region_from_dmabuf(p.provider_fd, p.addr);
}

static int
zctap_sys_create_context(void __user *uarg, size_t usize)
{
	struct zctap_context_param p;
	int err;

	err = zctap_get_param(&p, sizeof(p), uarg, usize);
	if (err)
		return err;

	return zctap_create_context(p.ifindex);
}

static int
zctap_sys_attach_region(void __user *uarg, size_t usize)
{
	struct zctap_attach_param p;
	int err;

	err = zctap_get_param(&p, sizeof(p), uarg, usize);
	if (err)
		return err;

	return zctap_attach_region(p.zctap_fd, p.region_fd);
}

static int
zctap_sys_attach_meta_region(void __user *uarg, size_t usize)
{
	struct zctap_attach_param p;
	int err;

	err = zctap_get_param(&p, sizeof(p), uarg, usize);
	if (err)
		return err;

	return zctap_attach_meta_region(p.zctap_fd, p.region_fd);
}

SYSCALL_DEFINE3(zctap, unsigned int, cmd, void __user *, uarg,
		unsigned int, usize)
{
	switch (cmd) {
	case ZCTAP_CREATE_HOST_REGION:
		return zctap_sys_create_host_region(uarg, usize);

	case ZCTAP_REGION_FROM_DMABUF:
		return zctap_sys_region_from_dmabuf(uarg, usize);

	case ZCTAP_CREATE_CONTEXT:
		return zctap_sys_create_context(uarg, usize);

	case ZCTAP_ATTACH_REGION:
		return zctap_sys_attach_region(uarg, usize);

	case ZCTAP_ATTACH_SOCKET:
		return zctap_sys_attach_socket(uarg, usize);

	case ZCTAP_BIND_QUEUE:
		return zctap_sys_bind_queue(uarg, usize);

	case ZCTAP_ATTACH_META_REGION:
		return zctap_sys_attach_meta_region(uarg, usize);
	}
	return -EINVAL;
}
