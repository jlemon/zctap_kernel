#ifndef _UAPI_MISC_ZCTAP_H
#define _UAPI_MISC_ZCTAP_H

#include <linux/ioctl.h>

#define ZCTAP_OFF_FILL_ID	(0ULL << 12)
#define ZCTAP_OFF_RX_ID		(1ULL << 12)
#define ZCTAP_OFF_CQ_ID		(2ULL << 12)
#define ZCTAP_OFF_META_ID	(3ULL << 12)

struct zctap_queue_offsets {
	unsigned prod;
	unsigned cons;
	unsigned data;
	unsigned resv;
};

struct zctap_user_queue {
	unsigned elt_sz;
	unsigned entries;
	unsigned mask;
	unsigned map_sz;
	unsigned map_off;
	struct zctap_queue_offsets off;
};

/* XXX remove */
enum zctap_memtype {
	MEMTYPE_HOST,
	MEMTYPE_CUDA,

	MEMTYPE_MAX,
};

/* VA memory provided by a specific PCI device. */
struct zctap_region_param {
	struct iovec iov;
	enum zctap_memtype memtype;	/* XXX remove */
	int provider_fd;
};

struct zctap_attach_param {
	int mem_fd;
	int mem_idx;
};

struct zctap_socket_param {
	unsigned resv;
	int fd;
	union {
		struct {
			struct zctap_user_queue rx;
			struct zctap_user_queue cq;
		};
		struct {
			struct iovec iov;
			struct zctap_user_queue meta;
			unsigned meta_len;
		};
	};
};

enum zctap_hdsplit {
	ZCTAP_SPLIT_NONE,
	ZCTAP_SPLIT_OFFSET,

	ZCTAP_SPLIT_LAST = ZCTAP_SPLIT_OFFSET
};

struct zctap_ifq_param {
	unsigned resv;
	unsigned ifq_fd;		/* OUT parameter */
	unsigned queue_id;		/* IN/OUT, IN: -1 if don't care */
	enum zctap_hdsplit hdsplit;
	unsigned split_offset;
	struct zctap_user_queue fill;
};

struct zctap_ctx_param {
	unsigned resv;
	unsigned ifindex;
};

#define ZCTAP_CTX_IOCTL_ATTACH_DEV	_IOR( 0, 1, int)
#define ZCTAP_CTX_IOCTL_BIND_QUEUE	_IOWR(0, 2, struct zctap_ifq_param)
#define ZCTAP_CTX_IOCTL_ATTACH_REGION	_IOW( 0, 3, struct zctap_attach_param)
#define ZCTAP_CTX_IOCTL_ATTACH_SOCKET	_IOW( 0, 4, struct zctap_socket_param)
#define ZCTAP_MEM_IOCTL_ADD_REGION	_IOR( 0, 5, struct zctap_region_param)

#endif /* _UAPI_MISC_ZCTAP_H */
