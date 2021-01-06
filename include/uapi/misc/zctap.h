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
};

struct zctap_user_queue {
	unsigned elt_sz;
	unsigned entries;
	unsigned mask;
	unsigned map_sz;
	unsigned map_off;
	struct zctap_queue_offsets off;
};

enum zctap_cmd {
	ZCTAP_CREATE_HOST_REGION,
	ZCTAP_REGION_FROM_DMABUF,
	ZCTAP_CREATE_CONTEXT,
	ZCTAP_ATTACH_REGION,
	ZCTAP_ATTACH_SOCKET,
	ZCTAP_ATTACH_META_REGION,
	ZCTAP_BIND_QUEUE,
};

struct zctap_host_param {
	struct iovec iov;
};

struct zctap_dmabuf_param {
	int provider_fd;
	unsigned long addr;
};

struct zctap_context_param {
	unsigned ifindex;
};

struct zctap_attach_param {
	int zctap_fd;
	int region_fd;
};

struct zctap_socket_param {
	int zctap_fd;
	int socket_fd;
	struct zctap_user_queue rx;
	struct zctap_user_queue cq;	/* XXX remove */

	struct zctap_user_queue meta;
	unsigned meta_bufsz;
	unsigned inline_max;

	/* flags for recv specification */
};

enum zctap_split {
	ZCTAP_SPLIT_NONE,	/* aka L1 */
	ZCTAP_SPLIT_L2,
	ZCTAP_SPLIT_L3,
	ZCTAP_SPLIT_L4,
};

struct zctap_ifq_param {
	unsigned zctap_fd;
	unsigned queue_id;		/* IN/OUT, IN: -1 if don't care */
	enum zctap_split split;
	unsigned split_offset;		/* additional split after header */
	struct zctap_user_queue fill;
	unsigned fill_bufsz;
};

/*---------------------------------------------------------------------------*/

/*
 * Layout of packet data:
 *  [ data_len ][pad][ iovec ... ][ name_len ][ cmsg_len ]
 * iovec starts on a 8 byte boundary.
 */
struct zctap_iovec {
	__u64	base;
	__u32	offset;
	__u32	length;
};

struct zctap_pktdata {
	__u16	data_len;
	__u8	iov_count;
	__u8	name_len;
	__u8	cmsg_len;
	__u8	_pad;
	__u16	flags;
	__u8	data[];
};

#define ZCTAP_CTX_IOCTL_ATTACH_DEV	_IOR( 0, 1, int)
#define ZCTAP_CTX_IOCTL_BIND_QUEUE	_IOWR(0, 2, struct zctap_ifq_param)
#define ZCTAP_CTX_IOCTL_ATTACH_REGION	_IOW( 0, 3, struct zctap_mem_attach_param)
#define ZCTAP_CTX_IOCTL_ATTACH_SOCKET	_IOW( 0, 4, struct zctap_socket_param)
#define ZCTAP_MEM_IOCTL_ADD_REGION	_IOR( 0, 5, struct zctap_region_param)

#endif /* _UAPI_MISC_ZCTAP_H */
