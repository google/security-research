#ifndef _OBJ_OPS_H_
#define _OBJ_OPS_H_

#include <stdint.h>
#include <libnftnl/object.h>	/* For NFTNL_CTTIMEOUT_ARRAY_MAX. */
#include "internal.h"

struct nlattr;
struct nlmsghdr;
struct nftnl_obj;

struct nftnl_obj {
	struct list_head	head;
	struct obj_ops		*ops;

	const char		*table;
	const char		*name;

	uint32_t		family;
	uint32_t		use;

	uint32_t		flags;
	uint64_t		handle;

	struct {
		void		*data;
		uint32_t	len;
	} user;

	union {
		struct nftnl_obj_counter {
			uint64_t	pkts;
			uint64_t	bytes;
		} counter;
		struct nftnl_obj_quota {
			uint64_t        bytes;
			uint64_t	consumed;
			uint32_t        flags;
		} quota;
		struct nftnl_obj_ct_helper {
			uint16_t	l3proto;
			uint8_t		l4proto;
			char		name[16];
		} ct_helper;
		struct nftnl_obj_ct_timeout {
			uint16_t	l3proto;
			uint8_t 	l4proto;
			uint32_t	timeout[NFTNL_CTTIMEOUT_ARRAY_MAX];
		} ct_timeout;
		struct nftnl_obj_ct_expect {
			uint16_t	l3proto;
			uint16_t	dport;
			uint8_t		l4proto;
			uint8_t		size;
			uint32_t	timeout;
		} ct_expect;
		struct nftnl_obj_limit {
			uint64_t	rate;
			uint64_t	unit;
			uint32_t	burst;
			uint32_t	type;
			uint32_t	flags;
		} limit;
		struct nftnl_obj_synproxy {
			uint16_t	mss;
			uint8_t		wscale;
			uint32_t	flags;
		} synproxy;
		struct nftnl_obj_tunnel {
			uint32_t	id;
			uint32_t	src_v4;
			uint32_t	dst_v4;
			struct in6_addr src_v6;
			struct in6_addr dst_v6;
			uint16_t	sport;
			uint16_t	dport;
			uint32_t	flowlabel;
			uint32_t	tun_flags;
			uint8_t		tun_tos;
			uint8_t		tun_ttl;
			union {
				struct {
					uint32_t	gbp;
				} tun_vxlan;
				struct {
					uint32_t	version;
					union {
						uint32_t	v1_index;
						struct {
							uint8_t	hwid;
							uint8_t	dir;
						} v2;
					} u;
				} tun_erspan;
			} u;
		} tunnel;
		struct nftnl_obj_secmark {
			char		ctx[NFT_SECMARK_CTX_MAXLEN];
		} secmark;
	} data;
};

struct obj_ops {
	const char *name;
	uint32_t type;
	size_t	alloc_len;
	int	max_attr;
	int	(*set)(struct nftnl_obj *e, uint16_t type, const void *data, uint32_t data_len);
	const void *(*get)(const struct nftnl_obj *e, uint16_t type, uint32_t *data_len);
	int	(*parse)(struct nftnl_obj *e, struct nlattr *attr);
	void	(*build)(struct nlmsghdr *nlh, const struct nftnl_obj *e);
	int	(*output)(char *buf, size_t len, uint32_t flags, const struct nftnl_obj *e);
};

extern struct obj_ops obj_ops_counter;
extern struct obj_ops obj_ops_quota;
extern struct obj_ops obj_ops_ct_helper;
extern struct obj_ops obj_ops_ct_timeout;
extern struct obj_ops obj_ops_ct_expect;
extern struct obj_ops obj_ops_limit;
extern struct obj_ops obj_ops_synproxy;
extern struct obj_ops obj_ops_tunnel;
extern struct obj_ops obj_ops_secmark;

#define nftnl_obj_data(obj) (void *)&obj->data

#endif
