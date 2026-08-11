#ifndef _LIBNFTNL_SET_INTERNAL_H_
#define _LIBNFTNL_SET_INTERNAL_H_

#include <linux/netfilter/nf_tables.h>

struct nftnl_set {
	struct list_head	head;
	struct hlist_node	hnode;

	uint32_t		family;
	uint32_t		set_flags;
	const char		*table;
	const char		*name;
	uint64_t		handle;
	uint32_t		key_type;
	uint32_t		key_len;
	uint32_t		data_type;
	uint32_t		data_len;
	uint32_t		obj_type;
	struct {
		void		*data;
		uint32_t	len;
	} user;
	uint32_t		id;
	enum nft_set_policies	policy;
	struct {
		uint32_t	size;
		uint8_t		field_len[NFT_REG32_COUNT];
		uint8_t		field_count;
	} desc;
	struct list_head	element_list;

	uint32_t		flags;
	uint32_t		gc_interval;
	uint64_t		timeout;
	struct list_head	expr_list;
};

struct nftnl_set_list;
struct nftnl_expr;
int nftnl_set_lookup_id(struct nftnl_expr *e, struct nftnl_set_list *set_list,
		      uint32_t *set_id);

#endif
