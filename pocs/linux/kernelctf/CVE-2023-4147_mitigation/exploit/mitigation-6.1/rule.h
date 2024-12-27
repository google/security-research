#ifndef _LIBNFTNL_RULE_INTERNAL_H_
#define _LIBNFTNL_RULE_INTERNAL_H_

struct nftnl_rule {
	struct list_head head;

	uint32_t	flags;
	uint32_t	family;
	const char	*table;
	const char	*chain;
	uint32_t	chain_id;
	uint64_t	handle;
	uint64_t	position;
	uint32_t	id;
	uint32_t	position_id;
	struct {
			void		*data;
			uint32_t	len;
	} user;
	struct {
			uint32_t	flags;
			uint32_t	proto;
	} compat;

	struct list_head expr_list;
};

#endif
