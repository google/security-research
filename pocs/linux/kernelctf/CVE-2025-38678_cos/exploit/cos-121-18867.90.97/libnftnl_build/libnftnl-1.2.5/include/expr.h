#ifndef _LIBNFTNL_EXPR_INTERNAL_H_
#define _LIBNFTNL_EXPR_INTERNAL_H_

struct expr_ops;

struct nftnl_expr {
	struct list_head	head;
	uint32_t		flags;
	struct expr_ops		*ops;
	uint8_t			data[];
};

struct nlmsghdr;

void nftnl_expr_build_payload(struct nlmsghdr *nlh, struct nftnl_expr *expr);
struct nftnl_expr *nftnl_expr_parse(struct nlattr *attr);


#endif
