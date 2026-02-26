#ifndef _EXPR_OPS_H_
#define _EXPR_OPS_H_

#include <stdint.h>
#include "internal.h"

struct nlattr;
struct nlmsghdr;
struct nftnl_expr;

struct expr_ops {
	const char *name;
	uint32_t alloc_len;
	int	max_attr;
	void	(*init)(const struct nftnl_expr *e);
	void	(*free)(const struct nftnl_expr *e);
	int	(*set)(struct nftnl_expr *e, uint16_t type, const void *data, uint32_t data_len);
	const void *(*get)(const struct nftnl_expr *e, uint16_t type, uint32_t *data_len);
	int 	(*parse)(struct nftnl_expr *e, struct nlattr *attr);
	void	(*build)(struct nlmsghdr *nlh, const struct nftnl_expr *e);
	int	(*output)(char *buf, size_t len, uint32_t flags, const struct nftnl_expr *e);
};

struct expr_ops *nftnl_expr_ops_lookup(const char *name);

#define nftnl_expr_data(ops) (void *)ops->data

#endif
