/*
 * (C) 2012-2013 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This code has been sponsored by Sophos Astaro <http://www.sophos.com>
 */
#include "internal.h"

#include <time.h>
#include <endian.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <netinet/in.h>
#include <errno.h>
#include <inttypes.h>
#include <ctype.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <libnftnl/rule.h>
#include <libnftnl/set.h>
#include <libnftnl/expr.h>

EXPORT_SYMBOL(nftnl_rule_alloc);
struct nftnl_rule *nftnl_rule_alloc(void)
{
	struct nftnl_rule *r;

	r = calloc(1, sizeof(struct nftnl_rule));
	if (r == NULL)
		return NULL;

	INIT_LIST_HEAD(&r->expr_list);

	return r;
}

EXPORT_SYMBOL(nftnl_rule_free);
void nftnl_rule_free(const struct nftnl_rule *r)
{
	struct nftnl_expr *e, *tmp;

	list_for_each_entry_safe(e, tmp, &r->expr_list, head)
		nftnl_expr_free(e);

	if (r->flags & (1 << (NFTNL_RULE_TABLE)))
		xfree(r->table);
	if (r->flags & (1 << (NFTNL_RULE_CHAIN)))
		xfree(r->chain);
	if (r->flags & (1 << (NFTNL_RULE_USERDATA)))
		xfree(r->user.data);

	xfree(r);
}

EXPORT_SYMBOL(nftnl_rule_is_set);
bool nftnl_rule_is_set(const struct nftnl_rule *r, uint16_t attr)
{
	return r->flags & (1 << attr);
}

EXPORT_SYMBOL(nftnl_rule_unset);
void nftnl_rule_unset(struct nftnl_rule *r, uint16_t attr)
{
	if (!(r->flags & (1 << attr)))
		return;

	switch (attr) {
	case NFTNL_RULE_TABLE:
		xfree(r->table);
		break;
	case NFTNL_RULE_CHAIN:
		xfree(r->chain);
		break;
	case NFTNL_RULE_CHAIN_ID:
	case NFTNL_RULE_HANDLE:
	case NFTNL_RULE_COMPAT_PROTO:
	case NFTNL_RULE_COMPAT_FLAGS:
	case NFTNL_RULE_POSITION:
	case NFTNL_RULE_FAMILY:
	case NFTNL_RULE_ID:
	case NFTNL_RULE_POSITION_ID:
		break;
	case NFTNL_RULE_USERDATA:
		xfree(r->user.data);
		break;
	}

	r->flags &= ~(1 << attr);
}

static uint32_t nftnl_rule_validate[NFTNL_RULE_MAX + 1] = {
	[NFTNL_RULE_CHAIN_ID]           = sizeof(uint32_t),
	[NFTNL_RULE_HANDLE]		= sizeof(uint64_t),
	[NFTNL_RULE_COMPAT_PROTO]	= sizeof(uint32_t),
	[NFTNL_RULE_COMPAT_FLAGS]	= sizeof(uint32_t),
	[NFTNL_RULE_FAMILY]		= sizeof(uint32_t),
	[NFTNL_RULE_POSITION]		= sizeof(uint64_t),
	[NFTNL_RULE_ID]			= sizeof(uint32_t),
	[NFTNL_RULE_POSITION_ID]	= sizeof(uint32_t),
};

EXPORT_SYMBOL(nftnl_rule_set_data);
int nftnl_rule_set_data(struct nftnl_rule *r, uint16_t attr,
			const void *data, uint32_t data_len)
{
	nftnl_assert_attr_exists(attr, NFTNL_RULE_MAX);
	nftnl_assert_validate(data, nftnl_rule_validate, attr, data_len);

	switch(attr) {
	case NFTNL_RULE_TABLE:
		if (r->flags & (1 << NFTNL_RULE_TABLE))
			xfree(r->table);

		r->table = strdup(data);
		if (!r->table)
			return -1;
		break;
	case NFTNL_RULE_CHAIN:
		if (r->flags & (1 << NFTNL_RULE_CHAIN))
			xfree(r->chain);

		r->chain = strdup(data);
		if (!r->chain)
			return -1;
		break;
	case NFTNL_RULE_CHAIN_ID:
                memcpy(&r->chain_id, data, sizeof(r->chain_id));
                break;
	case NFTNL_RULE_HANDLE:
		memcpy(&r->handle, data, sizeof(r->handle));
		break;
	case NFTNL_RULE_COMPAT_PROTO:
		memcpy(&r->compat.proto, data, sizeof(r->compat.proto));
		break;
	case NFTNL_RULE_COMPAT_FLAGS:
		memcpy(&r->compat.flags, data, sizeof(r->compat.flags));
		break;
	case NFTNL_RULE_FAMILY:
		memcpy(&r->family, data, sizeof(r->family));
		break;
	case NFTNL_RULE_POSITION:
		memcpy(&r->position, data, sizeof(r->position));
		break;
	case NFTNL_RULE_USERDATA:
		if (r->flags & (1 << NFTNL_RULE_USERDATA))
			xfree(r->user.data);

		r->user.data = malloc(data_len);
		if (!r->user.data)
			return -1;

		memcpy(r->user.data, data, data_len);
		r->user.len = data_len;
		break;
	case NFTNL_RULE_ID:
		memcpy(&r->id, data, sizeof(r->id));
		break;
	case NFTNL_RULE_POSITION_ID:
		memcpy(&r->position_id, data, sizeof(r->position_id));
		break;
	}
	r->flags |= (1 << attr);
	return 0;
}

int nftnl_rule_set(struct nftnl_rule *r, uint16_t attr, const void *data) __visible;
int nftnl_rule_set(struct nftnl_rule *r, uint16_t attr, const void *data)
{
	return nftnl_rule_set_data(r, attr, data, nftnl_rule_validate[attr]);
}

EXPORT_SYMBOL(nftnl_rule_set_u32);
void nftnl_rule_set_u32(struct nftnl_rule *r, uint16_t attr, uint32_t val)
{
	nftnl_rule_set_data(r, attr, &val, sizeof(uint32_t));
}

EXPORT_SYMBOL(nftnl_rule_set_u64);
void nftnl_rule_set_u64(struct nftnl_rule *r, uint16_t attr, uint64_t val)
{
	nftnl_rule_set_data(r, attr, &val, sizeof(uint64_t));
}

EXPORT_SYMBOL(nftnl_rule_set_str);
int nftnl_rule_set_str(struct nftnl_rule *r, uint16_t attr, const char *str)
{
	return nftnl_rule_set_data(r, attr, str, strlen(str) + 1);
}

EXPORT_SYMBOL(nftnl_rule_get_data);
const void *nftnl_rule_get_data(const struct nftnl_rule *r, uint16_t attr,
				   uint32_t *data_len)
{
	if (!(r->flags & (1 << attr)))
		return NULL;

	switch(attr) {
	case NFTNL_RULE_FAMILY:
		*data_len = sizeof(uint32_t);
		return &r->family;
	case NFTNL_RULE_TABLE:
		*data_len = strlen(r->table) + 1;
		return r->table;
	case NFTNL_RULE_CHAIN:
		*data_len = strlen(r->chain) + 1;
		return r->chain;
        case NFTNL_RULE_CHAIN_ID:
                *data_len = sizeof(uint32_t);
                return &r->chain_id;
	case NFTNL_RULE_HANDLE:
		*data_len = sizeof(uint64_t);
		return &r->handle;
	case NFTNL_RULE_COMPAT_PROTO:
		*data_len = sizeof(uint32_t);
		return &r->compat.proto;
	case NFTNL_RULE_COMPAT_FLAGS:
		*data_len = sizeof(uint32_t);
		return &r->compat.flags;
	case NFTNL_RULE_POSITION:
		*data_len = sizeof(uint64_t);
		return &r->position;
	case NFTNL_RULE_USERDATA:
		*data_len = r->user.len;
		return r->user.data;
	case NFTNL_RULE_ID:
		*data_len = sizeof(uint32_t);
		return &r->id;
	case NFTNL_RULE_POSITION_ID:
		*data_len = sizeof(uint32_t);
		return &r->position_id;
	}
	return NULL;
}

EXPORT_SYMBOL(nftnl_rule_get);
const void *nftnl_rule_get(const struct nftnl_rule *r, uint16_t attr)
{
	uint32_t data_len;
	return nftnl_rule_get_data(r, attr, &data_len);
}

EXPORT_SYMBOL(nftnl_rule_get_str);
const char *nftnl_rule_get_str(const struct nftnl_rule *r, uint16_t attr)
{
	return nftnl_rule_get(r, attr);
}

EXPORT_SYMBOL(nftnl_rule_get_u32);
uint32_t nftnl_rule_get_u32(const struct nftnl_rule *r, uint16_t attr)
{
	uint32_t data_len;
	const uint32_t *val = nftnl_rule_get_data(r, attr, &data_len);

	nftnl_assert(val, attr, data_len == sizeof(uint32_t));

	return val ? *val : 0;
}

EXPORT_SYMBOL(nftnl_rule_get_u64);
uint64_t nftnl_rule_get_u64(const struct nftnl_rule *r, uint16_t attr)
{
	uint32_t data_len;
	const uint64_t *val = nftnl_rule_get_data(r, attr, &data_len);

	nftnl_assert(val, attr, data_len == sizeof(uint64_t));

	return val ? *val : 0;
}

EXPORT_SYMBOL(nftnl_rule_get_u8);
uint8_t nftnl_rule_get_u8(const struct nftnl_rule *r, uint16_t attr)
{
	uint32_t data_len;
	const uint8_t *val = nftnl_rule_get_data(r, attr, &data_len);

	nftnl_assert(val, attr, data_len == sizeof(uint8_t));

	return val ? *val : 0;
}

EXPORT_SYMBOL(nftnl_rule_nlmsg_build_payload);
void nftnl_rule_nlmsg_build_payload(struct nlmsghdr *nlh, struct nftnl_rule *r)
{
	struct nftnl_expr *expr;
	struct nlattr *nest, *nest2;

	if (r->flags & (1 << NFTNL_RULE_TABLE))
		mnl_attr_put_strz(nlh, NFTA_RULE_TABLE, r->table);
	if (r->flags & (1 << NFTNL_RULE_CHAIN))
		mnl_attr_put_strz(nlh, NFTA_RULE_CHAIN, r->chain);
	if (r->flags & (1 << NFTNL_RULE_CHAIN_ID))
		mnl_attr_put_u32(nlh, NFTA_RULE_CHAIN_ID, htobe32(r->chain_id));
	if (r->flags & (1 << NFTNL_RULE_HANDLE))
		mnl_attr_put_u64(nlh, NFTA_RULE_HANDLE, htobe64(r->handle));
	if (r->flags & (1 << NFTNL_RULE_POSITION))
		mnl_attr_put_u64(nlh, NFTA_RULE_POSITION, htobe64(r->position));
	if (r->flags & (1 << NFTNL_RULE_USERDATA)) {
		mnl_attr_put(nlh, NFTA_RULE_USERDATA, r->user.len,
			     r->user.data);
	}

	if (!list_empty(&r->expr_list)) {
		nest = mnl_attr_nest_start(nlh, NFTA_RULE_EXPRESSIONS);
		list_for_each_entry(expr, &r->expr_list, head) {
			nest2 = mnl_attr_nest_start(nlh, NFTA_LIST_ELEM);
			nftnl_expr_build_payload(nlh, expr);
			mnl_attr_nest_end(nlh, nest2);
		}
		mnl_attr_nest_end(nlh, nest);
	}

	if (r->flags & (1 << NFTNL_RULE_COMPAT_PROTO) &&
	    r->flags & (1 << NFTNL_RULE_COMPAT_FLAGS)) {

		nest = mnl_attr_nest_start(nlh, NFTA_RULE_COMPAT);
		mnl_attr_put_u32(nlh, NFTA_RULE_COMPAT_PROTO,
				 htonl(r->compat.proto));
		mnl_attr_put_u32(nlh, NFTA_RULE_COMPAT_FLAGS,
				 htonl(r->compat.flags));
		mnl_attr_nest_end(nlh, nest);
	}
	if (r->flags & (1 << NFTNL_RULE_ID))
		mnl_attr_put_u32(nlh, NFTA_RULE_ID, htonl(r->id));
	if (r->flags & (1 << NFTNL_RULE_POSITION_ID))
		mnl_attr_put_u32(nlh, NFTA_RULE_POSITION_ID, htonl(r->position_id));
}

EXPORT_SYMBOL(nftnl_rule_add_expr);
void nftnl_rule_add_expr(struct nftnl_rule *r, struct nftnl_expr *expr)
{
	list_add_tail(&expr->head, &r->expr_list);
}

EXPORT_SYMBOL(nftnl_rule_del_expr);
void nftnl_rule_del_expr(struct nftnl_expr *expr)
{
	list_del(&expr->head);
}

static int nftnl_rule_parse_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_RULE_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_RULE_TABLE:
	case NFTA_RULE_CHAIN:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0)
			abi_breakage();
		break;
	case NFTA_RULE_HANDLE:
		if (mnl_attr_validate(attr, MNL_TYPE_U64) < 0)
			abi_breakage();
		break;
	case NFTA_RULE_COMPAT:
		if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0)
			abi_breakage();
		break;
	case NFTA_RULE_POSITION:
		if (mnl_attr_validate(attr, MNL_TYPE_U64) < 0)
			abi_breakage();
		break;
	case NFTA_RULE_USERDATA:
		if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0)
			abi_breakage();
		break;
	case NFTA_RULE_ID:
	case NFTA_RULE_POSITION_ID:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static int nftnl_rule_parse_expr(struct nlattr *nest, struct nftnl_rule *r)
{
	struct nftnl_expr *expr;
	struct nlattr *attr;

	mnl_attr_for_each_nested(attr, nest) {
		if (mnl_attr_get_type(attr) != NFTA_LIST_ELEM)
			return -1;

		expr = nftnl_expr_parse(attr);
		if (expr == NULL)
			return -1;

		list_add_tail(&expr->head, &r->expr_list);
	}
	return 0;
}

static int nftnl_rule_parse_compat_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_RULE_COMPAT_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_RULE_COMPAT_PROTO:
	case NFTA_RULE_COMPAT_FLAGS:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static int nftnl_rule_parse_compat(struct nlattr *nest, struct nftnl_rule *r)
{
	struct nlattr *tb[NFTA_RULE_COMPAT_MAX+1] = {};

	if (mnl_attr_parse_nested(nest, nftnl_rule_parse_compat_cb, tb) < 0)
		return -1;

	if (tb[NFTA_RULE_COMPAT_PROTO]) {
		r->compat.proto =
			ntohl(mnl_attr_get_u32(tb[NFTA_RULE_COMPAT_PROTO]));
		r->flags |= (1 << NFTNL_RULE_COMPAT_PROTO);
	}
	if (tb[NFTA_RULE_COMPAT_FLAGS]) {
		r->compat.flags =
			ntohl(mnl_attr_get_u32(tb[NFTA_RULE_COMPAT_FLAGS]));
		r->flags |= (1 << NFTNL_RULE_COMPAT_FLAGS);
	}
	return 0;
}

EXPORT_SYMBOL(nftnl_rule_nlmsg_parse);
int nftnl_rule_nlmsg_parse(const struct nlmsghdr *nlh, struct nftnl_rule *r)
{
	struct nlattr *tb[NFTA_RULE_MAX+1] = {};
	struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);
	int ret;

	if (mnl_attr_parse(nlh, sizeof(*nfg), nftnl_rule_parse_attr_cb, tb) < 0)
		return -1;

	if (tb[NFTA_RULE_TABLE]) {
		if (r->flags & (1 << NFTNL_RULE_TABLE))
			xfree(r->table);
		r->table = strdup(mnl_attr_get_str(tb[NFTA_RULE_TABLE]));
		if (!r->table)
			return -1;
		r->flags |= (1 << NFTNL_RULE_TABLE);
	}
	if (tb[NFTA_RULE_CHAIN]) {
		if (r->flags & (1 << NFTNL_RULE_CHAIN))
			xfree(r->chain);
		r->chain = strdup(mnl_attr_get_str(tb[NFTA_RULE_CHAIN]));
		if (!r->chain)
			return -1;
		r->flags |= (1 << NFTNL_RULE_CHAIN);
	}
 	if (tb[NFTA_RULE_CHAIN_ID]) {
                r->chain_id = be32toh(mnl_attr_get_u64(tb[NFTA_RULE_CHAIN_ID]));
                r->flags |= (1 << NFTNL_RULE_CHAIN_ID);
        }
	if (tb[NFTA_RULE_HANDLE]) {
		r->handle = be64toh(mnl_attr_get_u64(tb[NFTA_RULE_HANDLE]));
		r->flags |= (1 << NFTNL_RULE_HANDLE);
	}
	if (tb[NFTA_RULE_EXPRESSIONS]) {
		ret = nftnl_rule_parse_expr(tb[NFTA_RULE_EXPRESSIONS], r);
		if (ret < 0)
			return ret;
	}
	if (tb[NFTA_RULE_COMPAT]) {
		ret = nftnl_rule_parse_compat(tb[NFTA_RULE_COMPAT], r);
		if (ret < 0)
			return ret;
	}
	if (tb[NFTA_RULE_POSITION]) {
		r->position = be64toh(mnl_attr_get_u64(tb[NFTA_RULE_POSITION]));
		r->flags |= (1 << NFTNL_RULE_POSITION);
	}
	if (tb[NFTA_RULE_USERDATA]) {
		const void *udata =
			mnl_attr_get_payload(tb[NFTA_RULE_USERDATA]);

		if (r->flags & (1 << NFTNL_RULE_USERDATA))
			xfree(r->user.data);

		r->user.len = mnl_attr_get_payload_len(tb[NFTA_RULE_USERDATA]);

		r->user.data = malloc(r->user.len);
		if (r->user.data == NULL)
			return -1;

		memcpy(r->user.data, udata, r->user.len);
		r->flags |= (1 << NFTNL_RULE_USERDATA);
	}
	if (tb[NFTA_RULE_ID]) {
		r->id = ntohl(mnl_attr_get_u32(tb[NFTA_RULE_ID]));
		r->flags |= (1 << NFTNL_RULE_ID);
	}
	if (tb[NFTA_RULE_POSITION_ID]) {
		r->position_id = ntohl(mnl_attr_get_u32(tb[NFTA_RULE_POSITION_ID]));
		r->flags |= (1 << NFTNL_RULE_POSITION_ID);
	}

	r->family = nfg->nfgen_family;
	r->flags |= (1 << NFTNL_RULE_FAMILY);

	return 0;
}

static int nftnl_rule_do_parse(struct nftnl_rule *r, enum nftnl_parse_type type,
			     const void *data, struct nftnl_parse_err *err,
			     enum nftnl_parse_input input)
{
	int ret;
	struct nftnl_parse_err perr = {};

	switch (type) {
	case NFTNL_PARSE_JSON:
	case NFTNL_PARSE_XML:
	default:
		ret = -1;
		errno = EOPNOTSUPP;
		break;
	}
	if (err != NULL)
		*err = perr;

	return ret;
}

EXPORT_SYMBOL(nftnl_rule_parse);
int nftnl_rule_parse(struct nftnl_rule *r, enum nftnl_parse_type type,
		   const char *data, struct nftnl_parse_err *err)
{
	return nftnl_rule_do_parse(r, type, data, err, NFTNL_PARSE_BUFFER);
}

EXPORT_SYMBOL(nftnl_rule_parse_file);
int nftnl_rule_parse_file(struct nftnl_rule *r, enum nftnl_parse_type type,
			FILE *fp, struct nftnl_parse_err *err)
{
	return nftnl_rule_do_parse(r, type, fp, err, NFTNL_PARSE_FILE);
}

static int nftnl_rule_snprintf_default(char *buf, size_t remain,
				       const struct nftnl_rule *r,
				       uint32_t type, uint32_t flags)
{
	struct nftnl_expr *expr;
	int ret, offset = 0, i;
	const char *sep = "";

	if (r->flags & (1 << NFTNL_RULE_FAMILY)) {
		ret = snprintf(buf + offset, remain, "%s%s", sep,
			       nftnl_family2str(r->family));
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);
		sep = " ";
	}

	if (r->flags & (1 << NFTNL_RULE_TABLE)) {
		ret = snprintf(buf + offset, remain, "%s%s", sep,
			       r->table);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);
		sep = " ";
	}

	if (r->flags & (1 << NFTNL_RULE_CHAIN)) {
		ret = snprintf(buf + offset, remain, "%s%s", sep,
			       r->chain);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);
		sep = " ";
	}
	if (r->flags & (1 << NFTNL_RULE_HANDLE)) {
		ret = snprintf(buf + offset, remain, "%s%" PRIu64, sep,
			       r->handle);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);
		sep = " ";
	}

	if (r->flags & (1 << NFTNL_RULE_POSITION)) {
		ret = snprintf(buf + offset, remain, "%s%" PRIu64, sep,
			       r->position);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);
		sep = " ";
	}

	if (r->flags & (1 << NFTNL_RULE_ID)) {
		ret = snprintf(buf + offset, remain, "%s%u", sep, r->id);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);
		sep = " ";
	}

	if (r->flags & (1 << NFTNL_RULE_POSITION_ID)) {
		ret = snprintf(buf + offset, remain, "%s%u", sep,
			       r->position_id);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);
		sep = " ";
	}

	ret = snprintf(buf + offset, remain, "\n");
	SNPRINTF_BUFFER_SIZE(ret, remain, offset);

	list_for_each_entry(expr, &r->expr_list, head) {
		ret = snprintf(buf + offset, remain, "  [ %s ", expr->ops->name);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);

		ret = nftnl_expr_snprintf(buf + offset, remain, expr,
					     type, flags);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);

		ret = snprintf(buf + offset, remain, "]\n");
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);
	}

	if (r->user.len) {
		ret = snprintf(buf + offset, remain, "  userdata = { ");
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);

		for (i = 0; i < r->user.len; i++) {
			char *c = r->user.data;

			ret = snprintf(buf + offset, remain,
				       isprint(c[i]) ? "%c" : "\\x%02hhx",
				       c[i]);
			SNPRINTF_BUFFER_SIZE(ret, remain, offset);
		}

		ret = snprintf(buf + offset, remain, " }");
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);

	}

	return offset;
}

static int nftnl_rule_cmd_snprintf(char *buf, size_t remain,
				   const struct nftnl_rule *r, uint32_t cmd,
				   uint32_t type, uint32_t flags)
{
	uint32_t inner_flags = flags;
	int ret, offset = 0;

	inner_flags &= ~NFTNL_OF_EVENT_ANY;

	if (type != NFTNL_OUTPUT_DEFAULT)
		return -1;

	ret = nftnl_rule_snprintf_default(buf + offset, remain, r, type,
					inner_flags);
	SNPRINTF_BUFFER_SIZE(ret, remain, offset);
	return offset;
}

EXPORT_SYMBOL(nftnl_rule_snprintf);
int nftnl_rule_snprintf(char *buf, size_t size, const struct nftnl_rule *r,
			uint32_t type, uint32_t flags)
{
	if (size)
		buf[0] = '\0';

	return nftnl_rule_cmd_snprintf(buf, size, r, nftnl_flag2cmd(flags), type,
				     flags);
}

static int nftnl_rule_do_snprintf(char *buf, size_t size, const void *r,
				  uint32_t cmd, uint32_t type, uint32_t flags)
{
	return nftnl_rule_snprintf(buf, size, r, type, flags);
}

EXPORT_SYMBOL(nftnl_rule_fprintf);
int nftnl_rule_fprintf(FILE *fp, const struct nftnl_rule *r, uint32_t type,
		       uint32_t flags)
{
	return nftnl_fprintf(fp, r, NFTNL_CMD_UNSPEC, type, flags,
			   nftnl_rule_do_snprintf);
}

EXPORT_SYMBOL(nftnl_expr_foreach);
int nftnl_expr_foreach(struct nftnl_rule *r,
                          int (*cb)(struct nftnl_expr *e, void *data),
                          void *data)
{
       struct nftnl_expr *cur, *tmp;
       int ret;

       list_for_each_entry_safe(cur, tmp, &r->expr_list, head) {
               ret = cb(cur, data);
               if (ret < 0)
                       return ret;
       }
       return 0;
}

struct nftnl_expr_iter {
	const struct nftnl_rule	*r;
	struct nftnl_expr	*cur;
};

static void nftnl_expr_iter_init(const struct nftnl_rule *r,
				 struct nftnl_expr_iter *iter)
{
	iter->r = r;
	if (list_empty(&r->expr_list))
		iter->cur = NULL;
	else
		iter->cur = list_entry(r->expr_list.next, struct nftnl_expr,
				       head);
}

EXPORT_SYMBOL(nftnl_expr_iter_create);
struct nftnl_expr_iter *nftnl_expr_iter_create(const struct nftnl_rule *r)
{
	struct nftnl_expr_iter *iter;

	iter = calloc(1, sizeof(struct nftnl_expr_iter));
	if (iter == NULL)
		return NULL;

	nftnl_expr_iter_init(r, iter);

	return iter;
}

EXPORT_SYMBOL(nftnl_expr_iter_next);
struct nftnl_expr *nftnl_expr_iter_next(struct nftnl_expr_iter *iter)
{
	struct nftnl_expr *expr = iter->cur;

	if (expr == NULL)
		return NULL;

	/* get next expression, if any */
	iter->cur = list_entry(iter->cur->head.next, struct nftnl_expr, head);
	if (&iter->cur->head == iter->r->expr_list.next)
		return NULL;

	return expr;
}

EXPORT_SYMBOL(nftnl_expr_iter_destroy);
void nftnl_expr_iter_destroy(struct nftnl_expr_iter *iter)
{
	xfree(iter);
}

struct nftnl_rule_list {
	struct list_head list;
};

EXPORT_SYMBOL(nftnl_rule_list_alloc);
struct nftnl_rule_list *nftnl_rule_list_alloc(void)
{
	struct nftnl_rule_list *list;

	list = calloc(1, sizeof(struct nftnl_rule_list));
	if (list == NULL)
		return NULL;

	INIT_LIST_HEAD(&list->list);

	return list;
}

EXPORT_SYMBOL(nftnl_rule_list_free);
void nftnl_rule_list_free(struct nftnl_rule_list *list)
{
	struct nftnl_rule *r, *tmp;

	list_for_each_entry_safe(r, tmp, &list->list, head) {
		list_del(&r->head);
		nftnl_rule_free(r);
	}
	xfree(list);
}

EXPORT_SYMBOL(nftnl_rule_list_is_empty);
int nftnl_rule_list_is_empty(const struct nftnl_rule_list *list)
{
	return list_empty(&list->list);
}

EXPORT_SYMBOL(nftnl_rule_list_add);
void nftnl_rule_list_add(struct nftnl_rule *r, struct nftnl_rule_list *list)
{
	list_add(&r->head, &list->list);
}

EXPORT_SYMBOL(nftnl_rule_list_insert_at);
void nftnl_rule_list_insert_at(struct nftnl_rule *r, struct nftnl_rule *pos)
{
	list_add(&r->head, &pos->head);
}

EXPORT_SYMBOL(nftnl_rule_list_add_tail);
void nftnl_rule_list_add_tail(struct nftnl_rule *r, struct nftnl_rule_list *list)
{
	list_add_tail(&r->head, &list->list);
}

EXPORT_SYMBOL(nftnl_rule_list_del);
void nftnl_rule_list_del(struct nftnl_rule *r)
{
	list_del(&r->head);
}

EXPORT_SYMBOL(nftnl_rule_list_foreach);
int nftnl_rule_list_foreach(struct nftnl_rule_list *rule_list,
			  int (*cb)(struct nftnl_rule *r, void *data),
			  void *data)
{
	struct nftnl_rule *cur, *tmp;
	int ret;

	list_for_each_entry_safe(cur, tmp, &rule_list->list, head) {
		ret = cb(cur, data);
		if (ret < 0)
			return ret;
	}
	return 0;
}

struct nftnl_rule_list_iter {
	const struct nftnl_rule_list	*list;
	struct nftnl_rule		*cur;
};

EXPORT_SYMBOL(nftnl_rule_list_iter_create);
struct nftnl_rule_list_iter *
nftnl_rule_list_iter_create(const struct nftnl_rule_list *l)
{
	struct nftnl_rule_list_iter *iter;

	iter = calloc(1, sizeof(struct nftnl_rule_list_iter));
	if (iter == NULL)
		return NULL;

	iter->list = l;
	if (nftnl_rule_list_is_empty(l))
		iter->cur = NULL;
	else
		iter->cur = list_entry(l->list.next, struct nftnl_rule, head);

	return iter;
}

EXPORT_SYMBOL(nftnl_rule_list_iter_cur);
struct nftnl_rule *nftnl_rule_list_iter_cur(struct nftnl_rule_list_iter *iter)
{
	return iter->cur;
}

EXPORT_SYMBOL(nftnl_rule_list_iter_next);
struct nftnl_rule *nftnl_rule_list_iter_next(struct nftnl_rule_list_iter *iter)
{
	struct nftnl_rule *r = iter->cur;

	if (r == NULL)
		return NULL;

	/* get next rule, if any */
	iter->cur = list_entry(iter->cur->head.next, struct nftnl_rule, head);
	if (&iter->cur->head == iter->list->list.next)
		return NULL;

	return r;
}

EXPORT_SYMBOL(nftnl_rule_list_iter_destroy);
void nftnl_rule_list_iter_destroy(const struct nftnl_rule_list_iter *iter)
{
	xfree(iter);
}
