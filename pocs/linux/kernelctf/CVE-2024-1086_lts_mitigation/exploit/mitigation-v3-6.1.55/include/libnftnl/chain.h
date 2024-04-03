#ifndef _LIBNFTNL_CHAIN_H_
#define _LIBNFTNL_CHAIN_H_

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#include <libnftnl/common.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nftnl_chain;
struct nftnl_rule;

struct nftnl_chain *nftnl_chain_alloc(void);
void nftnl_chain_free(const struct nftnl_chain *);

enum nftnl_chain_attr {
	NFTNL_CHAIN_NAME	= 0,
	NFTNL_CHAIN_FAMILY,
	NFTNL_CHAIN_TABLE,
	NFTNL_CHAIN_HOOKNUM,
	NFTNL_CHAIN_PRIO	= 4,
	NFTNL_CHAIN_POLICY,
	NFTNL_CHAIN_USE,
	NFTNL_CHAIN_BYTES,
	NFTNL_CHAIN_PACKETS	= 8,
	NFTNL_CHAIN_HANDLE,
	NFTNL_CHAIN_TYPE,
	NFTNL_CHAIN_DEV,
	NFTNL_CHAIN_DEVICES,
	NFTNL_CHAIN_FLAGS,
	NFTNL_CHAIN_ID,
	NFTNL_CHAIN_USERDATA,
	__NFTNL_CHAIN_MAX
};
#define NFTNL_CHAIN_MAX (__NFTNL_CHAIN_MAX - 1)

bool nftnl_chain_is_set(const struct nftnl_chain *c, uint16_t attr);
void nftnl_chain_unset(struct nftnl_chain *c, uint16_t attr);
void nftnl_chain_set(struct nftnl_chain *t, uint16_t attr, const void *data) __attribute__((deprecated));
int nftnl_chain_set_data(struct nftnl_chain *t, uint16_t attr,
			     const void *data, uint32_t data_len);
void nftnl_chain_set_u8(struct nftnl_chain *t, uint16_t attr, uint8_t data);
void nftnl_chain_set_u32(struct nftnl_chain *t, uint16_t attr, uint32_t data);
void nftnl_chain_set_s32(struct nftnl_chain *t, uint16_t attr, int32_t data);
void nftnl_chain_set_u64(struct nftnl_chain *t, uint16_t attr, uint64_t data);
int nftnl_chain_set_str(struct nftnl_chain *t, uint16_t attr, const char *str);
int nftnl_chain_set_array(struct nftnl_chain *t, uint16_t attr, const char **data);

const void *nftnl_chain_get(const struct nftnl_chain *c, uint16_t attr);
const void *nftnl_chain_get_data(const struct nftnl_chain *c, uint16_t attr,
				 uint32_t *data_len);
const char *nftnl_chain_get_str(const struct nftnl_chain *c, uint16_t attr);
uint8_t nftnl_chain_get_u8(const struct nftnl_chain *c, uint16_t attr);
uint32_t nftnl_chain_get_u32(const struct nftnl_chain *c, uint16_t attr);
int32_t nftnl_chain_get_s32(const struct nftnl_chain *c, uint16_t attr);
uint64_t nftnl_chain_get_u64(const struct nftnl_chain *c, uint16_t attr);
const char *const *nftnl_chain_get_array(const struct nftnl_chain *c, uint16_t attr);

void nftnl_chain_rule_add(struct nftnl_rule *rule, struct nftnl_chain *c);
void nftnl_chain_rule_del(struct nftnl_rule *rule);
void nftnl_chain_rule_add_tail(struct nftnl_rule *rule, struct nftnl_chain *c);
void nftnl_chain_rule_insert_at(struct nftnl_rule *rule, struct nftnl_rule *pos);
void nftnl_chain_rule_append_at(struct nftnl_rule *rule, struct nftnl_rule *pos);

struct nlmsghdr;

void nftnl_chain_nlmsg_build_payload(struct nlmsghdr *nlh, const struct nftnl_chain *t);

int nftnl_chain_parse(struct nftnl_chain *c, enum nftnl_parse_type type,
		    const char *data, struct nftnl_parse_err *err);
int nftnl_chain_parse_file(struct nftnl_chain *c, enum nftnl_parse_type type,
			 FILE *fp, struct nftnl_parse_err *err);
int nftnl_chain_snprintf(char *buf, size_t size, const struct nftnl_chain *t, uint32_t type, uint32_t flags);
int nftnl_chain_fprintf(FILE *fp, const struct nftnl_chain *c, uint32_t type, uint32_t flags);

#define nftnl_chain_nlmsg_build_hdr	nftnl_nlmsg_build_hdr
int nftnl_chain_nlmsg_parse(const struct nlmsghdr *nlh, struct nftnl_chain *t);

int nftnl_rule_foreach(struct nftnl_chain *c,
			  int (*cb)(struct nftnl_rule *r, void *data),
			  void *data);
struct nftnl_rule *nftnl_rule_lookup_byindex(struct nftnl_chain *c, uint32_t index);

struct nftnl_rule_iter;

struct nftnl_rule_iter *nftnl_rule_iter_create(const struct nftnl_chain *c);
struct nftnl_rule *nftnl_rule_iter_next(struct nftnl_rule_iter *iter);
void nftnl_rule_iter_destroy(struct nftnl_rule_iter *iter);

struct nftnl_chain_list;

struct nftnl_chain_list *nftnl_chain_list_alloc(void);
void nftnl_chain_list_free(struct nftnl_chain_list *list);
int nftnl_chain_list_is_empty(const struct nftnl_chain_list *list);
int nftnl_chain_list_foreach(struct nftnl_chain_list *chain_list, int (*cb)(struct nftnl_chain *t, void *data), void *data);
struct nftnl_chain *nftnl_chain_list_lookup_byname(struct nftnl_chain_list *chain_list, const char *chain);

void nftnl_chain_list_add(struct nftnl_chain *r, struct nftnl_chain_list *list);
void nftnl_chain_list_add_tail(struct nftnl_chain *r, struct nftnl_chain_list *list);
void nftnl_chain_list_del(struct nftnl_chain *c);

struct nftnl_chain_list_iter;

struct nftnl_chain_list_iter *nftnl_chain_list_iter_create(const struct nftnl_chain_list *l);
struct nftnl_chain *nftnl_chain_list_iter_next(struct nftnl_chain_list_iter *iter);
void nftnl_chain_list_iter_destroy(struct nftnl_chain_list_iter *iter);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _LIBNFTNL_CHAIN_H_ */
