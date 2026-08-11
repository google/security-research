#ifndef _LIBNFTNL_FLOWTABLE_H_
#define _LIBNFTNL_FLOWTABLE_H_

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#include <libnftnl/common.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nftnl_flowtable;

struct nftnl_flowtable *nftnl_flowtable_alloc(void);
void nftnl_flowtable_free(const struct nftnl_flowtable *);

enum nftnl_flowtable_attr {
	NFTNL_FLOWTABLE_NAME	= 0,
	NFTNL_FLOWTABLE_FAMILY,
	NFTNL_FLOWTABLE_TABLE,
	NFTNL_FLOWTABLE_HOOKNUM,
	NFTNL_FLOWTABLE_PRIO	= 4,
	NFTNL_FLOWTABLE_USE,
	NFTNL_FLOWTABLE_DEVICES,
	NFTNL_FLOWTABLE_SIZE,
	NFTNL_FLOWTABLE_FLAGS,
	NFTNL_FLOWTABLE_HANDLE,
	__NFTNL_FLOWTABLE_MAX
};
#define NFTNL_FLOWTABLE_MAX (__NFTNL_FLOWTABLE_MAX - 1)

bool nftnl_flowtable_is_set(const struct nftnl_flowtable *c, uint16_t attr);
void nftnl_flowtable_unset(struct nftnl_flowtable *c, uint16_t attr);
void nftnl_flowtable_set(struct nftnl_flowtable *t, uint16_t attr, const void *data) __attribute__((deprecated));
int nftnl_flowtable_set_data(struct nftnl_flowtable *t, uint16_t attr,
			     const void *data, uint32_t data_len);
void nftnl_flowtable_set_u32(struct nftnl_flowtable *t, uint16_t attr, uint32_t data);
void nftnl_flowtable_set_s32(struct nftnl_flowtable *t, uint16_t attr, int32_t data);
void nftnl_flowtable_set_u64(struct nftnl_flowtable *t, uint16_t attr, uint64_t data);
int nftnl_flowtable_set_str(struct nftnl_flowtable *t, uint16_t attr, const char *str);
int nftnl_flowtable_set_array(struct nftnl_flowtable *t, uint16_t attr, const char **data);

const void *nftnl_flowtable_get(const struct nftnl_flowtable *c, uint16_t attr);
const void *nftnl_flowtable_get_data(const struct nftnl_flowtable *c, uint16_t attr,
				 uint32_t *data_len);
const char *nftnl_flowtable_get_str(const struct nftnl_flowtable *c, uint16_t attr);
uint32_t nftnl_flowtable_get_u32(const struct nftnl_flowtable *c, uint16_t attr);
int32_t nftnl_flowtable_get_s32(const struct nftnl_flowtable *c, uint16_t attr);
uint64_t nftnl_flowtable_get_u64(const struct nftnl_flowtable *c, uint16_t attr);
const char *const *nftnl_flowtable_get_array(const struct nftnl_flowtable *t, uint16_t attr);

struct nlmsghdr;

void nftnl_flowtable_nlmsg_build_payload(struct nlmsghdr *nlh, const struct nftnl_flowtable *t);

int nftnl_flowtable_parse(struct nftnl_flowtable *c, enum nftnl_parse_type type,
		    const char *data, struct nftnl_parse_err *err);
int nftnl_flowtable_parse_file(struct nftnl_flowtable *c, enum nftnl_parse_type type,
			 FILE *fp, struct nftnl_parse_err *err);
int nftnl_flowtable_snprintf(char *buf, size_t size, const struct nftnl_flowtable *t, uint32_t type, uint32_t flags);
int nftnl_flowtable_fprintf(FILE *fp, const struct nftnl_flowtable *c, uint32_t type, uint32_t flags);

#define nftnl_flowtable_nlmsg_build_hdr	nftnl_nlmsg_build_hdr
int nftnl_flowtable_nlmsg_parse(const struct nlmsghdr *nlh, struct nftnl_flowtable *t);

struct nftnl_flowtable_list;

struct nftnl_flowtable_list *nftnl_flowtable_list_alloc(void);
void nftnl_flowtable_list_free(struct nftnl_flowtable_list *list);
int nftnl_flowtable_list_is_empty(const struct nftnl_flowtable_list *list);
void nftnl_flowtable_list_add(struct nftnl_flowtable *s,
			      struct nftnl_flowtable_list *list);
void nftnl_flowtable_list_add_tail(struct nftnl_flowtable *s,
				   struct nftnl_flowtable_list *list);
void nftnl_flowtable_list_del(struct nftnl_flowtable *s);
int nftnl_flowtable_list_foreach(struct nftnl_flowtable_list *flowtable_list,
				 int (*cb)(struct nftnl_flowtable *t, void *data), void *data);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _LIBNFTNL_FLOWTABLE_H_ */
