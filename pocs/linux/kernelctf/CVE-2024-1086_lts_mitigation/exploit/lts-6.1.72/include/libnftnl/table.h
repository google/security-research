#ifndef _LIBNFTNL_TABLE_H_
#define _LIBNFTNL_TABLE_H_

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#include <libnftnl/common.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nftnl_table;

struct nftnl_table *nftnl_table_alloc(void);
void nftnl_table_free(const struct nftnl_table *);

enum nftnl_table_attr {
	NFTNL_TABLE_NAME	= 0,
	NFTNL_TABLE_FAMILY,
	NFTNL_TABLE_FLAGS,
	NFTNL_TABLE_USE,
	NFTNL_TABLE_HANDLE,
	NFTNL_TABLE_USERDATA,
	NFTNL_TABLE_OWNER,
	__NFTNL_TABLE_MAX
};
#define NFTNL_TABLE_MAX (__NFTNL_TABLE_MAX - 1)

bool nftnl_table_is_set(const struct nftnl_table *t, uint16_t attr);
void nftnl_table_unset(struct nftnl_table *t, uint16_t attr);
void nftnl_table_set(struct nftnl_table *t, uint16_t attr, const void *data) __attribute__((deprecated));
int nftnl_table_set_data(struct nftnl_table *t, uint16_t attr,
			 const void *data, uint32_t data_len);
const void *nftnl_table_get(const struct nftnl_table *t, uint16_t attr);
const void *nftnl_table_get_data(const struct nftnl_table *t, uint16_t attr,
				 uint32_t *data_len);

void nftnl_table_set_u8(struct nftnl_table *t, uint16_t attr, uint8_t data);
void nftnl_table_set_u32(struct nftnl_table *t, uint16_t attr, uint32_t data);
void nftnl_table_set_u64(struct nftnl_table *t, uint16_t attr, uint64_t data);
int nftnl_table_set_str(struct nftnl_table *t, uint16_t attr, const char *str);
uint8_t nftnl_table_get_u8(const struct nftnl_table *t, uint16_t attr);
uint32_t nftnl_table_get_u32(const struct nftnl_table *t, uint16_t attr);
uint64_t nftnl_table_get_u64(const struct nftnl_table *t, uint16_t attr);
const char *nftnl_table_get_str(const struct nftnl_table *t, uint16_t attr);

struct nlmsghdr;

void nftnl_table_nlmsg_build_payload(struct nlmsghdr *nlh, const struct nftnl_table *t);

int nftnl_table_parse(struct nftnl_table *t, enum nftnl_parse_type type,
		    const char *data, struct nftnl_parse_err *err);
int nftnl_table_parse_file(struct nftnl_table *t, enum nftnl_parse_type type,
			 FILE *fp, struct nftnl_parse_err *err);
int nftnl_table_snprintf(char *buf, size_t size, const struct nftnl_table *t, uint32_t type, uint32_t flags);
int nftnl_table_fprintf(FILE *fp, const struct nftnl_table *t, uint32_t type, uint32_t flags);

#define nftnl_table_nlmsg_build_hdr	nftnl_nlmsg_build_hdr
int nftnl_table_nlmsg_parse(const struct nlmsghdr *nlh, struct nftnl_table *t);

struct nftnl_table_list;

struct nftnl_table_list *nftnl_table_list_alloc(void);
void nftnl_table_list_free(struct nftnl_table_list *list);
int nftnl_table_list_is_empty(const struct nftnl_table_list *list);
int nftnl_table_list_foreach(struct nftnl_table_list *table_list, int (*cb)(struct nftnl_table *t, void *data), void *data);

void nftnl_table_list_add(struct nftnl_table *r, struct nftnl_table_list *list);
void nftnl_table_list_add_tail(struct nftnl_table *r, struct nftnl_table_list *list);
void nftnl_table_list_del(struct nftnl_table *r);

struct nftnl_table_list_iter;

struct nftnl_table_list_iter *nftnl_table_list_iter_create(const struct nftnl_table_list *l);
struct nftnl_table *nftnl_table_list_iter_next(struct nftnl_table_list_iter *iter);
void nftnl_table_list_iter_destroy(const struct nftnl_table_list_iter *iter);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _LIBNFTNL_TABLE_H_ */
