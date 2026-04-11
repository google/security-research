#ifndef _LIBNFTNL_SET_H_
#define _LIBNFTNL_SET_H_

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#include <libnftnl/common.h>

#ifdef __cplusplus
extern "C" {
#endif

enum nftnl_set_attr {
	NFTNL_SET_TABLE,
	NFTNL_SET_NAME,
	NFTNL_SET_FLAGS,
	NFTNL_SET_KEY_TYPE,
	NFTNL_SET_KEY_LEN,
	NFTNL_SET_DATA_TYPE,
	NFTNL_SET_DATA_LEN,
	NFTNL_SET_FAMILY,
	NFTNL_SET_ID,
	NFTNL_SET_POLICY,
	NFTNL_SET_DESC_SIZE,
	NFTNL_SET_TIMEOUT,
	NFTNL_SET_GC_INTERVAL,
	NFTNL_SET_USERDATA,
	NFTNL_SET_OBJ_TYPE,
	NFTNL_SET_HANDLE,
	NFTNL_SET_DESC_CONCAT,
	NFTNL_SET_EXPR,
	NFTNL_SET_EXPRESSIONS,
	__NFTNL_SET_MAX
};
#define NFTNL_SET_MAX (__NFTNL_SET_MAX - 1)

struct nftnl_set;

struct nftnl_set *nftnl_set_alloc(void);
void nftnl_set_free(const struct nftnl_set *s);

struct nftnl_set *nftnl_set_clone(const struct nftnl_set *set);

bool nftnl_set_is_set(const struct nftnl_set *s, uint16_t attr);
void nftnl_set_unset(struct nftnl_set *s, uint16_t attr);
int nftnl_set_set(struct nftnl_set *s, uint16_t attr, const void *data) __attribute__((deprecated));
int nftnl_set_set_data(struct nftnl_set *s, uint16_t attr, const void *data,
		       uint32_t data_len);
void nftnl_set_set_u32(struct nftnl_set *s, uint16_t attr, uint32_t val);
void nftnl_set_set_u64(struct nftnl_set *s, uint16_t attr, uint64_t val);
int nftnl_set_set_str(struct nftnl_set *s, uint16_t attr, const char *str);

const void *nftnl_set_get(const struct nftnl_set *s, uint16_t attr);
const void *nftnl_set_get_data(const struct nftnl_set *s, uint16_t attr,
			       uint32_t *data_len);
const char *nftnl_set_get_str(const struct nftnl_set *s, uint16_t attr);
uint32_t nftnl_set_get_u32(const struct nftnl_set *s, uint16_t attr);
uint64_t nftnl_set_get_u64(const struct nftnl_set *s, uint16_t attr);

struct nlmsghdr;

#define nftnl_set_nlmsg_build_hdr	nftnl_nlmsg_build_hdr
void nftnl_set_nlmsg_build_payload(struct nlmsghdr *nlh, struct nftnl_set *s);
int nftnl_set_nlmsg_parse(const struct nlmsghdr *nlh, struct nftnl_set *s);
int nftnl_set_elems_nlmsg_parse(const struct nlmsghdr *nlh, struct nftnl_set *s);

int nftnl_set_snprintf(char *buf, size_t size, const struct nftnl_set *s, uint32_t type, uint32_t flags);
int nftnl_set_fprintf(FILE *fp, const struct nftnl_set *s, uint32_t type, uint32_t flags);

struct nftnl_set_list;

struct nftnl_set_list *nftnl_set_list_alloc(void);
void nftnl_set_list_free(struct nftnl_set_list *list);
int nftnl_set_list_is_empty(const struct nftnl_set_list *list);
void nftnl_set_list_add(struct nftnl_set *s, struct nftnl_set_list *list);
void nftnl_set_list_add_tail(struct nftnl_set *s, struct nftnl_set_list *list);
void nftnl_set_list_del(struct nftnl_set *s);
int nftnl_set_list_foreach(struct nftnl_set_list *set_list, int (*cb)(struct nftnl_set *t, void *data), void *data);
struct nftnl_set *nftnl_set_list_lookup_byname(struct nftnl_set_list *set_list,
					       const char *set);

struct nftnl_expr;
void nftnl_set_add_expr(struct nftnl_set *s, struct nftnl_expr *expr);
int nftnl_set_expr_foreach(const struct nftnl_set *s,
			   int (*cb)(struct nftnl_expr *e, void *data),
			   void *data);

struct nftnl_set_list_iter;
struct nftnl_set_list_iter *nftnl_set_list_iter_create(const struct nftnl_set_list *l);
struct nftnl_set *nftnl_set_list_iter_cur(const struct nftnl_set_list_iter *iter);
struct nftnl_set *nftnl_set_list_iter_next(struct nftnl_set_list_iter *iter);
void nftnl_set_list_iter_destroy(const struct nftnl_set_list_iter *iter);

int nftnl_set_parse(struct nftnl_set *s, enum nftnl_parse_type type,
		  const char *data, struct nftnl_parse_err *err);
int nftnl_set_parse_file(struct nftnl_set *s, enum nftnl_parse_type type,
		       FILE *fp, struct nftnl_parse_err *err);

/*
 * Set elements
 */

enum {
	NFTNL_SET_ELEM_FLAGS,
	NFTNL_SET_ELEM_KEY,
	NFTNL_SET_ELEM_VERDICT,
	NFTNL_SET_ELEM_CHAIN,
	NFTNL_SET_ELEM_DATA,
	NFTNL_SET_ELEM_TIMEOUT,
	NFTNL_SET_ELEM_EXPIRATION,
	NFTNL_SET_ELEM_USERDATA,
	NFTNL_SET_ELEM_EXPR,
	NFTNL_SET_ELEM_OBJREF,
	NFTNL_SET_ELEM_KEY_END,
	NFTNL_SET_ELEM_EXPRESSIONS,
	__NFTNL_SET_ELEM_MAX
};
#define NFTNL_SET_ELEM_MAX (__NFTNL_SET_ELEM_MAX - 1)

struct nftnl_set_elem;

struct nftnl_set_elem *nftnl_set_elem_alloc(void);
void nftnl_set_elem_free(struct nftnl_set_elem *s);

struct nftnl_set_elem *nftnl_set_elem_clone(struct nftnl_set_elem *elem);

void nftnl_set_elem_add(struct nftnl_set *s, struct nftnl_set_elem *elem);

void nftnl_set_elem_unset(struct nftnl_set_elem *s, uint16_t attr);
int nftnl_set_elem_set(struct nftnl_set_elem *s, uint16_t attr, const void *data, uint32_t data_len);
void nftnl_set_elem_set_u32(struct nftnl_set_elem *s, uint16_t attr, uint32_t val);
void nftnl_set_elem_set_u64(struct nftnl_set_elem *s, uint16_t attr, uint64_t val);
int nftnl_set_elem_set_str(struct nftnl_set_elem *s, uint16_t attr, const char *str);

const void *nftnl_set_elem_get(struct nftnl_set_elem *s, uint16_t attr, uint32_t *data_len);
const char *nftnl_set_elem_get_str(struct nftnl_set_elem *s, uint16_t attr);
uint32_t nftnl_set_elem_get_u32(struct nftnl_set_elem *s, uint16_t attr);
uint64_t nftnl_set_elem_get_u64(struct nftnl_set_elem *s, uint16_t attr);

bool nftnl_set_elem_is_set(const struct nftnl_set_elem *s, uint16_t attr);

#define nftnl_set_elem_nlmsg_build_hdr	nftnl_nlmsg_build_hdr
void nftnl_set_elems_nlmsg_build_payload(struct nlmsghdr *nlh, struct nftnl_set *s);
void nftnl_set_elem_nlmsg_build_payload(struct nlmsghdr *nlh, struct nftnl_set_elem *e);
struct nlattr *nftnl_set_elem_nlmsg_build(struct nlmsghdr *nlh,
					  struct nftnl_set_elem *elem, int i);

int nftnl_set_elem_parse(struct nftnl_set_elem *e, enum nftnl_parse_type type,
		       const char *data, struct nftnl_parse_err *err);
int nftnl_set_elem_parse_file(struct nftnl_set_elem *e, enum nftnl_parse_type type,
			    FILE *fp, struct nftnl_parse_err *err);
int nftnl_set_elem_snprintf(char *buf, size_t size, const struct nftnl_set_elem *s, uint32_t type, uint32_t flags);
int nftnl_set_elem_fprintf(FILE *fp, const struct nftnl_set_elem *se, uint32_t type, uint32_t flags);

struct nftnl_expr;
void nftnl_set_elem_add_expr(struct nftnl_set_elem *e, struct nftnl_expr *expr);
int nftnl_set_elem_expr_foreach(struct nftnl_set_elem *e,
				int (*cb)(struct nftnl_expr *e, void *data),
				void *data);

int nftnl_set_elem_foreach(struct nftnl_set *s, int (*cb)(struct nftnl_set_elem *e, void *data), void *data);

struct nftnl_set_elems_iter;
struct nftnl_set_elems_iter *nftnl_set_elems_iter_create(const struct nftnl_set *s);
struct nftnl_set_elem *nftnl_set_elems_iter_cur(const struct nftnl_set_elems_iter *iter);
struct nftnl_set_elem *nftnl_set_elems_iter_next(struct nftnl_set_elems_iter *iter);
void nftnl_set_elems_iter_destroy(struct nftnl_set_elems_iter *iter);

int nftnl_set_elems_nlmsg_build_payload_iter(struct nlmsghdr *nlh,
					   struct nftnl_set_elems_iter *iter);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _LIBNFTNL_SET_H_ */
