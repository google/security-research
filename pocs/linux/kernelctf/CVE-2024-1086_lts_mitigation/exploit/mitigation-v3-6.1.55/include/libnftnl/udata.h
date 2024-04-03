#ifndef _LIBNFTNL_UDATA_H_
#define _LIBNFTNL_UDATA_H_

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

enum nftnl_udata_table_types {
	NFTNL_UDATA_TABLE_COMMENT,
	__NFTNL_UDATA_TABLE_MAX
};
#define NFTNL_UDATA_TABLE_MAX (__NFTNL_UDATA_TABLE_MAX - 1)

enum nftnl_udata_chain_types {
	NFTNL_UDATA_CHAIN_COMMENT,
	__NFTNL_UDATA_CHAIN_MAX
};
#define NFTNL_UDATA_CHAIN_MAX (__NFTNL_UDATA_CHAIN_MAX - 1)

enum nftnl_udata_rule_types {
	NFTNL_UDATA_RULE_COMMENT,
	NFTNL_UDATA_RULE_EBTABLES_POLICY,
	__NFTNL_UDATA_RULE_MAX
};
#define NFTNL_UDATA_RULE_MAX (__NFTNL_UDATA_RULE_MAX - 1)

enum nftnl_udata_obj_types {
	NFTNL_UDATA_OBJ_COMMENT,
	__NFTNL_UDATA_OBJ_MAX
};
#define NFTNL_UDATA_OBJ_MAX (__NFTNL_UDATA_OBJ_MAX - 1)

#define NFTNL_UDATA_COMMENT_MAXLEN	128

enum nftnl_udata_set_types {
	NFTNL_UDATA_SET_KEYBYTEORDER,
	NFTNL_UDATA_SET_DATABYTEORDER,
	NFTNL_UDATA_SET_MERGE_ELEMENTS,
	NFTNL_UDATA_SET_KEY_TYPEOF,
	NFTNL_UDATA_SET_DATA_TYPEOF,
	NFTNL_UDATA_SET_EXPR,
	NFTNL_UDATA_SET_DATA_INTERVAL,
	NFTNL_UDATA_SET_COMMENT,
	__NFTNL_UDATA_SET_MAX
};
#define NFTNL_UDATA_SET_MAX (__NFTNL_UDATA_SET_MAX - 1)

enum {
	NFTNL_UDATA_SET_TYPEOF_EXPR,
	NFTNL_UDATA_SET_TYPEOF_DATA,
	__NFTNL_UDATA_SET_TYPEOF_MAX,
};
#define NFTNL_UDATA_SET_TYPEOF_MAX (__NFTNL_UDATA_SET_TYPEOF_MAX - 1)

enum nftnl_udata_set_elem_types {
	NFTNL_UDATA_SET_ELEM_COMMENT,
	NFTNL_UDATA_SET_ELEM_FLAGS,
	__NFTNL_UDATA_SET_ELEM_MAX
};
#define NFTNL_UDATA_SET_ELEM_MAX (__NFTNL_UDATA_SET_ELEM_MAX - 1)

/**
 * enum nftnl_udata_set_elem_flags - meaning of bits in UDATA_SET_ELEM_FLAGS
 *
 * @SET_ELEM_F_INTERVAL_OPEN:   set element denotes a half-open range
 */
enum nftnl_udata_set_elem_flags {
	NFTNL_SET_ELEM_F_INTERVAL_OPEN	= 0x1,
};

/*
 * nftnl user data attributes API
 */
struct nftnl_udata;
struct nftnl_udata_buf;

/* nftnl_udata_buf */
struct nftnl_udata_buf *nftnl_udata_buf_alloc(uint32_t data_size);
void nftnl_udata_buf_free(const struct nftnl_udata_buf *buf);
uint32_t nftnl_udata_buf_len(const struct nftnl_udata_buf *buf);
void *nftnl_udata_buf_data(const struct nftnl_udata_buf *buf);
void nftnl_udata_buf_put(struct nftnl_udata_buf *buf, const void *data,
			 uint32_t len);
struct nftnl_udata *nftnl_udata_start(const struct nftnl_udata_buf *buf);
struct nftnl_udata *nftnl_udata_end(const struct nftnl_udata_buf *buf);

/* putters */
bool nftnl_udata_put(struct nftnl_udata_buf *buf, uint8_t type, uint32_t len,
		     const void *value);
bool nftnl_udata_put_u32(struct nftnl_udata_buf *buf, uint8_t type,
			 uint32_t data);
bool nftnl_udata_put_strz(struct nftnl_udata_buf *buf, uint8_t type,
			  const char *strz);

/* nest */
struct nftnl_udata *nftnl_udata_nest_start(struct nftnl_udata_buf *buf,
					   uint8_t type);
void nftnl_udata_nest_end(struct nftnl_udata_buf *buf, struct nftnl_udata *ud);

/* nftnl_udata_attr */
uint8_t nftnl_udata_type(const struct nftnl_udata *attr);
uint8_t nftnl_udata_len(const struct nftnl_udata *attr);
void *nftnl_udata_get(const struct nftnl_udata *attr);
uint32_t nftnl_udata_get_u32(const struct nftnl_udata *attr);

/* iterator */
struct nftnl_udata *nftnl_udata_next(const struct nftnl_udata *attr);

#define nftnl_udata_for_each(buf, attr)                       \
	for ((attr) = nftnl_udata_start(buf);                 \
	     (char *)(nftnl_udata_end(buf)) > (char *)(attr); \
	     (attr) = nftnl_udata_next(attr))

#define nftnl_udata_for_each_data(data, data_len, attr)  \
	for ((attr) = (struct nftnl_udata *)(data);      \
	     (char *)(data + data_len) > (char *)(attr); \
	     (attr) = nftnl_udata_next(attr))

typedef int (*nftnl_udata_cb_t)(const struct nftnl_udata *attr, void *data);
int nftnl_udata_parse(const void *data, uint32_t data_len, nftnl_udata_cb_t cb,
		      void *cb_data);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _LIBNFTNL_UDATA_H_ */
