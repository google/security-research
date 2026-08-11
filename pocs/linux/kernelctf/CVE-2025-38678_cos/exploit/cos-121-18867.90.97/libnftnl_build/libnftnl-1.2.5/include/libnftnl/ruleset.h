#ifndef _LIBNFTNL_RULESET_H_
#define _LIBNFTNL_RULESET_H_

#include <stdio.h>

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include <libnftnl/common.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nftnl_ruleset;

struct nftnl_ruleset *nftnl_ruleset_alloc(void);
void nftnl_ruleset_free(const struct nftnl_ruleset *r);

enum {
	NFTNL_RULESET_TABLELIST = 0,
	NFTNL_RULESET_CHAINLIST,
	NFTNL_RULESET_SETLIST,
	NFTNL_RULESET_RULELIST,
};

enum nftnl_ruleset_type {
	NFTNL_RULESET_UNSPEC = 0,
	NFTNL_RULESET_RULESET,
	NFTNL_RULESET_TABLE,
	NFTNL_RULESET_CHAIN,
	NFTNL_RULESET_RULE,
	NFTNL_RULESET_SET,
	NFTNL_RULESET_SET_ELEMS,
};

bool nftnl_ruleset_is_set(const struct nftnl_ruleset *r, uint16_t attr);
void nftnl_ruleset_unset(struct nftnl_ruleset *r, uint16_t attr);
void nftnl_ruleset_set(struct nftnl_ruleset *r, uint16_t attr, void *data);
void *nftnl_ruleset_get(const struct nftnl_ruleset *r, uint16_t attr);

enum {
	NFTNL_RULESET_CTX_CMD = 0,
	NFTNL_RULESET_CTX_TYPE,
	NFTNL_RULESET_CTX_TABLE,
	NFTNL_RULESET_CTX_CHAIN,
	NFTNL_RULESET_CTX_RULE,
	NFTNL_RULESET_CTX_SET,
	NFTNL_RULESET_CTX_DATA,
};

struct nftnl_parse_ctx;
void nftnl_ruleset_ctx_free(const struct nftnl_parse_ctx *ctx);
bool nftnl_ruleset_ctx_is_set(const struct nftnl_parse_ctx *ctx, uint16_t attr);
void *nftnl_ruleset_ctx_get(const struct nftnl_parse_ctx *ctx, uint16_t attr);
uint32_t nftnl_ruleset_ctx_get_u32(const struct nftnl_parse_ctx *ctx,
				 uint16_t attr);

int nftnl_ruleset_parse_file_cb(enum nftnl_parse_type type, FILE *fp,
			      struct nftnl_parse_err *err, void *data,
			      int (*cb)(const struct nftnl_parse_ctx *ctx));
int nftnl_ruleset_parse_buffer_cb(enum nftnl_parse_type type, const char *buffer,
				struct nftnl_parse_err *err, void *data,
				int (*cb)(const struct nftnl_parse_ctx *ctx));
int nftnl_ruleset_parse(struct nftnl_ruleset *rs, enum nftnl_parse_type type,
		      const char *data, struct nftnl_parse_err *err);
int nftnl_ruleset_parse_file(struct nftnl_ruleset *rs, enum nftnl_parse_type type,
			   FILE *fp, struct nftnl_parse_err *err);
int nftnl_ruleset_snprintf(char *buf, size_t size, const struct nftnl_ruleset *rs, uint32_t type, uint32_t flags);
int nftnl_ruleset_fprintf(FILE *fp, const struct nftnl_ruleset *rs, uint32_t type, uint32_t flags);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _LIBNFTNL_RULESET_H_ */
