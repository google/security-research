#ifndef _LIBNFTNL_GEN_H_
#define _LIBNFTNL_GEN_H_

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#include <libnftnl/common.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nftnl_gen;

struct nftnl_gen *nftnl_gen_alloc(void);
void nftnl_gen_free(const struct nftnl_gen *);

enum {
	NFTNL_GEN_ID 	= 0,
	__NFTNL_GEN_MAX
};
#define NFTNL_GEN_MAX (__NFTNL_GEN_MAX - 1)

bool nftnl_gen_is_set(const struct nftnl_gen *gen, uint16_t attr);
void nftnl_gen_unset(struct nftnl_gen *gen, uint16_t attr);
int nftnl_gen_set(struct nftnl_gen *gen, uint16_t attr, const void *data) __attribute__((deprecated));
int nftnl_gen_set_data(struct nftnl_gen *gen, uint16_t attr,
		       const void *data, uint32_t data_len);
const void *nftnl_gen_get(const struct nftnl_gen *gen, uint16_t attr);
const void *nftnl_gen_get_data(const struct nftnl_gen *gen, uint16_t attr,
			       uint32_t *data_len);

void nftnl_gen_set_u32(struct nftnl_gen *gen, uint16_t attr, uint32_t data);
uint32_t nftnl_gen_get_u32(const struct nftnl_gen *gen, uint16_t attr);

struct nlmsghdr;
int nftnl_gen_nlmsg_parse(const struct nlmsghdr *nlh, struct nftnl_gen *gen);

int nftnl_gen_snprintf(char *buf, size_t size, const struct nftnl_gen *gen, uint32_t type, uint32_t flags);
int nftnl_gen_fprintf(FILE *fp, const struct nftnl_gen *gen, uint32_t type, uint32_t flags);

#define nftnl_gen_nlmsg_build_hdr	nftnl_nlmsg_build_hdr

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _LIBNFTNL_GEN_H_ */
