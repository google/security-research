#ifndef _LIBNFTNL_TRACE_H_
#define _LIBNFTNL_TRACE_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

enum nftnl_trace_attr {
	NFTNL_TRACE_CHAIN = 0,
	NFTNL_TRACE_FAMILY,
	NFTNL_TRACE_ID,
	NFTNL_TRACE_IIF,
	NFTNL_TRACE_IIFTYPE,
	NFTNL_TRACE_JUMP_TARGET,
	NFTNL_TRACE_OIF,
	NFTNL_TRACE_OIFTYPE,
	NFTNL_TRACE_MARK,
	NFTNL_TRACE_LL_HEADER,
	NFTNL_TRACE_NETWORK_HEADER,
	NFTNL_TRACE_TRANSPORT_HEADER,
	NFTNL_TRACE_TABLE,
	NFTNL_TRACE_TYPE,
	NFTNL_TRACE_RULE_HANDLE,
	NFTNL_TRACE_VERDICT,
	NFTNL_TRACE_NFPROTO,
	NFTNL_TRACE_POLICY,
	__NFTNL_TRACE_MAX,
};
#define NFTNL_TRACE_MAX (__NFTNL_TRACE_MAX - 1)

struct nftnl_trace;

struct nftnl_trace *nftnl_trace_alloc(void);
void nftnl_trace_free(const struct nftnl_trace *trace);

bool nftnl_trace_is_set(const struct nftnl_trace *trace, uint16_t type);

const void *nftnl_trace_get_data(const struct nftnl_trace *trace,
				 uint16_t type, uint32_t *data_len);

uint16_t nftnl_trace_get_u16(const struct nftnl_trace *trace, uint16_t type);
uint32_t nftnl_trace_get_u32(const struct nftnl_trace *trace, uint16_t type);
uint64_t nftnl_trace_get_u64(const struct nftnl_trace *trace, uint16_t type);
const char *nftnl_trace_get_str(const struct nftnl_trace *trace, uint16_t type);

int nftnl_trace_nlmsg_parse(const struct nlmsghdr *nlh, struct nftnl_trace *t);
#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _LIBNFTNL_TRACE_H_ */
