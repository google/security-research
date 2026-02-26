#ifndef _DATA_H_
#define _DATA_H_

#include <linux/netfilter/nf_tables.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

enum {
	DATA_NONE,
	DATA_VALUE,
	DATA_VERDICT,
	DATA_CHAIN,
};

enum {
	DATA_F_NOPFX = 1 << 0,
};

union nftnl_data_reg {
	struct {
		uint32_t	val[NFT_DATA_VALUE_MAXLEN / sizeof(uint32_t)];
		uint32_t	len;
	};
	struct {
		uint32_t	verdict;
		const char	*chain;
		uint32_t	chain_id;
	};
};

int nftnl_data_reg_snprintf(char *buf, size_t size,
			    const union nftnl_data_reg *reg,
			    uint32_t flags, int reg_type);
struct nlattr;

int nftnl_parse_data(union nftnl_data_reg *data, struct nlattr *attr, int *type);
void nftnl_free_verdict(const union nftnl_data_reg *data);

#endif
