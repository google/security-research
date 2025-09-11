#ifndef _LIBNFTNL_COMMON_INTERNAL_H
#define _LIBNFTNL_COMMON_INTERNAL_H

#define BASE_DEC 10
#define BASE_HEX 16

#define NFTNL_SNPRINTF_BUFSIZ 4096

struct nftnl_parse_err {
	int line;
	int column;
	int error;
	const char *node_name;
};

enum nftnl_parse_input {
	NFTNL_PARSE_BUFFER,
	NFTNL_PARSE_FILE,
};

#endif
