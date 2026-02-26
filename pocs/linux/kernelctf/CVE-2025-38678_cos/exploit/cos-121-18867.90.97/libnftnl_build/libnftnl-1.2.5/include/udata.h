#ifndef _LIBNFTNL_UDATA_INTERNAL_H_
#define _LIBNFTNL_UDATA_INTERNAL_H_

#include <stdint.h>
#include <stddef.h>

/*
 * TLV structures:
 * nftnl_udata
 *  <-------- HEADER --------> <------ PAYLOAD ------>
 * +------------+-------------+- - - - - - - - - - - -+
 * |    type    |     len     |         value         |
 * |  (1 byte)  |   (1 byte)  |                       |
 * +--------------------------+- - - - - - - - - - - -+
 *  <-- sizeof(nftnl_udata) -> <-- nftnl_udata->len -->
 */
struct nftnl_udata {
	uint8_t		type;
	uint8_t		len;
	unsigned char	value[];
} __attribute__((__packed__));

/*
 *              +---------------------------------++
 *              | data[]                          ||
 *              |   ||                            ||
 *              |   \/                            \/
 *  +-------+-------+-------+-------+ ... +-------+- - - - - - -+
 *  | size  |  end  |  TLV  |  TLV  |     |  TLV  |    Empty    |
 *  +-------+-------+-------+-------+ ... +-------+- - - - - - -+
 *                  |<---- nftnl_udata_len() ---->|
 *                  |<----------- nftnl_udata_size() ---------->|
 */
struct nftnl_udata_buf {
	uint32_t	size;
	char		*end;
	char		data[];
};

#endif /* _LIBNFTNL_UDATA_INTERNAL_H_ */
