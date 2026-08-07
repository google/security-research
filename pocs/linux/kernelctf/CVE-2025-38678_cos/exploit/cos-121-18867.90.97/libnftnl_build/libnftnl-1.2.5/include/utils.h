#ifndef LIBNFTNL_UTILS_H
#define LIBNFTNL_UTILS_H 1

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <libnftnl/common.h>

#include "config.h"
#ifdef HAVE_VISIBILITY_HIDDEN
#	define __visible	__attribute__((visibility("default")))
#	define EXPORT_SYMBOL(x)	typeof(x) (x) __visible;
#else
#	define __visible
#	define EXPORT_SYMBOL
#endif

#define __noreturn	__attribute__((__noreturn__))

#define xfree(ptr)	free((void *)ptr);

#define div_round_up(n, d)	(((n) + (d) - 1) / (d))

void __noreturn __abi_breakage(const char *file, int line, const char *reason);

#define abi_breakage()	\
	__abi_breakage(__FILE__, __LINE__, strerror(errno));

void __nftnl_assert_fail(uint16_t attr, const char *filename, int line);

#define nftnl_assert(val, attr, expr)			\
  ((!val || expr)					\
   ? (void)0						\
   : __nftnl_assert_fail(attr, __FILE__, __LINE__))

#define nftnl_assert_validate(data, _validate_array, _attr, _data_len)		\
({										\
	if (!data)								\
		__nftnl_assert_fail(attr, __FILE__, __LINE__);			\
	if (_validate_array[_attr])						\
		nftnl_assert(data, attr, _validate_array[_attr] == _data_len);	\
})

void __nftnl_assert_attr_exists(uint16_t attr, uint16_t attr_max,
				const char *filename, int line);

#define nftnl_assert_attr_exists(_attr, _attr_max)					\
({											\
	if (_attr > _attr_max)								\
		__nftnl_assert_attr_exists(_attr, _attr_max, __FILE__, __LINE__);	\
})

#define SNPRINTF_BUFFER_SIZE(ret, remain, offset)	\
	if (ret < 0)					\
		ret = 0;				\
	offset += ret;					\
	if (ret > remain)				\
		ret = remain;				\
	remain -= ret;					\


#define BUILD_BUG_ON_ZERO(e)	(sizeof(char[1 - 2 * !!(e)]) - 1)

#define __must_be_array(a) \
	BUILD_BUG_ON_ZERO(__builtin_types_compatible_p(typeof(a), typeof(&a[0])))

#define array_size(arr)		(sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))

const char *nftnl_family2str(uint32_t family);
int nftnl_str2family(const char *family);

enum nftnl_type {
	NFTNL_TYPE_U8,
	NFTNL_TYPE_U16,
	NFTNL_TYPE_U32,
	NFTNL_TYPE_U64,
	NFTNL_TYPE_S8,
	NFTNL_TYPE_S16,
	NFTNL_TYPE_S32,
	NFTNL_TYPE_S64,
};

int nftnl_strtoi(const char *string, int base, void *number, enum nftnl_type type);
int nftnl_get_value(enum nftnl_type type, void *val, void *out);

const char *nftnl_verdict2str(uint32_t verdict);
int nftnl_str2verdict(const char *verdict, int *verdict_num);

const char *nftnl_cmd2tag(enum nftnl_cmd_type cmd);
uint32_t nftnl_str2cmd(const char *cmd);

enum nftnl_cmd_type nftnl_flag2cmd(uint32_t flags);

int nftnl_fprintf(FILE *fpconst, const void *obj, uint32_t cmd, uint32_t type,
		  uint32_t flags,
		  int (*snprintf_cb)(char *buf, size_t bufsiz, const void *obj,
			  	     uint32_t cmd, uint32_t type,
				     uint32_t flags));

#endif
