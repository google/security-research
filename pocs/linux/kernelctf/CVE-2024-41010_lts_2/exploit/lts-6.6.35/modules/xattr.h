#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>
#include <stdbool.h>

#include <sys/types.h>

#ifndef MODULES_SIMPLE_XATTR
#define MODULES_SIMPLE_XATTR

#define MODULES_CONFIG_IS_XATTR_RBTREE 1

#if MODULES_CONFIG_IS_XATTR_RBTREE

#ifndef MODULES_RB_NODE
#define MODULES_RB_NODE

#define RB_RED 0
#define RB_BLACK 1

struct rb_node {
	uint64_t  __rb_parent_color;
	struct rb_node *rb_right;
	struct rb_node *rb_left;
};
#endif

struct simple_xattr {
	struct rb_node rb_node;
	char * name;
	size_t size;
	char value[];
};

#else
#ifndef MODULES_LIST_HEAD
#define MODULES_LIST_HEAD
struct list_head {
    struct list_head *next, *prev;
};
#endif

struct simple_xattr {
	struct list_head list;
	char * name;
	size_t size;
	char value[];
};

#endif

struct xattr_return {
    uint64_t size;
    char *value;
};

#define XATTR_HEADER_SIZE sizeof(struct simple_xattr)
#define XATTR_VALUE_KMALLOC_CG_64 (0x40 - XATTR_HEADER_SIZE)
#define XATTR_VALUE_KMALLOC_CG_128 (0x80 - XATTR_HEADER_SIZE)
#define XATTR_VALUE_KMALLOC_CG_192 (0xc0 - XATTR_HEADER_SIZE)
#define XATTR_VALUE_KMALLOC_CG_256 (0x100 - XATTR_HEADER_SIZE)
#define XATTR_VALUE_KMALLOC_CG_512 (0x200 - XATTR_HEADER_SIZE)
#define XATTR_VALUE_KMALLOC_CG_1K (0x400 - XATTR_HEADER_SIZE)
#define XATTR_VALUE_KMALLOC_CG_2K (0x800 - XATTR_HEADER_SIZE)
#define XATTR_VALUE_KMALLOC_CG_4K (0x1000 - XATTR_HEADER_SIZE)
#define XATTR_VALUE_KMALLOC_CG_8K (0x2000 - XATTR_HEADER_SIZE)
#define XATTR_VALUE_KMALLOC_CG_16K (0x4000 - XATTR_HEADER_SIZE)
#define XATTR_VALUE_KMALLOC_CG_32K (0x8000 - XATTR_HEADER_SIZE)

#define XATTR_PREFIX_USER "user."
#define XATTR_PREFIX_SYSTEM "system."
#define XATTR_PREFIX_TRUSTED "trusted."
#define XATTR_PREFIX_SECURITY "security."

char *gen_xattr_name(char *prefix, char *name);
char *gen_xattr_name_fixed_sz(char *prefix, char *name, size_t sz);

int create_xattr(char *fname, char *name, char *value, uint64_t objectsz, bool panic_on_warn);
struct xattr_return *read_xattr(char *fname, char *name);
int remove_xattr(char *fname, char *name, bool panic_on_warn);
void remove_xattr_noerror(char *fname, char *name);

#if MODULES_CONFIG_IS_XATTR_RBTREE
struct simple_xattr *fake_xattr(bool color, struct rb_node *parent, struct rb_node *right, struct rb_node *left, char *name, size_t size, char *value, uint64_t valuesz);
#else
struct simple_xattr *fake_xattr(struct list_head *next, struct list_head *prev, char *name, size_t size, char *value, uint64_t valuesz);
#endif

#endif