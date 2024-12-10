#define _LOCAL_NETLINK_H_

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/keyctl.h>
#include <linux/unistd.h>
#include <libnftnl/chain.h>
#include <libnftnl/table.h>
#include <libnftnl/rule.h>
#include <libnftnl/set.h>
#include <libnftnl/object.h>
#include <libnftnl/expr.h>
#include <libmnl/libmnl.h>

void create_table(struct mnl_socket *, char *);
void create_set(struct mnl_socket *, char *, char*);
void create_obj(struct mnl_socket *, char *, char*);
void del_obj(struct mnl_socket *, char *, char*);
void get_obj( char *, char*);
void create_table_with_data(struct mnl_socket *, char *, void *, size_t);
char *dump_table(char *);
void delete_table(struct mnl_socket *, char *);

void cleanup_spray_tables(struct mnl_socket *);
void tbl_append_name(char *);
char *generate_rnd_name(void);
