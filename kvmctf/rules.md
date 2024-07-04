# kvmCTF Overview

kvmCTF is a part of the
[Google VRP](https://bughunters.google.com/about/rules/6625378258649088/google-and-alphabet-vulnerability-reward-program-vrp-rules)
and is focused on eliminating VM-reachable Kernel-based Virtual Machine (KVM)
vulnerabilities. We invite security researchers to demonstrate their bug hunting
and exploitation techniques on an LTS kernel version. Eventually we might add
experimental mitigations to KVM that we would like to see if and how researchers
can bypass them.

We are additionally asking researchers to publish their submissions, helping the
community to learn from each other’s techniques.

# Competition Rules

## Target: Linux LTS KVM
The host runs v6.1.74 and runs on an Intel(R) Xeon(R) Gold 5222 CPU @ 3.80GHz.
Participants will have the option to select whether they want the host to run
with `CONFIG_KASAN` disabled or enabled. The complete setup of the host can be
downloaded
[here](https://storage.googleapis.com/kvmctf/latest.tar.gz) in a
gzip format and contains the following:
* The kernel patch we applied on the kernel tree.
* The kernel configuration files.
* The gcc and binutils versions used to compile the kernel.
* The virsh version used to run the VM.
* The produced `vmlinux` images.
* The produced `bzImage` binaries.
* The produced `ko` module binaries.
* The `qemu-kvm` command used to run the guest.

Participants will be connected to a Debian 12.5 (bookworm) guest that runs on a
`v6.1.0-21` kernel compiled with the default Debian config.

The goal is to perform a successful guest-to-host attack. Currently we do not
reward QEMU, host-to-KVM or CPU-based vulnerabilities.

## Rewards
| Tier                   | Reward   |
|------------------------| -------- |
| Full VM escape         | $250,000 |
| Arbitrary memory write | $100,000 |
| Arbitrary memory read  | $50,000  |
| Relative memory write  | $50,000  |
| Denial of Service      | $20,000  |
| Relative memory read   | $10,000  |


Note that the above rewards do not stack. For instance, if you submit a full VM
escape exploit that takes advantage of an arbitrary memory read you will be
rewarded with $250,000, not $250,000 + $50,000.

## Flags
Your submission should contain proof that your exploit succeeded in one of the
above tiers. This is achieved by providing each tier's corresponding flag (a
64-bit number). Note that providing the flag does **not** automatically
guarantee the corresponding reward, your exploit must take advantage of a
vulnerability of that tier. For instance, if you use an arbitrary memory read
vulnerability to read the arbitrary memory write flag, you will **not** be
compensated with the arbitrary memory write reward.
### RCE flag
To obtain this flag your exploit should read the contents of the
`/root/rce_flag` file in the host file system.
### Arbitrary memory accesses
For the arbitrary memory write tier your exploit should overwrite the contents
of the write flag address (its default value is `0xdeadbeef41424344` so your
exploit should modify any or all of its bits), whereas for the arbitrary memory
read tier your exploit should read the contents of the read flag address. The
target addresses (both virtual and physical) can be found in the
`/root/addresses` file in the guest file system. For the arbitrary memory write
tier, your exploit should first overwrite the contents of the write flag address
and then call hypercall `#100` which will return the corresponding flag in
`RAX`. For the arbitrary memory read tier, the flag is the contents of the read
flag address.
### Relative memory accesses
The relative memory read and relative memory write are available only if the
host runs with `CONFIG_KASAN` enabled. The mapping between the KASAN violations
and the reward tiers is the following:

| Operation     | KASAN violation         | Reward Tier           |
| ------------  | ----------------------- | ------------------    |
| Memory Write  | use-after-free          | Relative memory write |
| Memory Write  | out-of-bounds           | Relative memory write |
| Memory Write  | slab-out-of-bounds      | Relative memory write |
| Memory Write  | global-out-of-bounds    | Relative memory write |
| Memory Write  | stack-out-of-bounds     | Relative memory write |
| Memory Write  | alloca-out-of-bounds    | Relative memory write |
| Memory Write  | vmalloc-out-of-bounds   | Relative memory write |
| Memory Write  | user-memory-access      | Relative memory write |
| Memory Write  | wild-memory-access      | Relative memory write |
| *             | double-free             | Relative memory write |
| *             | invalid-free            | Relative memory write |
| Memory Read   | use-after-free          | Relative memory read  |
| Memory Read   | out-of-bounds           | Relative memory read  |
| Memory Read   | slab-out-of-bounds      | Relative memory read  |
| Memory Read   | global-out-of-bounds    | Relative memory read  |
| Memory Read   | stack-out-of-bounds     | Relative memory read  |
| Memory Read   | alloca-out-of-bounds    | Relative memory read  |
| Memory Read   | vmalloc-out-of-bounds   | Relative memory read  |
| Memory Read   | user-memory-access      | Relative memory read  |
| Memory Read   | wild-memory-access      | Relative memory read  |
| *             | null-ptr-deref          | Denial of Service     |

For the relative memory write tier, your exploit should first perform the
operation that produces the KASAN violation and then call hypercall `#101` which
will return the flag in `RAX`.
Similarly, for the relative memory read tier, your exploit should first perform
the operation to produce the KASAN violation and then call hypercall `#102`
which will return the flag in `RAX`.

### Denial of Service
The Denial of Service tier rewards exploits that induce a `null-ptr-deref` KASAN
violation, or that make the host panic or otherwise
crash. In the former case, your exploit should first perform the operation to
produce the KASAN violation and then call hypercall `#103` which will return the
flag in `RAX`.
In the latter case, you do not need to provide a flag: after executing your
exploit and crashing the host just specify in the submission form that you are
submitting a Denial of Service exploit.

## Process
To try your exploit on our server you will have to reserve a time slot. You can
do it using the command:

``socat FILE:`tty`,raw,echo=0 ssl:kvmctf.ctfcompetition.com:1337,cafile=server_cert.pem``

`server_cert.pem`:
```
-----BEGIN CERTIFICATE-----
MIIBXTCCAQ+gAwIBAgIUcU+vah86fZls1/1gfDBEotuQTi4wBQYDK2VwMCQxIjAg
BgNVBAMMGWt2bWN0Zi5jdGZjb21wZXRpdGlvbi5jb20wHhcNMjQwMzI2MTc1MjUw
WhcNMzQwMzI0MTc1MjUwWjAkMSIwIAYDVQQDDBlrdm1jdGYuY3RmY29tcGV0aXRp
b24uY29tMCowBQYDK2VwAyEAWiQBWTd51Qej7hPho7MtkLu6gtOJhyGM8lVr4dlf
r6OjUzBRMB0GA1UdDgQWBBSGgjr7/oy7f72v7fjy+Boe7dmTaTAfBgNVHSMEGDAW
gBSGgjr7/oy7f72v7fjy+Boe7dmTaTAPBgNVHRMBAf8EBTADAQH/MAUGAytlcANB
AKwz9VdZ1e81DObSMEmeAm5mBc+Hsu50etwjDQGAPMoag+qcPddvlmlxcmuKY4QO
OzLhYAILFWvYJrT5uTF0FwU=
-----END CERTIFICATE-----
```

and follow the prompts. Note that the reservations are done using the UTC time
so please convert your desired time to UTC before reserving. You will need to
provide an email address and whether you want a KASAN-enabled host, and you will
be given a key (both in your terminal and in an email verification). To connect
to the server during your reserved time slot you can use the same command as
above. You will be asked to provide the email address you used to reserve the
time slot and the key you received. After verification, you will be redirected
to the server.

## Additional eligibility rules
Only the first submission for a vulnerability is eligible for a reward.
If a patch commit fixes multiple vulnerabilities (e.g. by backporting a new
version of a component to the stable tree), we assume the root cause is the same
and we consider further submissions as duplicates.
If the same vulnerability is fixed in multiple patch commits (e.g. in commit A
in the mainline tree and separately in commit B in the stable tree), then we
still consider it as the same vulnerability, thus making further submissions
duplicates.

# Submission process
Note: Minor details of the submission process may change from time to time,
please make sure you check this page again for updates when you make a new
submission.
Submissions can only target 0-day vulnerabilities.

We consider a bug 0-day if at the time of the submission:
* There is no patch commit in the mainline tree, and
* The vulnerability is not disclosed in any form (e.g. there is no Syzkaller
  report about the bug)
    * Note: We may still consider a bug 0-day at our discretion (e.g. although
      the bug was disclosed by Syzkaller more than 30 days ago, there is no fix
      and you convince the maintainers to fix the bug)

The submission process contains two stages. The purpose of the two-stage system
is to make sure the vulnerability details are not shared with us before the
patch is released but to still provide a way for 0-day vulnerability finders
to prove that they found the vulnerability by submitting the flag to us
in the first stage.

### First stage

1. Exploit the bug and capture the flag from the target environment (the flag is
   a proof of successful exploitation).
2. Compress the exploit and its source code as a .tar.gz filei, calculate its
   SHA256 checksum.
   * Save this exact file, you will need to send us this later.
   * Try to keep this file to the minimum necessary, leave out large files like
     e.g. vmlinux, bzImage as they can be downloaded separately if needed.
3. Go to
   [https://bughunters.google.com/report/vrp](https://bughunters.google.com/report/vrp)
4. Sign in (this helps us identify you and send you a reward)
5. In the "Report Description" field put a summary of the report – please
   mention "kvmCTF", the time slot and the reward tier (e.g. `kvmCTF
   2025_01_01_00_00: Relative Memory Write`)
6. Enter `Linux Kernel` into the affected product / website field, select the
   `My product is not listed in the product list` checkbox.
7. Enter `kernel.org` into the URL field.
8. Enter the following information in the `Please describe the technical details
   of the vulnerability` field:
   * The first line should be "kvmCTF"
   * The second line should be "Reward Tier: " followed by the targeted reward
     tier.
   * The third line should be "Email: " followed by the email used to reserve
     the time slot.
   * The fourth line should be "Time slot: " followed by the reserved time slot
     (e.g. 2025/01/01 00:00).
   * The fifth line should be the "Flag: " followed by the flag you obtained.
     If your exploit is a "Denial of Service" and crashed the host, please fill
     this line with "Flag: Host Crash".
9. Enter the hash computed at step 2 in the `Please briefly explain who can
   exploit the vulnerability, and what they gain when doing so` field.
11. Select `Privilege Escalation` as the Vulnerability Type.
12. Select `No, this vulnerability is private`.
13. Select `Yes` on `Do you plan to disclose this bug publicly?`
14. Set the date (at most 14 days after the date of filling this report) that
    you plan to report the vulnerability.
15. You can optionally donate twice the reward to charity if you select
      "Donate to charity and double my reward."
16. Submit your report.
17. We will review your submission and contact you when to proceed with the rest
    of the steps.

### Second stage
1. Report the vulnerability to security@kernel.org within 7 days of receiving
   the notice.
   * Note: A submission will be considered ineligible if it turns out that this
     requirement was not respected.
2. Make sure that you are credited in the Reported-By tag of the patch that
   fixes the bug.
   * Use the same email address in the Reported-By tag as you use in the
     bughunters website or the one you used to reserve the time slot.
   * If there is no Reported-By tag on a patch commit, then a 0-day submission
     is eligible only if this is the first 0-day submission for that patch
     commit (based on the submission time of the bughunters report).
   * If it is unclear who reported the bug, then we reserve the right to
     invalidate the submission, change the reward or make a custom decision at
     our discretion. 
3. Wait for the patch to land in a release candidate on the mainline tree (and
    tagged in Git), or committed on a stable tree.
4. Contact us within 7 days and provide the following details:
    * The patch commit, CVE (optionally, if it is already known) and the exact
    target(s) (e.g. `LTS 6.1.74`).
    * Describe the vulnerability in detail (see the Documentation requirements
    section)
    * Reuse the contents of your `vulnerability.md` if it already exists (see
    the "Exploit PR file structure" section).
5. Wait for Linux to publish a CVE or publish the vulnerability details
   yourself on [oss-sec](https://seclists.org/oss-sec/).
6. After the vulnerability is disclosed via a CVE or oss-sec, wait 30 days
    (recommendation, see notes below) and send us your exploit with the
    description of the exploitation technique via a PR to [the security-research
    repo](https://github.com/google/security-research/) (see required structure
    below).
7. Make sure that the PR is merged (this is a requirement to get a reward).

A submission will not be eligible as a 0-day submission if the vulnerability
details were reported somewhere (e.g. Pwn2Own) other than
[security@kernel.org](mailto:security@kernel.org).

## Note about making the exploit public
You can publish your exploit at any time you would like to, but we recommend
publishing the exploit 30 days after the vulnerability was disclosed. This gives
the industry time to apply patches. Read our stance on the topic in [Google’s
disclosure policy](http://about.google/appsecurity).

We only process submissions after the exploit is public (and we can only issue
rewards when the submission was processed), but not sooner than 30 days after
the vulnerability disclosure.

If you publish sooner than 30 days, you won’t get the reward faster. If you want
to delay the publication (disclose later than 30 days), you could do that, but
you would get the money later (we want to encourage you to publish the exploit
details sooner than later).

## Exploit PR file structure
The submission should be put into the `pocs/linux/kvmctf/<cve>/` folder within
the [security-research](https://github.com/google/security-research/) repo,
where:
* cve is the CVE number of the vulnerability in the format `CVE-yyyy-NNNNN`
For example: `pocs/linux/kvmctf/CVE-2023-1872/`.

The structure of this submission folder should be:
* `original.tar.gz`
  * Required, contains the original exploit. Its hash must match the one
    submitted initially via the submission (this hash cannot be modified later).
* `docs/vulnerability.md`
  * Required, description of the vulnerability.
* `docs/exploit.md`
  * Required, description of how the exploits work.
* `exploit/6.1.x/`
  * `exploit.c`
    * Required, source code of the exploit.
  * `exploit`
    * Required, compiled exploit which stole the flag.
  * `Makefile`
    * Required, includes target (`exploit`) to compile exploit.c into exploit
      and target (`run`) to run the exploit on the live instance (which steals
      the flag).

You can add additional files (e.g. images for writeup or supporting libraries
for the exploit). The exploit can be split into multiple files, although we
prefer if it is kept as a single `.c` file.
# Documentation requirements
## Vulnerability
If possible please include the following information in the vulnerability
details:
* Commit which introduced the vulnerability
* Commit which fixed the vulnerability
* Affected kernel versions
* Cause (UAF, BoF, race condition, double free, refcount overflow, etc)
## Exploit
Make sure that the exploit is properly commented and the accompanying exploit.md
includes all the details, making it easy to understand what the exploit does.

Give a step-by-step overview of the exploitation process. When describing the
following activities, include them as a separate step:
* Triggering a vulnerability.
* Converting one attack primitive into another.
* Spraying or grooming the heap.
* Leaking host information.
* Overwriting host memory.
* Getting RIP control.
* Executing interesting post-RIP approaches.
* Doing a major step towards a successful exploitation which is not listed
  above.

In the steps, include the affected objects (e.g. `struct file`), their role
(e.g. vulnerable object, victim object), and their respective caches (e.g.
`kmalloc-1k`) and the used field members of the object (e.g. getting RIP control
via `file->ops->ioctl`, overwriting `msg_msg->security`).

We expect the following parts to be properly documented:
* Non-trivial constant values should be explained, for example:
  * Flag and enumeration values
  * Field offsets
  * Function addresses
  * ROP gadget offsets
* ROP chain items should be explained.
  * E.g. in `rop[0] = base + 0x123456;` explain that 0x123456 is resolved to
    e.g. `call_usermodehelper_exec`.
* Fake structures should be explained; i.e. which structure is created and what
  fields are set.
  * E.g. `data[0x8] = base + 0x123456;` -> data variable contains a fake `struct
    file`, the field at 0x8 offset is a `f_inode` pointer which is set to ...
* Usage of multi-threading (or forking)
  * Why is it needed?
  * If a race condition is exploited, then what code paths are raced.
  * Communication and synchronization between two the threads (e.g. what data
    was sent between the threads, and when the threads are waiting on each
    other).
* Separation between code parts which are needed to trigger the vulnerability
  and parts which are part of the exploitation process (spraying, heap grooming,
  cross-cache, converting one primitive to another).
* Any action (e.g. MSR update, hypercall) where a side-effect of the action is
  used for the exploit and not the main functionality, for example:
  * Hypercall used for spraying a specific structure, not for its main purpose.
  * Change of some MSR value with a non-trivial effect.

If possible, also include how stable your exploit is (e.g. it worked 90% of the
time during your testing).
# Additional information
## Program change notifications and communication
We announce major program changes on
[Google’s Security Blog](https://security.googleblog.com/), but we may change
minor, mostly technical details (like steps in the submission process) by
changing this page and announcing the change on our
[#kvmctf-announcements](https://discord.gg/gBrsEgvAUk) Discord channel.

If you have any question regarding kvmCTF, feel free to ask on the
[#kvmctf](https://discord.gg/c8drZpwYBn) Discord channel.
