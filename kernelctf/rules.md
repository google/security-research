# kernelCTF rules

kernelCTF is a part of the [Google VRP](https://bughunters.google.com/about/rules/6625378258649088/google-and-alphabet-vulnerability-reward-program-vrp-rules) and is focused on making exploiting Linux kernel vulnerabilities harder by inviting security researchers to demonstrate their exploitation techniques on 0-day and 1-day vulnerabilities in various kernel versions. This includes the kernel version with our experimental mitigations; we'd like to see if and how researchers can bypass these mitigations.

We are asking researchers to publish their submissions, helping the community to learn from each other's techniques.

> ⚠️ This document describes the rules which apply from 2025-07-01. For older versions, check the [Github history of the rules page](https://github.com/google/security-research/commits/master/kernelctf/rules.md).

# Reward structure and targets

## Targets

A submission can contain any number of the following 4 parts:

### 1. Exploit for the latest LTS instance

This instance uses the latest LTS with [COS kernel config](https://cos.googlesource.com/third_party/kernel/+/refs/heads/cos-6.1/arch/x86/configs/lakitu_defconfig) and unpriviledged user namespaces turned off since July 1st, 2025 (this configuration considered temporary and could be revised in a new kernelCTF iteration). Besides that, `io_uring` and `nftables` are also [disabled](https://github.com/google/security-research/blob/master/kernelctf/kernel_configs/lts-6.6.config). Only the first submission is eligible per LTS kernel version, but we are upgrading the kernel version every 2-4 weeks on average.

#### Rewards

  * Base reward: $21,337

  * Stability bonus (+$10,000)

    * Criteria: 90% of runs successfully steal the flag.

    * More precisely, the [exploit_repro Github Action](https://github.com/google/security-research/blob/master/.github/workflows/kernelctf-submission-verification.yaml) reports `Reliability: 90%` or better in the `Reproduction summary` (after a sane amount of re-runs if needed)

    * If the exploit requires us to provide a KASLR base address, then it is ineligible for the bonus (`requires_separate_kaslr_leak` is true in `metadata.json` file).

  * Reduced attack surface bonus (+$20,000)

    * Criteria: Exploit works without using unprivileged user namespaces.

    * Note: The bonus applies to all the submissions since July 1st, 2025, as we temporary don't accept the LTS submissions with unpriviledged user namespaces.

    * Note: We may change the bonus definition from time to time (for example adding additional restrictions), but we will announce any changes at least 1 month in advance (see the "Program change notifications and communication" section).

  * 0-day bonus (+$20,000)

    * Criteria: You are exploiting a non-patched, non-disclosed vulnerability (see a more detailed definition in the section "0-day submissions" below).

### 2. Mitigation bypass (on the mitigation instance)

The mitigation instance is upgraded far less frequently than the LTS instance, thus more 1-day vulnerabilities can be exploited. At the same time the unpriviledged namespaces are turned off on this target, similar to LTS, starting from July 1st, 2025. This way you have more opportunity to present your mitigation bypass techniques.

Only exploits which clearly bypass [our mitigations](https://github.com/thejh/linux/blob/slub-virtual/MITIGATION_README) are eligible (e.g. if a mitigation protects against UAF, but not against BoF, then an exploit using a BoF vulnerability is not eligible).

As the current instance uses the `CONFIG_RANDOM_KMALLOC_CACHES` probabilistic memory allocator hardening, only exploits with at least 70% reliability are eligible (checked the same way as the LTS stability bonus).

See the [source code](https://github.com/thejh/linux/tree/c64d47f3a86262fb0e4e43108daf785d875b0f7e) and the [extra kernel hardenings](https://github.com/google/security-research/blob/master/kernelctf/kernel_configs/mitigation-v3-full.config) turned on.

#### Reward

  * $21,000

### 3. Exploits for COS instances

These instances follow the live COS kernel config (which is also used in GKE), with the necessary modifications to make it work in our infrastructure. `io_uring` and `nftables` are enabled here.

Only the first submission is eligible per COS version unless it is part of a valid 0-day LTS submission. New COS versions are released every few weeks on average.

#### Reward

  * $21,000 if the exploit does not use user namespaces and io\_uring

  * $10,500 if the exploit uses user namespaces or io\_uring

    * This reward is based on whether the exploit works on GKE AutoPilot or not. AutoPilot currently does not enable unprivileged user namespaces and they are also considering disabling io\_uring.

  * Currently, there are two instances (COS 105 and COS 109) available. The reward is the same regardless of which instance was exploited (the reward is not doubled if both were exploited).

  * We may change the number of instances or their kernel versions, but will announce this at least 1 month in advance (via [#kernelctf-announcements](https://discord.gg/yXue2RwDEA)).

  * Note: Other bonuses (e.g. 0-day and reduced attack surface bonuses) do not apply here.

### 4. Novel techniques

We reward submissions demonstrating novel exploitation techniques (at our discretion), and including a description of the technique that shows why it is novel.

Novel techniques can be submitted at any time exploiting any available environment, even if the vulnerability was already exploited in that environment.

#### Reward

  * From $0 to $20,000 per technique, at our discretion.

### Target instances

You can connect to the targets with `socat - ssl:kernelctf.vrp.ctfcompetition.com:1337,cafile=server_cert.pem`

`server_cert.pem`:

```
-----BEGIN CERTIFICATE-----
MIIBazCCAR2gAwIBAgIUSXiRksvnzRI2WYqh7nDZVoZydOIwBQYDK2VwMCsxKTAn
BgNVBAMMIGtlcm5lbGN0Zi52cnAuY3RmY29tcGV0aXRpb24uY29tMB4XDTIzMDYw
ODIyNDA0MFoXDTMzMDYwNTIyNDA0MFowKzEpMCcGA1UEAwwga2VybmVsY3RmLnZy
cC5jdGZjb21wZXRpdGlvbi5jb20wKjAFBgMrZXADIQCTg2ayrs3BsxUocgbd1eWj
WWVzQQmORR5LT3unlZCzFaNTMFEwHQYDVR0OBBYEFCSsjYgVH8funXWPApo32zpS
NhPgMB8GA1UdIwQYMBaAFCSsjYgVH8funXWPApo32zpSNhPgMA8GA1UdEwEB/wQF
MAMBAf8wBQYDK2VwA0EAxJ+NlnvVYZKj/ctSIzcuPm7+4SlziIHDRW43SrLks15v
KQVTtek3sAifw5NuaXWZrGrX7JAqNqci3QPCMHFEDA==
-----END CERTIFICATE-----
```

You can use maximum two connections per IPv4 address and the connection will be closed after 30 minutes.

The source code running on the server is available [on our Github](https://github.com/google/security-research/tree/master/kernelctf/server).

## Additional eligibility rules

Only the first submission for a vulnerability is eligible for a reward (per target). The COS instances are considered to be one target so there are 3 targets in total (LTS, mitigation, COS).

This means: if a vulnerability is exploited on the latest LTS by Researcher A (but not on the other targets), then it can still be exploited on the mitigation instance and COS instances (e.g. by Researcher B or later by Researcher A), but can no longer be exploited on the latest LTS (even if the LTS kernel version is updated).

If a patch commit fixes multiple vulnerabilities (e.g. by backporting a new version of a component to the stable tree), we assume the root cause is the same and we consider further submissions (for the same target) as duplicates.

If the same vulnerability is fixed in multiple patch commits (e.g. in commit A in the mainline tree and separately in commit B in the stable tree), then we still consider it as the same vulnerability, thus making further submissions (for the same target) duplicates.

The "novel techniques" category is an exception from these rules, as in that category we are rewarding the technique, so you can target already exploited vulnerabilities.

If you are unsure about eligibility, contact us on the [#kernelctf Discord channel](https://discord.gg/ECS5VnJZys) before making the submission.

# Submission process

_Note: Minor details of the submission process may change from time to time, please make sure you check this page again for updates when you make a new submission._

Before you start the submission process, please make sure that the target's slot you are planning to exploit is not taken by looking at the [public spreadsheet](https://docs.google.com/spreadsheets/d/e/2PACX-1vS1REdTA29OJftst8xN5B5x8iIUcxuK6bXdzF8G1UXCmRtoNsoQ9MbebdRdFnj6qZ0Yd7LwQfvYC2oF/pubhtml). The server also tries to warn you about this by putting "Slot is taken by expNNN" next to the target.

Submissions can target 0-day and 1-day bugs.

## Non-patched and 0-day submissions

We consider a bug 0-day if at the time of the submission:

  * There is no patch commit in the mainline tree, and

  * The vulnerability is not disclosed in any form (e.g. there is no Syzkaller report about the bug)

    * Note: We may still consider a bug 0-day at our discretion (e.g. although the bug was disclosed by Syzkaller more than 30 days ago, there is no fix and you convince the maintainers to fix the bug)

If the submission targets a bug which is not patched yet (0-day or 1-day without a patch), then the submission process has one additional initial stage.

The purpose of this additional stage is to make sure the vulnerability details are not shared with us before the patch is released but to still provide a 7-days long "protection window" for 0-day vulnerability founders in case some else makes a 1-day submission for the same vulnerability before the 0-day founder.

In this stage:

  0. Exploit the bug and capture the flag from the target environment (the flag is a proof of successful exploitation).

     * The environments are not shared but running in separate VMs, so you don't have to worry about others stealing your 0-day.

  1. Compress the exploit and its source code as a .tar.gz file and calculate its SHA256 checksum.

     * Save this exact file, you will need to send us this later.

     * Try to keep this file to the minimum necessary, leave out large files like e.g. `vmlinux`, `bzImage` as they can be downloaded separately if needed.

  2. Submit the flag and the hash via [this form](https://forms.gle/JA3XVBdmSbFmhgZQ9) with the additional details requested.

     * Save the link as you’ll have to edit this form later.

  3. Check the [public spreadsheet](https://docs.google.com/spreadsheets/d/e/2PACX-1vS1REdTA29OJftst8xN5B5x8iIUcxuK6bXdzF8G1UXCmRtoNsoQ9MbebdRdFnj6qZ0Yd7LwQfvYC2oF/pubhtml) that you actually took a free slot and your submission is not a dupe (if there is a race for a slot, it is possible that someone else was faster than you and took the slot). If your submission was dupe, you have to wait for new, empty slot to be released.

  4. Report the vulnerability to security@kernel.org within 7 days of the first form submission.

     * Note: A submission will be considered ineligible if it turns out that this requirement was not respected.

  5. Make sure that you are credited in the `Reported-By` tag of the patch that fixes the bug.

     * Use the same email address in the `Reported-By` tag as you use for the form submission or in the "Email address used in Reported-By tag" field of the form.

     * If there is no `Reported-By` tag on a patch commit, then a 0-day submission is eligible only if this is the first 0-day submission for that patch commit (based on the first stage submission date).

     * If it is unclear who reported the bug, then the 0-day bonus can be split (multiple reporters), reduced, invalidated or the 0-day submission protection can be lost at our discretion.

  6. Wait for the patch to land in a release candidate on the mainline tree (and tagged in Git), or committed on a stable tree.

  7. Modify the form within 7 days by following the previously saved link and fill out the extra details as described below in the 1-day section.

     * If the 7-day deadline is missed, then the first stage 0-day protection expires and other 1-day submissions can take priority over this submission (which makes this submission a duplicate and thus ineligible for reward).

A submission will not be eligible as a 0-day submission if the vulnerability details were reported somewhere (e.g. Pwn2Own) other than [security@kernel.org](mailto:security@kernel.org).

## Already patched, 1-day submissions

  0. Exploit the bug and capture the flag from the target environment (the flag is a proof of successful exploitation).

  1. Submit the requested vulnerability details via [this form](https://forms.gle/JA3XVBdmSbFmhgZQ9) (without including additional details on the exploitation technique for now).

  2. Check the [public spreadsheet](https://docs.google.com/spreadsheets/d/e/2PACX-1vS1REdTA29OJftst8xN5B5x8iIUcxuK6bXdzF8G1UXCmRtoNsoQ9MbebdRdFnj6qZ0Yd7LwQfvYC2oF/pubhtml) that you actually took a free slot and your submission is not a dupe (if there is a race for a slot, it is possible that someone else was faster than you and took the slot). If your submission was dupe, you have to wait for new, empty slot to be released.

  3. Send us the description of the vulnerability via [bughunters.google.com](https://bughunters.google.com/) (please follow the process described below).

  4. Wait for the kernel CNA to publish the CVE or publish the vulnerability details yourself on [oss-sec](https://seclists.org/oss-sec/).

     * If you'd like to speed up the CVE publication process or if the kernel does not assign a CVE for the patch commit, [contact the kernel CNA](https://docs.kernel.org/process/cve.html).

  5. Send us your exploit within 90 days of Step 1 with the description of the exploitation technique via a PR to [the security-research repo](https://github.com/google/security-research/) (see required structure below). This is mandatory step for us to start verification of the vulnerability.

  6. If the PR GHA checks are successful and we verified that the submission exploits the claimed vulnerability, you get half of the reward amount. After a manual PR review and the PR is merged, you get the other half of the reward amount.

### Google Bughunter's website submission process

  1. Go to [https://bughunters.google.com/report/vrp](https://bughunters.google.com/report/vrp)

  2. Sign in (this helps us identify you and send you a reward)

  3. Put a summary of the vulnerability in the report description field – please mention "kernelCTF", the submission ID ("expNN") listed on the [public spreadsheet](https://docs.google.com/spreadsheets/d/e/2PACX-1vS1REdTA29OJftst8xN5B5x8iIUcxuK6bXdzF8G1UXCmRtoNsoQ9MbebdRdFnj6qZ0Yd7LwQfvYC2oF/pubhtml), the affected targets, the affected subsystem, the cause and type of vulnerability (e.g. `kernelCTF exp45: Refcount issue leading to UAF in io_uring affecting COS 5.15 and Linux 6.1`)

  4. Enter `Linux Kernel` into the affected product / website field, select the `My product is not listed in the product list` checkbox.

  5. Enter `kernel.org` into the URL field.

  6. Describe the vulnerability in detail (see the Documentation requirements section):

     * Do not include the exploitation details here.

     * Put "kernelCTF" and the submission ID here again (e.g. "kernelCTF exp45").

     * Make sure that the patch commit, CVE (optionally, if it is already known) and the exact target(s) (e.g. `cos-93-16623.402.40`) are included.

     * You can reuse the contents of your `vulnerability.md` if it already exists (see the "Exploit PR file structure" section).

     * You can just enter "`unprivileged user can get root`" into the attack scenario (bottom) field.

     * If you'd like to attach images or a PoC (triggering the vulnerability without actually exploiting it), you can attach them as a tar.gz file here.

  8. Select `Privilege Escalation` as the Vulnerability Type

  9. Select `Yes, this vulnerability is public or known to third parties` (as the patch is already out).

  10. You can optionally donate twice the reward to charity if you select "Donate to charity and double my reward."

  11. Submit your report.
  
  12. We highly recommend to change your payment provider to BugCrowd for a better payment process. You can [read here](https://bughunters.google.com/blog/6483936851394560/announcing-bugcrowd-as-a-new-bughunters-google-com-payment-option) how.

## Note about making the exploit public

You have to publish your exploit within 90 days of submitting the patch commit via the Google Form to be eligible for a reward.

We only process submissions after the exploit is public and we can only start issuing first half of the reward when the PR checks the automated checks and the initial submission review confirms the submission exploits the claimed vulnerability. The second half of the reward is issued after successful merge of the PR which includes a more depth review (including submission quality checks).

If you want to delay the publication (within the 90 days window), you could do that, but you would get the money later (we want to encourage you to publish the exploit details sooner than later).

The above is about the exploit itself, not the vulnerability. We automatically share some limited vulnerability details of the submissions on our [public submission spreadsheet](https://docs.google.com/spreadsheets/d/e/2PACX-1vS1REdTA29OJftst8xN5B5x8iIUcxuK6bXdzF8G1UXCmRtoNsoQ9MbebdRdFnj6qZ0Yd7LwQfvYC2oF/pubhtml?gid=2095368189), as a CVE, and as soon as you submit the vulnerability details via the form.

## Exploit PR file structure

The submission should be put into the `pocs/linux/kernelctf/<cve>_<targets>/` folder within the [security-research repo](https://github.com/google/security-research/), where:

  * `cve` is the CVE number of the vulnerability in the format `CVE-yyyy-NNNNN`

  * `<targets>` is the list of targets separated by underscore (`_`)

    * Valid target names: `lts`, `mitigation`, `cos`

  * If there is a conflicting submission (e.g. you are only submitting a novel technique), then append `_2` (or `_3`, etc.) after the directory name.

For example: `pocs/linux/kernelctf/CVE-2023-1872_lts_cos/`.

The structure of this submission folder should be:

  * `original.tar.gz`

    * Required, contains the original exploit. Its hash must match the one submitted initially via the form (this hash cannot be modified later).

  * `metadata.json`

    * Required, structured metadata information following [this JSON schema (version 3)](metadata.schema.v3.json).

  * `docs/vulnerability.md`

    * Required, description of the vulnerability.

  * `docs/exploit.md`

    * Required, description of how the exploits work. If exploits are too different, then it can also be put next to exploits.

  * `docs/novel-techniques.md`

    * Only required if submission contains novel technique(s). Contains the description of the techniques.

  * `exploit/mitigation-6.1/`<br>
    `exploit/lts-6.x.x/`<br>
    `exploit/cos-(93|97|101|105|...)-xxxxx.yyy.zz/`

    * `exploit.c`
       * Required, source code of the exploit.

    * `exploit`
       * Required, compiled exploit which stole the flag.

    * `Makefile`
       * Required, includes target (`exploit`) to compile `exploit.c` into `exploit` and target (`run`) to run the exploit on the live instance (which steals the flag).

You can add additional files (e.g. images for writeup or supporting libraries for the exploit). The exploit can be split into multiple files, although we prefer if it is kept as a single `.c` file.

## Documentation requirements

### Vulnerability

If possible please include the following information in the vulnerability details:

  * Requirements to trigger the vulnerability:
    * [Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
    * Kernel configuration
    * Are user namespaces needed?

  * Commit which introduced the vulnerability

  * Commit which fixed the vulnerability

  * Affected kernel versions

  * Affected component, subsystem

  * Cause (UAF, BoF, race condition, double free, refcount overflow, etc)

  * Which syscalls or syscall parameters are needed to be blocked to prevent triggering the vulnerability? (If there is any easy way to block it.)

### Exploit

Ensure that exploit code follows [kernelCTF code style guide](https://google.github.io/security-research/kernelctf/style_guide).

Make sure that the exploit is properly commented and the accompanying `exploit.md` includes all the details, making it easy to understand what the exploit does.

Give a step-by-step overview of the exploitation process. When describing the following activities, include them as a separate step:

  * Triggering a vulnerability.

  * Converting one attack primitive into another.

  * Spraying or grooming the heap.

  * Executing cross-cache attack.

  * Leaking information (e.g. heap pointer, kASLR base address).

  * Overwriting kernel memory.

  * Getting RIP control.

  * Executing interesting post-RIP approaches.

  * Doing a major step towards a successful exploitation which is not listed above.

In the steps, include the affected objects (e.g. `struct file`), their role (e.g. vulnerable object, victim object), and their respective caches (e.g. `kmalloc-1k`) and the used field members of the object (e.g. getting RIP control via `file->ops->ioctl`, overwriting `msg_msg->security`).

We expect the following parts to be properly documented:

  * Non-trivial constant values should be explained, for example:
    * Flag and enumeration values
    * Field offsets
    * Function addresses
    * ROP gadget offsets

  * ROP chain items should be explained.
    * E.g. in `rop[0] = base + 0x123456;` explain that 0x123456 is resolved to e.g. `call_usermodehelper_exec`.

  * Fake structures should be explained; i.e. which structure is created and what fields are set.
    * E.g. `data[0x8] = base + 0x123456`; -> data variable contains a fake `struct file`, the field at 0x8 offset is a `f_inode` pointer which is set to `...`

  * Usage of multi-threading (or forking)
    * Why is it needed?
    * If a race condition is exploited, then what code paths are raced.
    * Communication and synchronization between two the threads (e.g. what data was sent between the threads, and when the threads are waiting on each other).

  * Environmental requirements
    * If specific climit or cpu affinity settings are required, then explain why they are needed.
    * Which limit the exploit runs into using the default settings.

  * Namespaces usage and why are they required.

  * Separation between code parts which are needed to trigger the vulnerability and parts which are part of the exploitation process (spraying, heap grooming, cross-cache, converting one primitive to another).

  * Any action (e.g. syscall) where a side-effect of the action is used for the exploit and not the main functionality, for example:
    * Syscall used for spraying a specific structure, not for its main purpose.
    * Some calls (e.g. `sleep`) used for a specific side-effect which is not trivial see.

If possible, also include how stable your exploit is (e.g. it worked 90% of the time during your testing) and whether your exploit requires a separate kASLR leak (or bruteforce).

# Additional information

## Program change notifications and communication

We announce major program changes on [Google's Security Blog](https://security.googleblog.com/), but we may change minor, mostly technical details (like steps in the submission process) by changing this page and announcing the change on our [#kernelctf-announcements](https://discord.gg/yXue2RwDEA) Discord channel.

## Questions about program

If you have any questions regarding kernelCTF, check [the FAQ page](faq.md) and feel free to ask on the [#kernelctf](https://discord.gg/ECS5VnJZys) Discord channel.

## Non-kernel vulnerabilities

If you are submitting a non-kernel vulnerability affecting our kCTF VRP cluster, please submit the vulnerability to our [kCTF VRP](https://google.github.io/kctf/vrp.html).
