# kernelCTF rules

> [!WARNING]
> These rules apply from 2026-09-04, you can find [the previous version of the rules on Github](https://github.com/google/security-research/blob/88ec1d535b0d147eec404751f0457e7162450aed/kernelctf/rules.md).

kernelCTF is a part of the [Google VRP](https://bughunters.google.com/about/rules/6625378258649088/google-and-alphabet-vulnerability-reward-program-vrp-rules) and is focused on making exploiting Linux kernel vulnerabilities harder by inviting security researchers to demonstrate their exploitation techniques on 0-day vulnerabilities.

We are asking researchers to publish their submissions, helping the community to learn from each other's techniques.

# Reward structure and targets

## Target: Hardened (`hardened-v1-7.x`)

The target is Linux 7.2-rc5 (x86_64) based on the [COS kernel config](https://cos.googlesource.com/third_party/kernel/+/refs/heads/cos-6.12/arch/x86/configs/lakitu_defconfig) with additional hardenings and a reduced attack surface.

### Configuration changes

* **Mitigation features enabled:**
  * `kCFI` + `IBT`
  * `SLAB_VIRTUAL=y`
  * `KMALLOC_PARTITION_TYPED=y`
  * `SLAB_MERGE_DEFAULT=n`

* **Disabled subsystems (reduced attack surface):**
  * `CONFIG_IO_URING=n`
  * `CONFIG_USER_NS=n`
  * `CONFIG_TLS=n`
  * `CONFIG_CRYPTO_USER_API_AEAD=n`
  * `CONFIG_BPF_UNPRIV_DEFAULT_OFF=y`
  * `CONFIG_AF_UNIX_OOB=n`

### Requirements

* **Stability:** Submissions must achieve at least 70% stability based on 20 exploit runs. The exploit needs to run within 5 minutes, otherwise it will be counted as a failed run when we measure stability.
* **Vulnerability works on LTS 6.12:** The underlying vulnerability must be triggerable on the latest LTS 6.12. When executed with the `--vuln-trigger` flag on LTS 6.12, the exploit must crash the system (a full LPE chain is not required on LTS).

### Reward

* **$71,337**

We have retired separate target tiers and bonus categories in favor of a single static reward per eligible exploit.

### Target updates

Only one submission is eligible per kernel version. The 7.2 version will generally remain fixed due to the `SLAB_VIRTUAL` porting requirement. However, we will update the LTS version (used for vulnerability freshness testing) when we release new slots, upgrading the LTS kernel version every 2-4 weeks on average.

## Submission evaluation system

On weeks when a slot is released, the submission window will open on Monday at 12:00 UTC and close on Friday at 12:00 UTC, at which point the winning submission will be selected.

Submissions are evaluated on both speed and reliability over **20 exploit runs**. The server extracts the pre-compiled `exploit` binary from your `.tar.gz` archive and executes it (without recompilation), awarding a final score based on the following formula:

$$\text{Score} = 2 \times (\text{Stability \%}) + \max(100 - \text{AVG}(\text{time\_in\_sec}), 0)$$

* **Maximum Possible Score:** 300 pts (100% stability, 0-second runtime).
* **Minimum Passing Score:** 140 pts (70% stability, $\ge 100$-second runtime).
* **Winning Criterion:** The submission with the highest overall score wins the reward.
* **Submission Limits:** Only one submission per researcher is eligible per slot. Researchers may test and submit multiple times during the open window, but only their latest submission before the Friday 12:00 UTC deadline will be used.

### Connecting to the evaluation system

You can connect to the target with `socat - ssl:kernelctf.vrp.ctfcompetition.com:1337,cafile=server_cert.pem`

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

You can use a maximum of two connections per IPv4 address and the connection will be closed after 30 minutes.

The source code running on the server is available [on our Github](https://github.com/google/security-research/tree/master/kernelctf/server).

## Additional eligibility rules

### Vulnerability dupes

Only the first submission for a vulnerability is eligible for a reward.

This means: if a vulnerability is exploited on the target by Researcher A, it can no longer be exploited on the target (even if the LTS kernel version is updated).

If a patch commit fixes multiple vulnerabilities (e.g. by backporting a new version of a component to the stable tree), we assume the root cause is the same and we consider further submissions as duplicates.

If the same vulnerability is fixed in multiple patch commits (e.g. in commit A in the mainline tree and separately in commit B in the stable tree), then we still consider it as the same vulnerability, thus making further submissions duplicates.

If you are unsure about eligibility, contact us on the [#kernelctf Discord channel](https://discord.gg/ECS5VnJZys) before making the submission.

# Submission process

_Note: Minor details of the submission process may change from time to time, please make sure you check this page again for updates when you make a new submission._

Before you start the submission process, please make sure that the submission window is currently open (Monday 12:00 UTC to Friday 12:00 UTC on slot release weeks) and that you are submitting for the active target version by checking the [public spreadsheet](https://docs.google.com/spreadsheets/d/e/2PACX-1vS1REdTA29OJftst8xN5B5x8iIUcxuK6bXdzF8G1UXCmRtoNsoQ9MbebdRdFnj6qZ0Yd7LwQfvYC2oF/pubhtml) or the evaluation server.

Submissions can only target 0-day vulnerabilities.

We consider a bug 0-day if at the time of the submission:

  * There is no patch commit in the mainline tree, and

  * The vulnerability is not disclosed in any form (e.g. there is no Syzkaller report about the bug)

    * Note: We may still consider a bug 0-day at our discretion (e.g. although the bug was disclosed by Syzkaller more than 30 days ago, there is no fix and you convince the maintainers to fix the bug)

A submission will not be eligible if the vulnerability details were reported somewhere (e.g. Pwn2Own) other than [security@kernel.org](mailto:security@kernel.org).

The submission process has two stages to make sure the vulnerability details are not shared with us before the patch is released:

## Stage 1: Initial submission (before patch release)

  0. Compress the compiled `exploit` binary, its source code, and all the build files as a `.tar.gz` file.

     * Save this exact file, you will need to send us this later.

     * Note: The evaluation system will extract the `exploit` binary from the archive and run it without recompilation.

     * Try to keep this file to the minimum necessary, leave out large files like e.g. `vmlinux`, `bzImage` as they can be downloaded separately if needed.

  1. Upload the compressed file to the evaluation system, which will provide a flag upon successful exploitation.

  2. Submit the flag on [this form](https://forms.gle/JA3XVBdmSbFmhgZQ9) with the additional details requested.

     * Save the link as you’ll have to edit this form later.

  3. Check the [public spreadsheet](https://docs.google.com/spreadsheets/d/e/2PACX-1vS1REdTA29OJftst8xN5B5x8iIUcxuK6bXdzF8G1UXCmRtoNsoQ9MbebdRdFnj6qZ0Yd7LwQfvYC2oF/pubhtml) after submitting the form and confirm that your submission was added and your score is correct.

  4. Wait until Friday at 12:00 UTC and verify that your submission won the current slot. If there are multiple submissions for the same slot, another submission with a higher score may take the slot. If your submission does not win, you must wait for a new, empty slot to be released (start from Step 1).

  5. Report the vulnerability to security@kernel.org within 7 days of winning the slot.

     * Note: A submission will be considered ineligible if it turns out that this requirement was not respected.

  6. If you are not the author of the patch that fixes the bug, make sure that you are credited in the `Reported-By` tag of the patch that fixes the bug.

     * Do not include the `Reported-By` tag if you both discovered the flaw and authored the patch.

     * Use the same email address in the `Reported-By` tag as you use for the form submission or in the "Email address used in Reported-By tag" field of the form.

     * If there is no `Reported-By` tag on a patch commit, then a 0-day submission is eligible only if this is the first 0-day submission for that patch commit (based on the first stage submission date).

     * If it is unclear who reported the bug, then the reward can be split (multiple reporters), reduced, or invalidated at our discretion.

  7. Wait for the patch to land in a release candidate on the mainline tree (and be tagged in Git) or be committed to a stable tree, whichever happens first.

     * Make sure that the patch correctly fixes the vulnerability you reported. If it does not, report the issue to the kernel and wait for the correct patch commit, otherwise your submission will be ineligible.

## Stage 2: After patch release

  1. Modify the form within 7 days by following the previously saved link and fill out the extra vulnerability details.

     * If the 7-day deadline is missed, then the submission may be considered ineligible for reward at our discretion.

  2. Send us your exploit within 90 days with the description of the exploitation technique via a PR to [the security-research repo](https://github.com/google/security-research/) (see required structure below). This is a mandatory step for us to start verification of the vulnerability.

  3. Once the PR's GitHub Actions (GHA) checks pass and we confirm the submission exploits the claimed vulnerability, you receive the first half of the reward. After a manual review and the PR is merged, the second half is issued.

### Google Bughunter's website registration and reward payments

Submitting reports via [bughunters.google.com](https://bughunters.google.com/) prior to PR submission is **no longer required**; an issue will automatically be created on the portal for winning entries.

However, to collect your payout reward:
  1. You must register once on [bughunters.google.com](https://bughunters.google.com/) so we can send you the reward.
  2. We highly recommend changing your payment provider to BugCrowd for a better payment process. You can [read here](https://bughunters.google.com/blog/6483936851394560/announcing-bugcrowd-as-a-new-bughunters-google-com-payment-option) how.

## Note about making the exploit public

You have to publish your exploit within 90 days of submitting the patch commit via the Google Form to be eligible for a reward.

We only process submissions after the exploit becomes public. We can only issue the first half of the reward once the PR passes the automated checks and the initial review confirms that the submission exploits the claimed vulnerability. Following an in-depth review and successful quality checks, the PR will be merged, and the second half of the reward will be issued.

If you want to delay the publication (within the 90 days window), you could do that, but you would get the money later (we want to encourage you to publish the exploit details sooner than later).

The above is about the exploit itself, not the vulnerability. We automatically share some limited vulnerability details of the submissions on our [public submission spreadsheet](https://docs.google.com/spreadsheets/d/e/2PACX-1vS1REdTA29OJftst8xN5B5x8iIUcxuK6bXdzF8G1UXCmRtoNsoQ9MbebdRdFnj6qZ0Yd7LwQfvYC2oF/pubhtml?gid=2095368189), as a CVE, once you submit the extra vulnerability details via the form in Stage 2.

## Exploit PR file structure

The submission should be put into the `pocs/linux/kernelctf/<cve>_<targets>/` folder within the [security-research repo](https://github.com/google/security-research/), where:

  * `cve` is the CVE number of the vulnerability in the format `CVE-yyyy-NNNNN`

  * `<targets>` is the list of targets separated by underscore (`_`)

    * Valid target names: `hardened-v1-7.x`

  * If there is a conflicting submission directory name, then append `_2` (or `_3`, etc.) after the directory name.

For example: `pocs/linux/kernelctf/CVE-2023-1872_hardened-v1-7.x/`.

The structure of this submission folder should be:

  * `original.tar.gz`

    * Required; contains the original exploit (compiled binary and source code used to build it). Its hash must match the one calculated by the evaluation system and encoded within the flag you submitted in the form.

  * `metadata.json`

    * Required, structured metadata information following [this JSON schema (version 3)](metadata.schema.v3.json).

  * `docs/vulnerability.md`

    * Required, description of the vulnerability.

  * `docs/exploit.md`

    * Required, description of how the exploits work. If exploits are too different, then it can also be put next to exploits.

  * `exploit/hardened-v1-7.x/`<br>

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
    * Communication and synchronization between the two threads (e.g. what data was sent between the threads, and when the threads are waiting on each other).

  * Environmental requirements
    * If specific climit or cpu affinity settings are required, then explain why they are needed.
    * Which limit the exploit runs into using the default settings.

  * Namespaces usage and why are they required.

  * Separation between code parts which are needed to trigger the vulnerability and parts which are part of the exploitation process (spraying, heap grooming, cross-cache, converting one primitive to another).

  * Any action (e.g. syscall) where a side-effect of the action is used for the exploit and not the main functionality, for example:
    * Syscall used for spraying a specific structure, not for its main purpose.
    * Some calls (e.g. `sleep`) used for a specific side-effect which is not trivial see.

If possible, also include how stable your exploit is (e.g. it worked 90% of the time during your testing).

Your exploit must support the `--vuln-trigger` argument, which triggers the underlying vulnerability to crash the system (ideally under KASAN) on other versions without requiring a full LPE chain. To stay within [vuln-verify workflow](https://github.com/google/security-research/blob/master/.github/workflows/kernelctf-vuln-verify.yaml) time limits, this mode should skip non-essential steps such as KASLR prefetching.

# Additional information

## Program change notifications and communication

We announce program changes through [#kernelctf-announcements](https://discord.gg/yXue2RwDEA) Discord channel. All major changes are going to be announced 2 weeks in advance before they take an effect. This document will be updated to reflect current set of kernelCTF rules.

## Questions about program

If you have any questions regarding kernelCTF, check [the FAQ page](faq.md) and feel free to ask on the [#kernelctf](https://discord.gg/ECS5VnJZys) Discord channel.

## Non-kernel vulnerabilities

If you are submitting a non-kernel vulnerability affecting our kCTF VRP cluster, please submit the vulnerability to our [kCTF VRP](https://google.github.io/kctf/vrp.html).

## Legal points

kernelCTF is part of Google VRP, so its rules including but not limited to [these Legal points](https://bughunters.google.com/about/rules/google-friends/google-and-alphabet-vulnerability-reward-program-vrp-rules#legal-points) apply.

You should understand that we can cancel the program at any time and the decision as to whether or not to pay a reward and how much has to be entirely at our discretion.
