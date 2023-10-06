# kvmCTF rules

kvmCTF is a part of the [Google VRP](https://bughunters.google.com/about/rules/6625378258649088/google-and-alphabet-vulnerability-reward-program-vrp-rules) and is focused on making exploiting Kernel-based Virtual Machine (KVM) vulnerabilities harder by inviting security researchers to demonstrate their exploitation techniques on 0-day and 1-day vulnerabilities on LTS kernel versions. Eventually we might add experimental mitigations to KVM that we would like to see if and how researchers can bypass them.

We are asking researchers to publish their submissions, helping the community to learn from each other’s techniques.

# Reward structure and targets

## Target

### Exploit for the LTS server
This instance uses the latest LTS kernel version (currently 6.1) with the [COS kernel config](https://cos.googlesource.com/third_party/kernel/+/refs/heads/cos-6.1/arch/x86/configs/lakitu_defconfig) but with `CONFIG_KVM=m`.
The host runs on an Intel(R) Xeon(R) Gold 5222 CPU @ 3.80GHz. \
Participants will be connected to a Debian 11.7 (bullseye) guest that runs on a `v5.10.0-25` kernel compiled with the default Debian config. \
The goal is to perform a successful guest-to-host attack. Currently we do not reward QEMU exploits or vulnerabilities.

#### Rewards
* Full VM Escape: $99,999
* Arbitrary (host) memory write: $34,999
* Arbitrary (host) memory read: $24,999
* Host Denial-of-Service: $14,999

Note that the above rewards do not stack. For example if you submit a full VM
escape exploit that uses an arbitrary memory write, you will be compensated with the
reward for the VM escape ($99,999) and not with two separate rewards ($99,999 +
$34,999).

### Process
To try your exploit on our server you will have to reserve a time slot. You can do it using the command:

`ssh kvmctf@kvmctf.vrp.ctfcompetition.com`

and follow the prompts. Note that the reservations are done using the UTC time so please convert your desired time to UTC before reserving. You will need to provide an email address and you will be given a key. \
To connect to the server during your reserved time slot you can use the same command as above. You will be asked to provide the email address you used to reserve the time slot and the key you received. After verification, you will be redirected to the server.

## Additional eligibility rules
Only the first submission for a vulnerability is eligible for a reward.
If a patch commit fixes multiple vulnerabilities (e.g. by backporting a new version of a component to the stable tree), we assume the root cause is the same and we consider further submissions as duplicates.
If the same vulnerability is fixed in multiple patch commits (e.g. in commit A in the mainline tree and separately in commit B in the stable tree), then we still consider it as the same vulnerability, thus making further submissions duplicates.

# Submission process
Note: Minor details of the submission process may change from time to time, please make sure you check this page again for updates when you make a new submission.
Submissions can target 0-day and 1-day bugs.
## Non-patched and 0-day submissions
We consider a bug 0-day if at the time of the submission:
* There is no patch commit in the mainline tree, and
* The vulnerability is not disclosed in any form (e.g. there is no Syzkaller report about the bug)
    * Note: We may still consider a bug 0-day at our discretion (e.g. although the bug was disclosed by Syzkaller more than 30 days ago, there is no fix and you convince the maintainers to fix the bug)

If the submission targets a bug which is not patched yet (0-day or 1-day without a patch), then the submission process has one additional initial stage. \
The purpose of this additional stage is to make sure the vulnerability details are not shared with us before the patch is released but to still provide a 7-days long “protection window” for 0-day vulnerability founders in case some else makes a 1-day submission for the same vulnerability before the 0-day founder. \
In this stage:
1. Exploit the bug and capture the flag from the target environment (the flag is a proof of successful exploitation).
2. Compress the exploit and its source code as a .tar.gz file and calculate its SHA256 checksum.
   * Save this exact file, you will need to send us this later.
   * Try to keep this file to the minimum necessary, leave out large files like e.g. vmlinux, bzImage as they can be downloaded separately if needed.
3. Submit the flag and the hash via [this form](https://forms.gle/Hu5EuMPieWHRdqXi8) with the additional details requested.
   * Save the link as you’ll have to edit this form later.
4. Report the vulnerability to security@kernel.org within 7 days of the first form submission.
   * Note: A submission will be considered ineligible if it turns out that this requirement was not respected.
5. Make sure that you are credited in the Reported-By tag of the patch that fixes the bug.
   * Use the same email address in the Reported-By tag as you use for the form submission or in the “Email address used in Reported-By tag” field of the form.
   * If there is no Reported-By tag on a patch commit, then a 0-day submission is eligible only if this is the first 0-day submission for that patch commit (based on the first stage submission date).
   * If it is unclear who reported the bug, then the 0-day bonus can be split (multiple reporters), reduced, invalidated or the 0-day submission protection can be lost at our discretion.
6. Wait for the patch to land in a release candidate on the mainline tree (and tagged in Git), or committed on a stable tree.
7. Modify the form within 7 days by following the previously saved link and fill out the extra details as described below in the 1-day section.
   * If the 7-day deadline is missed, then the first stage 0-day protection expires and other 1-day submissions can take priority over this submission (which makes this submission a duplicate and thus ineligible for reward).

A submission will not be eligible as a 0-day submission if the vulnerability details were reported somewhere (e.g. Pwn2Own) other than [security@kernel.org](mailto:security@kernel.org).

## Already patched, 1-day submissions

1. Exploit the bug and capture the flag from the target environment (the flag is a proof of successful exploitation).
2. Submit the requested vulnerability details via [this form](https://forms.gle/Hu5EuMPieWHRdqXi8) (without including additional details on the exploitation technique for now).
3. Send us the description of the vulnerability via [bughunters.google.com](https://bughunters.google.com/) (please follow the process described below).
4. Wait for us to publish the CVE or publish the vulnerability details yourself on [oss-sec](https://seclists.org/oss-sec/).
   * If you’d like to speed up the CVE publication process, please make sure you fill out all the details needed for the CVE when you fill out the form. This way the disclosure happens earlier and your submission will be processed faster.
5. After the vulnerability is disclosed via a CVE or oss-sec, wait 30 days (recommendation, see notes below) and send us your exploit with the description of the exploitation technique via a PR to https://github.com/google/security-research/ (see required structure below).
6. Make sure that the PR is merged (this is a requirement to get a reward).

## Note about making the exploit public
You can publish your exploit at any time you would like to, but we recommend publishing the exploit 30 days after the vulnerability was disclosed. This gives the industry time to apply patches. Read our stance on the topic in [Google’s disclosure policy](http://about.google/appsecurity).

We only process submissions after the exploit is public (and we can only issue rewards when the submission was processed), but not sooner than 30 days after the vulnerability disclosure.

If you publish sooner than 30 days, you won’t get the reward faster. If you want to delay the publication (disclose later than 30 days), you could do that, but you would get the money later (we want to encourage you to publish the exploit details sooner than later).

The above is about the exploit itself, not the vulnerability. We automatically share some limited vulnerability details of the submissions on our [public submission spreadsheet](https://docs.google.com/spreadsheets/d/e/2PACX-1vS1REdTA29OJftst8xN5B5x8iIUcxuK6bXdzF8G1UXCmRtoNsoQ9MbebdRdFnj6qZ0Yd7LwQfvYC2oF/pubhtml?gid=2095368189), as a CVE, and as soon as you submit the vulnerability details via the form.

## Exploit PR file structure
The submission should be put into the `pocs/linux/kvmctf/<cve>/` folder within the [security-research](https://github.com/google/security-research/) repo, where:
* cve is the CVE number of the vulnerability in the format `CVE-yyyy-NNNNN`
* If there is a conflicting submission, then append `_2` (or `_3`, etc.) after the directory name.

For example: `pocs/linux/kvmctf/CVE-2023-1872/`.

The structure of this submission folder should be:
* `original.tar.gz`
  * Required, contains the original exploit. Its hash must match the one submitted initially via the form (this hash cannot be modified later).
* `metadata.json`
  * Required, structured metadata information following this [JSON schema (version 2)](https://google.github.io/security-research/kvmctf/metadata.schema.v1.json).
* `docs/vulnerability.md`
  * Required, description of the vulnerability.
* `docs/exploit.md`
  * Required, description of how the exploits work. If exploits are too different, then it can also be put next to exploits.
* `exploit/6.1.x/`
  * `exploit.c`
    * Required, source code of the exploit.
  * `exploit`
    * Required, compiled exploit which stole the flag.
  * `Makefile`
    * Required, includes target (`exploit`) to compile exploit.c into exploit and target (`run`) to run the exploit on the live instance (which steals the flag).

You can add additional files (e.g. images for writeup or supporting libraries for the exploit). The exploit can be split into multiple files, although we prefer if it is kept as a single `.c` file.
# Documentation requirements
## Vulnerability
If possible please include the following information in the vulnerability details:
* Commit which introduced the vulnerability
* Commit which fixed the vulnerability
* Affected kernel versions
* Cause (UAF, BoF, race condition, double free, refcount overflow, etc)
## Exploit
Make sure that the exploit is properly commented and the accompanying exploit.md includes all the details, making it easy to understand what the exploit does.

Give a step-by-step overview of the exploitation process. When describing the following activities, include them as a separate step:
* Triggering a vulnerability.
* Converting one attack primitive into another.
* Spraying or grooming the heap.
* Leaking host information.
* Overwriting host memory.
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
  * E.g. `data[0x8] = base + 0x123456;` -> data variable contains a fake `struct file`, the field at 0x8 offset is a `f_inode` pointer which is set to ...
* Usage of multi-threading (or forking)
  * Why is it needed?
  * If a race condition is exploited, then what code paths are raced.
  * Communication and synchronization between two the threads (e.g. what data was sent between the threads, and when the threads are waiting on each other).
* Separation between code parts which are needed to trigger the vulnerability and parts which are part of the exploitation process (spraying, heap grooming, cross-cache, converting one primitive to another).
* Any action (e.g. MSR update, hypercall) where a side-effect of the action is used for the exploit and not the main functionality, for example:
  * Hypercall used for spraying a specific structure, not for its main purpose.
  * Change of some MSR value with a non-trivial effect.

If possible, also include how stable your exploit is (e.g. it worked 90% of the time during your testing) and whether your exploit requires a separate kASLR leak (or bruteforce).
# Additional information
## Program change notifications and communication
We announce major program changes on [Google’s Security Blog](https://security.googleblog.com/), but we may change minor, mostly technical details (like steps in the submission process) by changing this page and announcing the change on our #kvmctf-announcements Discord channel.

If you have any question regarding kvmCTF, feel free to ask on the #kvmctf Discord channel.
