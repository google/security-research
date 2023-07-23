---
title: 'Linux Kernel: Spectre-v1 gadgets'
severity: Moderate
ghsa_id: GHSA-m7j5-797w-vmrh
cve_id: CVE-2023-0458
weaknesses: []
products:
- ecosystem: Linux
  package_name: Kernel
  affected_versions: < 6.1.8
  patched_versions: See Additional Info
cvss: null
credits:
- github_user_id: JordyZomer
  name: Jordy Zomer
  avatar: https://avatars.githubusercontent.com/u/17198473?s=40&v=4
- github_user_id: alexandrasandulescu
  name: Alexandra Sandulescu
  avatar: https://avatars.githubusercontent.com/u/2550548?s=40&v=4
---

### Summary
Detected a few exploitable gadgets that could leak secret memory through a side-channel such as MDS as well as insufficient hardening of the usercopy functions against spectre-v1.

### Severity
Moderate - These vulnerabilities could be exploited to leak secret memory.

### Proof of Concept
The gadget is in the ```do_prlimit``` function, which is invoked by a number of syscalls, including the ```getrlimit``` syscall. The code has been commented to better illustrate how we would exploit this weakness; you can see the commented code below.

#### Half Spectre-v1 Gadget prlimit CVE-2023-0458 ####

``` c++
/* make sure you are allowed to change @tsk limits before calling this */
static int do_prlimit(struct task_struct *tsk, unsigned int resource, <------ resource is a syscall argument
		      struct rlimit *new_rlim, struct rlimit *old_rlim)
{
	struct rlimit *rlim;
	int retval = 0;
 
	if (resource >= RLIM_NLIMITS) <------ we speculatively bypass this branch NOT taken.
		return -EINVAL;
	if (new_rlim) {
		if (new_rlim->rlim_cur > new_rlim->rlim_max)
			return -EINVAL;
		if (resource == RLIMIT_NOFILE &&
				new_rlim->rlim_max > sysctl_nr_open)
			return -EPERM;
	}
 
	/* Holding a refcount on tsk protects tsk->signal from disappearing. */
	rlim = tsk->signal->rlim + resource; <------ resource gets added to a pointer, we now  control an arbitrary offset of 0-4294967295 from tsk->signal->rlim
	task_lock(tsk->group_leader);
	if (new_rlim) {
		/*
		 * Keep the capable check against init_user_ns until cgroups can
		 * contain all limits.
		 */
		if (new_rlim->rlim_max > rlim->rlim_max &&
				!capable(CAP_SYS_RESOURCE))
			retval = -EPERM;
		if (!retval)
			retval = security_task_setrlimit(tsk, resource, new_rlim);
	}
	if (!retval) {
		if (old_rlim)
			*old_rlim = *rlim; <------ pointer gets dereferenced and the secret value has been loaded in the internal buffers of the CPU
		if (new_rlim)
			*rlim = *new_rlim;
	}
```

By combining this issue with a side-channel, such as Microarchitectural Data Sampling (MDS), we can leak secret kernel memory because the value of the arbitrary pointer is loaded into internal CPU buffers once it is dereferenced. We verified that the speculation window is large enough by making a duplicate of the code and sending a cache-signal to a userspace argument "probe" after the pointer dereference. In this manner, we can validate that the speculation window reaches the pointer-dereference of `rlim` when the CPU misspeculates the boundary check on the `resource` variable. As a result, we observe a cache-hit on our `probe` pointer. A copy of our kernel module to verify this has been added as an attachment. [Recent research](https://download.vusec.net/papers/kasper_ndss22.pdf) shows that an MDS gadget is exploitable with the default mitigation enabled i.e. `mds=full`. The XI.C section describes an experiment with two co-located threads, one that triggers the vulnerability through a syscall and one that reads the signal using MDS. They claim that they “verified that a signal exists if the loads are happening approximately at the same time in both threads, leaking the secret from a kernel buffer to user space”. 

After the bounds check on the `resource` parameter, we recommend adding a call to `barrier_nospec` to address this concern.


#### Spectre-v1 Usercopy Hardening CVE-2023-0459 ####

Another concern regarding spectre-v1 was detected in the usercopy functions, specifically on x86_64.  In the past there has been some hardening to functions that deal with memory from user-space. For example, the mitigation for `copy_from_user` on 32-bits calls `__uaccess_begin_nospec` which is essentially the same as `barrier_nospec`. 

On 64-bits, however, we were unable to locate a comparable mitigation, so the `copy_(to|from)_user` methods do not implement a barrier on 64-bits. Calls to `__uaccess_begin_nospec` were previously present, but they seem to have been mistakenly removed in [this commit](https://github.com/torvalds/linux/commit/4b842e4e25b12951fa10dedb4bc16bc47e3b850c) while switching to `raw_copy_from_user`.

The relevant code artifacts that seem to be missing the barriers are the following:

https://github.com/torvalds/linux/blob/5dc4c995db9eb45f6373a956eb1f69460e69e6d4/arch/x86/lib/copy_user_64.S#L53
https://github.com/torvalds/linux/blob/5dc4c995db9eb45f6373a956eb1f69460e69e6d4/arch/x86/lib/copy_user_64.S#L126
https://github.com/torvalds/linux/blob/5dc4c995db9eb45f6373a956eb1f69460e69e6d4/arch/x86/lib/copy_user_64.S#L162
https://github.com/torvalds/linux/blob/5dc4c995db9eb45f6373a956eb1f69460e69e6d4/arch/x86/lib/copy_user_64.S#L273 


This worries us because a user is able to speculatively bypass the `access_ok` check and pass a kernel pointer to `copy_(to|from)_user`, which might then be used to exfiltrate information through additional side-channels such as MDS or variant 3a. This was also verified by sending a cache-signal through a probe variable, however we observed less cache-hits than the `do_prlimit` gadget. Our hypothesis is that this is caused by additional memory access checks that follow the `stac` instruction, which slow down execution, or by a smaller speculation window, but results may vary on different systems.

Adding a `lfence` instruction after the `ASM_STAC` instructions in `arch/x86/lib/copy_user_64.S` is our suggested solution to this issue.

Additionally, there’s also other functions which are missing barriers such as `clear_user` and `put_user`, which could use the same resolution. 

Because there are no barriers with `put_user` and `clear_user` problems could still occur if `access_ok` is speculatively bypassed in ways similar to those in the previous example.

The relevant code artifacts can be found below.

put_user:
https://github.com/torvalds/linux/blob/5dc4c995db9eb45f6373a956eb1f69460e69e6d4/arch/x86/lib/putuser.S#L50
https://github.com/torvalds/linux/blob/5dc4c995db9eb45f6373a956eb1f69460e69e6d4/arch/x86/lib/putuser.S#L60
https://github.com/torvalds/linux/blob/5dc4c995db9eb45f6373a956eb1f69460e69e6d4/arch/x86/lib/putuser.S#L72
https://github.com/torvalds/linux/blob/5dc4c995db9eb45f6373a956eb1f69460e69e6d4/arch/x86/lib/putuser.S#L82
https://github.com/torvalds/linux/blob/5dc4c995db9eb45f6373a956eb1f69460e69e6d4/arch/x86/lib/putuser.S#L94
https://github.com/torvalds/linux/blob/5dc4c995db9eb45f6373a956eb1f69460e69e6d4/arch/x86/lib/putuser.S#L104
https://github.com/torvalds/linux/blob/5dc4c995db9eb45f6373a956eb1f69460e69e6d4/arch/x86/lib/putuser.S#L116
https://github.com/torvalds/linux/blob/5dc4c995db9eb45f6373a956eb1f69460e69e6d4/arch/x86/lib/putuser.S#L129 


clear_user:
https://github.com/torvalds/linux/blob/c1649ec55708ae42091a2f1bca1ab49ecd722d55/arch/x86/include/asm/uaccess_64.h#L97 


We recommend imposing the proper barriers, such as adding a `lfence` instruction or the `barrier_nospec` macro to address both of these problems.




### Further Analysis
[prlimit](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/diff/kernel/sys.c?id=v6.1.8&id2=v6.1.7)
[usercopy](https://github.com/torvalds/linux/commit/74e19ef0ff8061ef55957c3abd71614ef0f42f47)

## Backports
[prlimit](https://kernel.dance/#739790605705ddcf18f21782b9c99ad7d53a8c11)
[usercopy](https://kernel.dance/#74e19ef0ff8061ef55957c3abd71614ef0f42f47)


### Timeline
**Date reported**: 01/18/2023
**Date fixed**: See additional info
**Date disclosed**: 04/18/2023

### Additional Info 
CVE-2023-0458 has been addressed in 6.1.8:

https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/diff/kernel/sys.c?id=v6.1.8&id2=v6.1.7

CVE-2023-0459 has been addressed in the following commit:

https://github.com/torvalds/linux/commit/74e19ef0ff8061ef55957c3abd71614ef0f42f47

### SMAP Effects on Exploitation
We were made aware of previous attempts to exploit the exact gadgets described above by the [VUSec](https://www.vusec.net/) and [ETH COMSEC](https://comsec.ethz.ch/) research groups. The following papers [RIDL: Rogue In-Flight Data Load](https://mdsattacks.com/files/ridl.pdf) and [Assessing the Security of Hardware-Assisted Isolation Techniques](https://d-nb.info/120658873X/34) discuss the behavior pointed out to us, namely that enabling access to userspace memory in the supervisor has potentially serializing effects or acts as a memory barrier. Therefore, the branch speculation that starts before `stac` could stop before the attacker-controlled dereference. Indeed in our experiments we moved the `stac`/`clac` instructions outside of the speculation window (we execute `uaccess_begin` before the `access_ok` check and `uaccess_end` after the `access_ok` check `if` body) which is almost equivalent to disabling SMAP, like RIDL describes.

Nevertheless, the feedback we received from Linux was a positive one because the SMAP instructions happen to be serializing but are not guaranteed to be according to the Intel and [Linux documentation](https://docs.kernel.org/admin-guide/hw-vuln/spectre.html#id1). The gadgets we found are still exploitable on systems that do not enable SMAP.

We thank Johannes Wikner and Cristiano Giuffrida for their effective and timely feedback. We also thank Rodrigo Branco for his help and feedback. We welcome such feedback and invite the community to test our results and build on top of our findings.

#### Experiment
`stac` stops a mispredicted path. We designed the experiment in a similar way as the `copy_from_user` gadget. For convenience, we used a slow load for the first branch resolution.

We ran the following experiment:
```
flush(ptr1);
flush(ptr2);
lfence();

for (i = 0; i < 4096; ++i) {
  asm volatile(“nop”);
}

if (*ptr1 < CONSTANT) {
  stac
  if (*ptr2 == ANOTHER_CONSTANT) {
    access_probe();
  }
  clac
}

```
We force mispeculation on both branches by running the code in a loop and only triggering “not taken” architecturally in the last iteration of the loop.

The result of the experiment is that we get no probe hits if the `ptr1` load happens before `stac`, and when both `ptr1` and `ptr2` loads happen before `stac`. If we change the code and move `stac` outside the loop (essentially both loads happen after `stac`), we get a very high success rate. The experiments show that `stac` acts as a memory barrier. We did not experiment further to understand if `stac` influences speculation that is not triggered by slow branch operands resolution.

We tested only on two Intel CPU models, Broadwell and Cascade Lake. We plan to test on other microarchitectures since Intel documentation seems to imply that the `stac`/`clac` behavior is not consistent.