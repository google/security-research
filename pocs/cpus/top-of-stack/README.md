# Unexpected Speculation Control of _RETs_

<p align="right">Alexandra Sandulescu <br/>
Eduardo Vela Nava <br/>
Rodrigo Branco (BSDaemon)</p>

## Introduction

We observed some undocumented (to the best of our knowledge) behavior of the indirect branch predictors, specifically relative to _‘ret’_ instructions. The research we conducted appears to show that this behavior doesn't seem to create exploitable security vulnerabilities in the software we've tested. We would like to better understand the impact and implications for different software stacks, thus we welcome feedback or further research.

Our observations (and tests) indicate that certain microarchitectures decide the destination of a _‘ret’_ instruction based on a different order than first the ‘RSB/RAS’ and then the ‘BTB’.

This behavior was confirmed in the following microarchitectures, other vendors/versions may also have similar behavior.

* Intel Skylake
* Intel Cascade Lake
* AMD Zen 1
* AMD Zen 2

Interestingly, in our tests, we did not observe signals in the following microarchitectures:

* AMD Zen 3

We've seen mixed results on:

* Intel Broadwell

By not observing the signal in our tests we can not rule out the possibility that they are affected. We would like to learn more about the behavior in these and other microarchitectures.

## Details

Returns (ret) are indirect branches that should be predicted from a data structure called RSB (or RAS on AMD).  When the RSB/RAS structure is empty, depending on the microarchitecture and patch level/configuration, the returns might also be predicted from the BTB (the order for the prediction between the RSB/RAS and the BTB might be also different in some microarchitectures, as recently disclosed as part of the RetBleed response[^1]).

While not officially documented/discussed, the work in Spectre v1.1 [^2] indicates that speculative overwrites controlling some other data structure also affect the prediction. The example discussed talks about a speculative overwrite over the return address and how a speculative return uses that value. Our tests indicate that such overwrites are using the store buffer (see Subsection: Speculative top of the stack for more details). But still, an open question remains:  **What other prediction order/conditions exists?**  This matters because mitigations such as retpoline [^3] clearly depend on it to be properly understood (and effective).  Nonetheless, retpoline documentation only discusses RSB/RAS and BTB.

Our experiments confirm the findings of Mambretti et. al [^8], that ‘rets’ also predict from the top of the stack if the contents of it are recently accessed even when *NOT* speculatively overwritten. Given that to prevent an attacker from controlling the destination of a _‘ret’_ (Spectre v2) the recommendation is to perform an IBPB (which flushes the BTB and the RSB), we have common scenarios in which the first _‘ret’_ upon a context switch (between untrusted and trusted entities, such as user to kernel or guest to hypervisor) will actually predict from the recently accessed top of the stack.

What is worse is that in the user to kernel case, the RSB/RAS is thought to not be possible to point to a kernel address (since their entries are only created by _‘calls’_).  With that, SMEP is the mechanism that prevents bad speculation from happening on the user->kernel attack case (via RSB/RAS control)  because only user-space addresses can be trained/injected there.  But in the case of the top of the stack, an entry can be created with a simple _‘push’_ instruction (in fact, many instructions such as _pop_, _sub_, _add_, _leave_, _xchg_), potentially making SMEP ineffective for the observed scenario.  It is also worth noting that deeper (in the control flow) _‘ret’s_ might still have attacker controlled values in the top of the stack (that are recently accessed) due to parameter passing, stack adjustments (such as _subs_ to allocate stack space) and many other software-controlled reasons.

### Architectural Top of the Stack

If the top of the stack is accessed (for example, via a _‘push’_), a speculatively executed _‘ret’_ instruction will actually predict using the value from that location.  A _‘clflush’_ can be added for the negative testing (notice that we still see some hits in some of the microarchitectures, which might support the theory of the usage of store-buffers).  

Here is an example of a test (based on KTF [^5]):


```c
/* Preparing */
flushbtb();
rsbstuff();
clflush(&end_ptr);
lfence();
mfence();

/* Ret speculates via shadow of a branch */
// Uncomment out the clflush (%%rsp) for negative testing
asm goto(".global branch\n"
	"push %%rax\n"
	//"clflush (%%rsp)\n"
	"lfence\n"
	".align 16\n"
	"branch:\n"
	"cmp %%rax, (%%rdi)\n"
	"jnz %l[end]\n"
	"ret\n"
	"nop\n"
	::"a" (&leak_secret),
	"D" (&baseline):
	: end);
// end
end:
	asm volatile(".global _end;_end: nop; pop %rax);
```


### Speculative Top of the Stack

We’ve also compared this to the Spectre v1.1 [^2] case.  In a speculative overwrite, the ‘store buffers’ seem to be used and the _‘ret’_ speculate from them.  Our experiment with the Spectre v1.1 case look like this:


```c
".align 16\n\t"
"SHADOW_BRANCH:\n\t"
"cmp %%rax, (%%rdi)\n\t"
// This branch is always taken
"jnz SHADOW_DEST\n\t"
"sub $0x100, %%rax\n\t"
"mov %%rax, (%%rsp)\n\t"
".align 64\n\t"
"ret\n\t"
// where: rax is the gadget address + 0x100 (to avoid false positives)
// rdi points to a page address that we allocate randomly and will never be       // equal to rax because rax points to a .text address
```


Coincidentally, we got N = 42 for a Broadwell Server and N = 56 for {Skylake Server, Cascadelake}.  From [^4]  we see that one of the changes from Broadwell to Skylake is exactly the increase of the store buffer:  “Larger store buffer (56 entries, up from 42)”

## Conclusion

Speculative and non-speculative paths both leverage the store buffers. That means that other values (recently overwritten, architecturally or speculatively) might be used in ret destination prediction (e.g. nested cases of _‘rets’_).

While this does not seem to be a vulnerability (because we have not yet identified cases in which a compiler would generate vulnerable code) it is an undocumented behavior that might have security implications in some scenarios that we may not have thought of. We welcome feedback or further research.

### Ideas for future work

Here are some examples of code constructs that may be vulnerable due to the behavior we discussed here. We did not test any of these scenarios:



1. interrupted code, interrupts overall (including vmexit and SMI)
2. alloca cases (even though user mode alloca is just an inlined _‘sub rsp_’, in certain conditions ‘RSP’ is architecturally modified in the middle of an execution flow)
    1. gcc use of dynamic arrays (like char array[var]), which use alloca internally
3. dispatch code using function pointers
4. inline assembly
5. goto (apart from error handling use)
6. The ‘Post-barrier RSB Prediction’ issue discovered by Intel [^6] (specifically the case one of Spectre v1.1) might be a _‘call’_ instruction writing to the ‘_store buffer_’ (thus a ret instruction loads the destination through store-to-load-forwarding. RSB filling and IBPB are useless in this case.).  If so, notice that it is not only the last, unbalanced _‘call’_ that could be problematic.

## Acknowledgements

We would like to thank Pawel Wieczorkiewicz from Open Source Security Inc. for his collaboration in this work.  We would like to thank Intel and AMD for the timely response to our inquiry about the findings documented here. We thank the IBM Research System Security group [^7] for their timely feedback.

## Timeline

* July 7 2022 - Initial draft of the advisory sent to Intel and AMD
* July 8 2022 - Initial ack from AMD on the issue
* July 14 2022 - Answer from AMD referencing Spectre v1.1 https://people.csail.mit.edu/vlk/spectre11.pdf
* July 16 2022 - Request from AMD to keep issue secret for 90 days
* July 28 2022 - Answer from Intel referencing Intel whitepaper https://www.intel.com/content/dam/develop/public/us/en/documents/336983-intel-analysis-of-speculative-execution-side-channels-white-paper.pdf
* August 8 2022 - Request from Intel to keep issue secret for "a couple days" to avoid confusion with CVE-2022-28693, and to incorporate Intel's whitepaper on the public advisory
* October 5 2022 - Final draft of the advisory incorporating references provided by Intel and AMD send to Intel and AMD
* October 6 2022 - Public disclosure of advisory
* October 6 2022 - Request from AMD to delete a sentence from advisory `(in case the IBPB instruction does not clear the RAS, as is the case on some AMD microarchitectures)` (which was done while we investigated the reason)
* November 8 2022 - AMD discloses https://www.amd.com/en/corporate/product-security/bulletin/amd-sb-1040 which is a bug collission of the IBPB/RSB bug
* November 21 2022 - Deleted sentence is added back

## References

[^1]: “Retbleed: Arbitrary Speculative Code Execution with Return Instructions”.  Link: [https://comsec.ethz.ch/research/microarch/retbleed/](https://comsec.ethz.ch/research/microarch/retbleed/) 
[^2]: “Speculative Buffer Overflows: Attacks and Defenses”.  Link: [https://people.csail.mit.edu/vlk/spectre11.pdf](https://people.csail.mit.edu/vlk/spectre11.pdf) 
[^3]: “Retpoline: A Branch Target Injection Mitigation”.  Link:  [https://www.intel.com/content/dam/develop/external/us/en/documents/retpoline-a-branch-target-injection-mitigation.pdf](https://www.intel.com/content/dam/develop/external/us/en/documents/retpoline-a-branch-target-injection-mitigation.pdf) 
[^4]: Skylake Server Microarchitecture (Wikichip).  Link:  [https://en.wikichip.org/wiki/intel/microarchitectures/skylake_%28server%29](https://en.wikichip.org/wiki/intel/microarchitectures/skylake_%28server%29)
[^5]: KTF (Kernel Test Framework).  Link:  [https://github.com/KernelTestFramework/ktf](https://github.com/KernelTestFramework/ktf) 
[^6]: “Post-barrier RSB Prediction”.  Link:  [https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00706.html](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00706.html) 
[^7]: IBM System Security. Link: https://researcher.watson.ibm.com/researcher/view_group.php?id=8257
[^8]: Bypassing memory safety mechanisms through speculative control flow hijacks. Link: https://arxiv.org/pdf/2003.05503.pdf
