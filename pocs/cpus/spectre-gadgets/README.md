# Finding Gadgets for CPU Side-Channels with Static Analysis Tools
<p align="right">
Jordy Zomer<br/>
Alexandra Sandulescu
</p>

## About
We have recently begun research on using static analysis tools to find Spectre-v1 gadgets. During this research, we discovered two gadgets, one in `do_prlimit` (CVE-2023-0458) and one in `copy_from_user` (CVE-2023-0459). In this writeup, we explain these issues and how we found them.
## Details
Finding useful gadgets is one of the challenges[^1] in (CPU) side-channel exploitation. We started looking at Spectre-v1 gadgets because there is no comprehensive mitigation for such gadgets, and the current solution is to manually remove them from the kernel code[^6].

There are a variety of ways to find these issues, but we wanted to explore CodeQL. CodeQL[^2] is a query language developed by GitHub to query a semantic analysis engine for static code analysis. In CodeQL, code and relationships between its elements are represented in a database. Security vulnerabilities, bugs, and other issues are represented as the results of queries that may be executed on code-retrieved databases. Queries that discover potential vulnerabilities display the outcome in the source file. As a result, it is a tremendously strong tool for purposes such as variant analysis and the like. This paper assumes some familiarity with CodeQL. See https://codeql.github.com/docs/writing-codeql-queries/ql-tutorials/ for an introduction.

The reason we decided to use CodeQL is because it provides excellent DataFlow analysis capabilities. We were looking for data flows from user-controlled values that are guarded by a branch and used in either array-offsets or pointer-arithmetic operations where the corresponding memory location is later dereferenced. This pattern is of interest because an adversary can trigger the taken code path speculatively and then control a kernel pointer whose value will be loaded later. We are looking for dereferences of that memory location so that we can use MDS (Microarchitectural Data Sampling) to leak the data.

According to recent research[^1], a MDS gadget can be exploited even with the default mitigation set to `mds=full`[^3]. The experiment with two co-located threads is described in the XI.C section of the paper. One thread uses a syscall to exploit the vulnerability, while the other thread reads the signal using MDS. According to their statement, they "verified that a signal exists if the loads are happening roughly at the same time in both threads, leaking the secret from a kernel buffer to user space."
### Query
The CodeQL query that we wrote finds data-flows from user-controlled sources such as arguments to function-calls where the function pointer is stored in a struct that is either ending in `ops` or `_operations`, arguments from system calls or the destination of `copy_from_user` or `get_user` to either array-offsets or pointer-arithmetic expressions followed by a dependant load. Below you will see the query, including documentation.

```codeql
/**
 * @name SpectreV1
 * @description Finds potential spectre v1 gadgets
 * @kind path-problem
 * @problem.severity warning
 * @id cpp/linux-spectre-v1
 */

import cpp
import semmle.code.cpp.ir.IR
import semmle.code.cpp.ir.dataflow.TaintTracking
import semmle.code.cpp.ir.dataflow.DataFlow
import semmle.code.cpp.controlflow.Guards
import semmle.code.cpp.ir.dataflow.internal.DataFlowUtil
import semmle.code.cpp.valuenumbering.GlobalValueNumbering
import DataFlow::PathGraph

// used to find flows to memory loads depending on source
predicate flowsToMemoryLoad(DataFlow::ExprNode source, DataFlow::Node sink) {
  exists(LoadInstruction out |
    out.getSourceAddressOperand() = sink.asOperand() and
    DataFlow::localFlowStep(source, sink)
  )
}

// used to find user-controllable sources
predicate isUserLandInput(DataFlow::Node node, string cause) {
  // arguments to function-pointers in _ops or _operations structs are probably user-input
  exists(Struct s, Function func, Field f |
    s.getQualifiedName().regexpMatch(".*_ops|.*_operations") and
    f = s.getAField() and
    f.getType() instanceof FunctionPointerType and
    f.getAnAssignedValue() = func.getAnAccess() and
    node.asParameter() = func.getAParameter() and
    cause = func.getName()
  )
  or
  // arguments to ioctl calls or syscalls are probably user-input
  exists(Function func |
    func.getName().regexpMatch(".*ioctl.*|__do_sys_.*") and
    node.asParameter() = func.getAParameter() and
    cause = func.getName()
  )
  or
  // the destination of copy_from_user or get_user is probably user-input
  exists(FunctionCall fc |
    fc.getTarget().getName().regexpMatch(".*copy_from_user|get_user") and
    fc.getArgument(0) = node.asDefiningArgument() and
    cause = fc.getTarget().getName()
  )
}

// finds dataflow from user-controlled sources to an array-index
// which is later used in a load-instruction
class UserArrayIndexConfig extends TaintTracking::Configuration {
  UserArrayIndexConfig() { this = "User-controlled to array index" }

  // our taint-source is data coming from user-space
  override predicate isSource(DataFlow::Node source) { isUserLandInput(source, _) }

  // our taint-sink is either an array-offset or pointer-arithmetic where there's a memory load depending on the sink afterwards
  override predicate isSink(DataFlow::Node sink) {
    exists(ArrayExpr ae | sink.asExpr() = ae.getArrayOffset().getAChild*())
    or
    exists(PointerArithmeticOperation pao | sink.asExpr() = pao.getAnOperand().getAChild*()) and
    flowsToMemoryLoad(sink, _)
  }

  // if the node flows through array_index_nospec() it's safe
  override predicate isSanitizer(DataFlow::Node node) {
    exists(MacroInvocation mi |
      mi.getMacroName() = "array_index_nospec" and
      mi.getAnExpandedElement() = node.asExpr()
    )
  }
}

from
  UserArrayIndexConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink, GuardCondition gc,
  GVN gv
where
  // source must have a flow path to sink
  cfg.hasFlowPath(source, sink) and
  // using global value numbering to find other expressions
  // to in which the sink node is used, so that we can figure out
  // if our array-access is bounded by its index
  gv.getAnExpr() = sink.getNode().asExpr() and
  // check if our sink is guarded by a branch that we can speculatively bypass
  gc.comparesLt(gv.getAnExpr(), _, _, _, _) and
  gc.controls(sink.getNode().asExpr().getBasicBlock(), _)
select sink.getNode(), source, sink, "possible spectre-BCB gadget"
```
### Results
#### Gadget in do_prlimit
The first gadget we discovered is in the `do_prlimit` function, which is called by several syscalls, including the `getrlimit` syscall. The code has been annotated to better demonstrate how we would exploit this weakness; the commented code is shown below.

```c
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
	rlim = tsk->signal->rlim + resource; <------ resource gets added to a pointer, we now  control an arbitrary offset of 0-4294967295 from tsk->signal->rlim.
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
			*old_rlim = *rlim; <------ pointer gets dereferenced and our secret value has been loaded in the internal buffers of the CPU.
		if (new_rlim)
			*rlim = *new_rlim;
	}
```

We now walk through this example in more detail, we can control the value of the `resource` argument. This number is later utilized in pointer arithmetic in the `rlim` variable, which can have an arbitrary offset in the range `0-4294967295` because we bypass the following branch.

```c
if (resource >= RLIM_NLIMITS) <------ we speculatively bypass this branch NOT taken.
	return -EINVAL;
```

When the pointer is dereferenced with the following code, we can leak the contents of the rlim variable since we are in control of the address in the variable.

```c
if (old_rlim)
	*old_rlim = *rlim; <------ pointer gets dereferenced and our secret value has been loaded in the internal buffers of the CPU.
```

By combining this issue with a side-channel, such as Microarchitectural Data Sampling (MDS), we can leak secret kernel memory because the arbitrary pointer value is loaded into internal CPU buffers once it gets dereferenced. You’ll find more information about how we verified this gadget in the verification section. This issue has been addressed in the following commit:

https://github.com/torvalds/linux/commit/739790605705ddcf18f21782b9c99ad7d53a8c11

The problem was solved by using the `array_index_nospec` macro. If the CPU speculates past the bounds check, `array_index_nospec()` will clamp the resource value between `0` and `RLIM_NLIMITS`.
### Gadget in copy_from_user
The second gadget we discovered was in the copy_from_user function, specifically on x86_64.  In the past there has been some hardening to functions that deal with memory from user-space, on 32-bits this is mitigated by calling __uaccess_begin_nospec which is essentially the same as barrier_nospec. 

On 64-bit architectures, however, we were unable to locate a comparable mitigation, so it appears that the copy_from_user function doesn’t implement a barrier on 64-bits. 

This is an issue because a user can speculatively bypass the access_ok check and pass a kernel pointer to copy_from_user, which might then be used to exfiltrate information through MDS. This was also verified by sending a cache-signal through a probe variable, however we received less cache-hits than the do_prlimit gadget. Our hypothesis is that this is caused by additional memory access checks that follow the stac instruction, which slow down execution, or by a smaller speculation window, but results may vary on different systems.  The is issue has been addressed in the following commit:

https://github.com/torvalds/linux/commit/74e19ef0ff8061ef55957c3abd71614ef0f42f47

The commit message also gives a great summary of the implications of this issue. However, it appears from copy_from_user's disassembly that arbitrary loads of controlled pointers were already happening before the patch. This enables an adversary to read the values through a side channel that doesn't necessarily call for a subsequent victim action like do_something_with but instead only requires probing the microarchitectural components MDS-style. 

The problem was solved by adding a call to barrier_nospec after the access_ok check, which ensures that the pointer is a valid user-space pointer before passing it to raw_copy_from_user.
### Verification
We verified that both gadgets can be triggered speculatively by sending a cache signal to the userspace process (adversary). We simplified the tests through a patch that adds one more parameter representing the “probe-variable” which is a userspace pointer. We flush the probe prior to calling the function containing the gadget and subsequently speculatively access the probe as part of the gadget execution. We repeatedly call the respective syscall from userspace with a valid branch operand that exercises the code path containing the controlled dereference with a valid pointer. When an uncached invalid branch operand is passed, the CPU speculates the same code path which eventually accesses the probe variable after the arbitrary pointer dereference. We consider the gadget to be exploitable if the probe access-time falls below a given threshold, indicating that the speculation window is large enough (this could vary on different systems) to fit the arbitrary dereference.

For simplifying the verification, we disabled SMAP. Furthermore we explored the exploitability of the gadgets with  SMAP enabled [^7] but we concluded that `stac` prevents the speculative memory dereference on the mispredicted path.

## Conclusion
In conclusion, we discovered two confirmed half Spectre-v1 gadgets and quite a few yet unverified results (that will be addressed in a future report) in the Linux kernel. As shown in previous research on this topic, the gadgets can lead to cross privilege arbitrary memory read. As a result of our report, the Linux security team mitigated the two gadgets in the most recent Linux kernel version. Although we believe there is still much work to be done, we are excited to continue our research on using static analysis techniques to identify (half) Spectre-v1 gadgets since we believe this is a promising approach for discovering and fixing these problems. Furthermore, we are welcoming feedback and are eager to discuss and compare different approaches for discovering gadgets.
## Acknowledgements
We would like to thank Adam Krasuski and Rodrigo Branco (BSDaemon) for their contribution to our research. Their help and support was invaluable, and we could not have completed this project without them. We would also like to thank the Linux kernel security team for their quick and good collaboration. They were always responsive and helpful, and we are grateful for their assistance.

## References

[^1]: “KASPER: Scanning for Generalized Transient Execution Gadgets in the Linux Kernel”, Link: https://download.vusec.net/papers/kasper_ndss22.pdf
[^2]: CodeQL, Link: https://codeql.github.com/
[^3]: MDS command line configuration, Link: https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/mds.html#mitigation-control-on-the-kernel-command-line
[^4]: RIDL: Rogue In-Flight Data Load, Link: https://mdsattacks.com/files/ridl.pdf
[^5]: Assessing the Security of Hardware-Assisted Isolation Techniques, Link: https://d-nb.info/120658873X/34
[^6]: https://docs.kernel.org/admin-guide/hw-vuln/spectre.html#id1
[^7]: https://github.com/google/security-research/security/advisories/GHSA-m7j5-797w-vmrh
