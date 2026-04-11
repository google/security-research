# Intra-mode BHI

## Summary

We found that BHI can be exploited using very generic code constructs,
that are likely to occur in targets such as Linux kernel. This bypasses
current BHI mitigations, such as BHB untraining, and makes systems vulnerable
to arbitrary memory disclosure.

## Severity

At this point we believe this is a medium severity issue. Exploit development
is difficult, requiring all the steps outlined in the Native BHI paper,
as well as finding good training loop on a path to an indirect jump.

## Proof of concept

We attach code to reproduce the issue (`Makefile, main-for.c, snippet-for.S`)
along with a compiled version in case compiler differences matter.
We were able to reproduce the issue on Skylake (`Xeon(R)
W-2135`) and Cascade Lake (`Intel(R) Xeon(R) Platinum 8273CL`) CPUs.

## Disclosure timeline

We have disclosed this vulnerability to Intel on 2025-01-22.
On 2025-01-29 Intel replied that they believe my report does not
introduce any new practical security concerns and published
Spectre guidance applies.

We were notified that VUSec independently discovered similar issues
in the meantime, though they were still under embargo because of
another variant that Intel deemed exploitable. After discussing
intra-BHI with them, we decided it is close enough to the vulnerable
variant to, out of abundance of caution, delay publishing until
that embargo is lifted on 2025-05-12.

VUSec's report is now public at
[Training Solo](http://vusec.net/projects/training-solo).

## Additional analysis and discussion

### Context

Branch History Injection was first found in
[2022](https://www.usenix.org/system/files/sec22-barberis.pdf).
At the time, it was represented as a variation of BTI, bypassing its
mitigations. The original PoC relied on eBPF to insert
disclosure gadgets using registers as needed, that are targets
of an indirect branch (all eBPF programs are called indirectly).
Exploitation was then just a matter of crafting a colliding history from
userspace, and executing a syscall that performs an indirect branch
(which will then speculate into our prepared gadget).

As a response, unprivileged eBPF programs were disabled. This was, as shown
in [2024](https://www.vusec.net/projects/native-bhi/), not enough, as the
researchers were able to find *native* BHI gadgets - that is, ones that
exist in the kernel on their own, and are actual targets of some indirect branches.
Exploitation is much harder, but using symbolic analysis, the researchers
found thousands of exploitable gadgets.

As a further mitigation, OSs began isolating branch history between
user and kernel - using techniques such as BHI\_DIS\_S or BHB untraining.

### Problem

During our response to the Native BHI vulnerability, we had a few doubts
regarding the proposed mitigations. In particular, we thought that an
attacker could influence a number of branches while already in the kernel
(i.e. after BHB untraining).

For example, we imagined a syscall that takes a `flags` argument and
then checks several bits in a row:

```
if (flags & 1) { ... }
if (flags & 2) { ... }
if (flags & 4) { ... }
```

Intel's position at the time was that it
is statistically unlikely that branches on an architectural path can
give the attacker sufficient control over BHB, unless they have full
control over branches placement, not just their direction (such as using BPF).

We experimented with existing BHI reproducers, and found that we can
force indirect branch prediction collisions using very simple code patterns,
such as a for-loop containing a single conditional:

```
for (i = 0; i < n; i++) {
    if (atkr_arr[i]) { ... }
}
```

We placed a single indirect call at the end of the snippet, and were
able to craft the `atkr_arr` such that the call was mispredicted to a
previously planted gadget.

### Proof of concept description

The PoC has a few parameters, such as maximum history size (the
array length), how much of it (and which part) is controllable by the attacker
etc. We found that the PoC works for history size of 128 even if the attacker
is prevented from controlling a few final branches (and many initial ones).

The PoC is not optimized and may take a few minutes to find collisions. There
are occasional false positives, so each time we find a candidate collision,
we retry it a few iterations later to confirm.

The victim indirect branch that supplies the entry to BTB is always the same:
a chain of N if-statements with a fixed (randomized at startup) direction.
The collider can be chosen among a few options:
- the same chain of N if-statements,
- another chain of N if-statements (out-of-place collision),
- for-loop with an if-statement (two version: assembly and C),
- for-loop with four if-statements (this gives the attacker more freedom while
  still being plausible).

### Discussion

According to the
[Indirector](https://indirector.cpusec.org/index_files/Indirector_USENIX_Security_2024.pdf)
paper, the BTB set index and tag is computed from the branch source address and
the BHB (which they call PHR - Pattern History Register). However, both are
hash functions compressing multiple bits into short keys (about 10 bits
each).

This means that Intel's argument was mistaken - even though the attacker can
only control the direction and not branches' addresses, BHB is folded in
such a way that even that is enough to craft a mostly arbitrary tag and set
(though this depends on exact alignment and addresses of the branches - it
may happen that some BHB values are not reachable, e.g. due to a parity
invariant).

### Potential gadgets in the Linux kernel

We haven't tried implementing a full end-to-end exploit. That said, we thought
how the issue could be exploited in principle. An attacker could, for example,
target the `select` syscall. Its job is to check which of the user-provided
file descriptors are ready (which the attacker can influence easily).

The internal
[implementation](https://github.com/torvalds/linux/blob/master/fs/select.c#L512)
consists, as expected, of a loop iterating over the descriptors, checking
several conditions:

```
for (;;) {
    ...
    mask = select_poll_one(i, wait, in, out, bit, busy_flag);
    if ((mask & POLLIN_SET) && (in & bit)) {
        ...
    }
    if ((mask & POLLOUT_SET) && (out & bit)) {
        ...
    }
    if ((mask & POLLEX_SET) && (ex & bit)) {
        ...
    }
    ...
}
```

This mimics our PoC quite closely. As for the victim indirect branch, the
`select_poll_one` function calls `vfs_poll`, which in turn calls
`file->f_op->poll`, which is a function pointer.

We believe there are many similar code patterns in the Linux kernel,
as well as in other large code bases.

### Mitigation

Current BHI mitigations are effectively a BHB barrier stopping BHB propagation
at the user-kernel boundary. This means they do nothing
to stop intra-BHI.

To mitigate this issue, we would need to completely stop history-based
speculation in the whole OS. One inefficient way to do that would be to
untrain BHB before every indirect branch. Another way is to use controls
such as `IPRED_DIS_S`, which completely stops indirect speculation.

Written by: Adam Krasuski.
