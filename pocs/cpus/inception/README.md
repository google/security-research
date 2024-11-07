# Novel Inception/SRSO exploitation method

TL;DR We could exploit SRSO in KVM on AMD Zen 3 and Zen 4 by controlling the
full return address stack (RAS). We did so by injecting a PhantomJMP (which
subsequently injects a PhantomCALL) in the pipeline after a dispatch serializing
instruction.

### Context

The Inception paper reports that on Zen 3 they could only poison one RAS entry
and required a deep call stack to discard the corrected entries. On Zen 4, they
report that they could poison multiple entries but they still needed a deep call
stack to discard the corrected ones. As a result, they could only exploit SRSO
on Zen 4 and they reported that they didn't find a suitable code pattern to
exploit it on Zen 3.

> "Specifically, on Zen 3 microarchitectures we hijack a single return
> instruction by first exhausting 17 uncorrupted RSB entries. On Zen 4, we need
> to exhaust 8 uncorrupted RSB entries, after which we control the next 16
> return target predictions."[^1]

### Problem

We experimented with the findings in the Inception paper and observed that
injecting the PhantomJMP after a dispatch serializing instruction like `rdtscp`,
`lfence`, `cpuid`, `wrmsr`, `invlpga` will preserve all RAS entries injected by
the PhantomCALL and all of them will be used for predicting the following return
instructions. See the code below.

```
cpuid
instr
instr
..
ret
```

If the PhantomJMP collides in the BTB with any of the instructions following
`cpuid`, then the `ret` speculatively executes the gadget injected by the
PhantomCALL. Moreover, all following `ret` instructions will continue
mispredicting from the poisoned RAS entries. We attached a proof-of-concept
implementation of this vulnerability which works on Zen 3 and Zen 4.

We tested it on the following cpus:

-   AMD EPYC 9B14 96-Core Processor ucode(0xa101144)

-   AMD EPYC 7B13 64-Core Processor ucode (0xa0011d1)

### Proof-of-concept

Consider the code above to be the vulnerable code pattern. We train the
PhantomJMP to collide with the `ret` following `cpuid`. The PhantomJMP
destination is the PhantomCALL location. We train the PhantomCALL to collide
with the instruction preceeding the gadget. We find that the requirements
presented in the paper regarding the location and destination of the
PhantomJMP (section 6.3) are not necessary for the exploit to work neither on
Zen 3 nor Zen 4.

poc.c allows you to pass the depth of the call stack in the command line. Before
every return, we shift the flush+reload array by 0x1000 to measure precisely
which return instructions in the call stack mispredicted from the RAS.

### Results

We show that on both Zen 3 and Zen 4 we can control the full RAS.

```
make
./poc 32 # will report hits from entry 0 to 32.
```

To test without the dispatch serializing instruction:

```
make CFLAGS="-DNO_DSI=1"
./poc 32 # will report a few entries > only
```

In our experiments, we added a RSB clearing sequence to see if that would remove
the signal.

```
make CFLAGS="-DMITIGATION -DRSB_DEPTH=8"
./poc 32 # will report hits from entry 0 and 8-32
```

To clear the signal, run the following:

```
make CFLAGS="-DMITIGATION -DRSB_DEPTH=32"
./poc 32 # will report hits on entry #0
```

We didn't clear the signal for the first return in the `a()` execution so a hit
for entry #0 will always show up.

### Root Cause hypothesis

As a result of our analysis, we hypothesize that this vulnerability is possible
because of the special microarchitectural conditions created by the
architectural execution of dispatch serializing instructions. We think that such
instruction brings the RAS in a "clean" state which doesn't trigger the
invalidation of RAS entries injected as a result of PhantomCALL speculation.

### Mitigation

We didn't research what impact does this finding have on safeRET. Given that
this vulnerability happens in microarchitectural conditions created by dispatch
serializing instructions and that such instructions are microcoded, we think AMD
might be able to issue a microcode fix. We confirmed that IBPB mitigates this
issue on Zen 3 and Zen 4.

#### New mitigation discussion

We investigated a potential mitigation for this particular vulnerability, namely
clearing the RSB before the first return instruction that comes after a dispatch
serializing instruction. We used the upstream Linux RSB clearing sequence in our
experiments. We observed that the PhantomJMP can be trained to overlap with one
of the RSB clearing sequence instructions or with the `ret`, therefore the
signal was still present for specific RSB entries. With a 32-entry RSB clearing
sequence, we couldn't observe signal for the first `ret` in the deep call stack
but from the 20th `ret` execution onwards, depending on the depth of the call
stack.

We conclude, based on our experiments, that clearing the RSB before the first
return instruction that executes after a dispatch serializing instruction,
reduces the risk of this vulnerability by hindering the possibility of
controlling the full RSB.

### Impact

Vulnerable function                                                                                                 | Serializing instruction
------------------------------------------------------------------------------------------------------------------- | -----------------------
[kvm_set_user_return_msr](https://elixir.bootlin.com/linux/v6.10.3/C/ident/kvm_set_user_return_msr)                 | wrmsr
[kvm_set_msr_common](https://elixir.bootlin.com/linux/v6.10.3/C/ident/kvm_set_msr_common)                           | wrmsr
[vcpu_enter_guest](https://elixir.bootlin.com/linux/v6.10.3/C/ident/vcpu_enter_guest)                               | wrmsr
[svm_complete_interrupt_delivery](https://elixir.bootlin.com/linux/v6.10.3/C/ident/svm_complete_interrupt_delivery) | wrmsr
[kvm_emulate_wbinvd](https://elixir.bootlin.com/linux/v6.10.3/C/ident/kvm_emulate_wbinvd)                           | wbinvd
[svm_flush_tlb_gva](https://elixir.bootlin.com/linux/v6.10.3/C/ident/svm_flush_tlb_gva)                             | invlpga
[read_tsc](https://elixir.bootlin.com/linux/v6.10.3/C/ident/read_tsc)                                               | rdtscp

We found 7 code patterns (see above) in the upstream Linux KVM implementation
which are potentially exploitable. We have a full exploit for `read_tsc` which
we trigger using `vmmcall` with `rax = KVM_HC_CLOCK_PAIRING`. This was the
easiest to exploit because the guest controls up to three (3) arguments. The
exploit works on AMD Zen 3 and we consider it needs a few small adjustments to
work on AMD Zen 4 as well. We achieved an arbitrary memory read primitive in the
host kernel.

Given the above, we consider the risk assessment section of this recent
[AMD report](https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/white-papers/amd-epyc-9004-wp-srso.pdf)
to be inaccurate.

#### Speculative ROP

We discovered a novel method to control the RAS that allows us to chain gadgets
to construct a disclosure primitive. This method is different from the "Dueling
recursive phantom calls" presented in the Inception paper (Section 7.4).

To inject two gadgets in the RAS, we use two chained recursive PhantomCALLs.

```
gadget1 - 5: PhantomCALL (call gadget2 - 5)
gadget1:
```

```
gadget2 - 5: PhantomCALL (call gadget1 - 5)
gadget2:
```

When `gadget1 - 5` is fetched, `gadget1` is pushed to RAS. Then the cpu starts
fetching at `gadget2 - 5`, according to the first PhantomCALL destination. That
pushes `gadget2` to RAS. Next, the cpu fetches at `gadget1 - 5` again and pushes
`gadget1` to RAS and so on. This results in `gadget1` and `gadget2` to be
interleaved in the RAS.

With this method we could chain up to three (3) gadgets. In our KVM exploit, we
only need to chain two gadgets to achieve a reliable disclosure primitive.

### Disclosure

We are privately disclosing this vulnerability to you so that you can develop a
fix and manage its rollout. We do not require you to keep any information of
this report secret, but if you make it public then please let us know that you
did. This advisory will be kept private by Google for 30 days after a fix is
publicly available or after 90 days if no fix is made. After this deadline we
plan to disclose this advisory in full at:
http://github.com/google/security-research/. Please read more details about this
policy here: https://g.co/appsecurity

Finder: Andy Nguyen of the Google Security Team

Credits: Andy Nguyen, Anthony Weems, Matteo Rizzo, Alexandra Sandulescu

[^1]: https://comsec.ethz.ch/wp-content/files/inception_sec23.pdf
