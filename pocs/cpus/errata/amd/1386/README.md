# XSAVES Instruction May Fail to Save XMM Registers

<p align="right">
Tavis Ormandy <br/>
</p>

## Introduction

AMD Errata 1386 [^1] is a flaw that affects the AMD Zen 2 family of processors.
The observed result of this bug is that changes to xmm or ymm extended
registers during normal program execution may be unexpectedly discarded.

The implications of this flaw will vary depending on the workload.

This errata was fixed in the microcode update released on 2022-08-09 [^2], and
we have confirmed it is not reproducible after patch `0x08301055`.

We have confirmed the bug is reproducible on:

- `Family=0x17 Model=0x31 Stepping=0x00 Patch=0x830104d`

You can verify the current Model, Family, Stepping and microcode level by
examining `/proc/cpuinfo`.

## Details

We have discovered a method of reliably reproducing this errata. To reproduce
the flaw we force `XSAVES` operations with `syscall` transitions, and interpose
those with writes to `ymm` registers. We have found that the `UCOMISS xmm1, m32`[^3]
instruction is a reliable way to trigger the flaw.

We believe this form of the `UCOMISS` instruction is less-commonly used in
practice because there is no compiler intrinsic for it, which may explain why
this method wasn't previously known.

### Reproducing

There are two components to the reproducer.

The program `hammer.c` is used to force frequent context switches, it simply
sets the CPU affinity and then runs `sched_yield()` in a loop.

The program `zenymmasm.asm` is the testcase.

#### Building

```
$ cc -o hammer hammer.c
$ nasm -felf64 -O0 zenymmasm.asm
$ ld -o zenymmasm zenymmasm.o
```

#### Running

The normal expected output of `zenymmasm` should be nuls:

```
$ ./zenymmasm
$
```

If you first run `hammer` and then pin `zenymmasm` to the same core, the result
should be different.

```
$ ./hammer &
$ taskset -c 1 ./zenymmasm
SECRETSECRET
```

### Analysis

The code first writes a fixed value into `ymm0`, then forces a context switch with
`sched_yield()`. The kernel should then use `XSAVES` to save the process state.

```nasm
    vmovdqu         ymm0, [rel secret]      ; Put SECRET value into ymm0
    mov             rax, SYS_sched_yield
    syscall
```

Now we zero `ymm0`, so its previous value should be permanently lost. The
method here is not important, `VZEROALL` or loading some other value are all
acceptable.

```nasm
    vpxor           ymm0, ymm0, ymm0        ; Here the value of ymm0 should be lost
```

The errata is then triggered with the `UCOMISS` instruction. Testing has shown
that the value must be less than 0x800000 to trigger the bug. `UCOMISS` should
only alter the condition flags, and should not change any register values, but
because of this errata the value of `ymm0` will change on the next XRSTOR.

We trigger another XRSTOR with another `sched_yield()`.

```nasm
    ucomiss         xmm0, dword [rel space]
    mov             rax, SYS_sched_yield
    syscall
```

When execution continues, the value of the `ymm` registers should have
reverted, and can be printed or examined in a debugger.

## Conclusion

It is not clear if it is possible to leak data across kernel or process
boundaries, this would likely depend on kernel implementation details.

It is clear that, depending on workload, registers can unexpectedly revert to
previous values. Many standard library routines use the AVX registers for
high performance string processing, so it is plausible that secrets could
accidentally leak or unexpected values cause crashes or other errors.

## References

[^1]: https://www.amd.com/system/files/TechDocs/56323-PUB\_1.00.pdf#page=49
[^2]: https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/
[^3]: Intel® 64 and IA-32 Architectures Software Developer’s Manual Volume 2B.
