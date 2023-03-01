# XGETBV is non-deterministic.

<p align="right">Tavis Ormandy (taviso)</p>

## Introduction

> This document is a work in progress, documenting a behaviour under investigation.

The XGETBV instruction reads the contents of an internal control register, it
is not a privileged instruction and is usually available to userspace. The
conntents is also exposed via the header in the XSAVE structure.

The primary use of XGETBV is determining the "XINUSE" state, which allows
kernels and userspace threads to determine what CPU state needs to be swapped
out or restored on context switch. However, it is been observed that this state
appears to be non-deterministic on various Intel CPU families.

It is not clear what the consequences of this is are, or if this is security
relevant.

We are not the first team to observe this non-determinism, the RR project have
also noticed this behaviour. [^1]

## Reproducing

We have found a good way to reproduce this issue is with `VSQRTSS` followed by
`VZEROALL`, by running this in a loop we can see the value of the XINUSE flags
fluctuate for no apparent reason.

If we artificially increase context switching, we see the value fluctuating
rapidly.

First, compile the testcase with `-mavx`

```
$ cc -mavx xgetbv.c -o xgetbv
```

If you run the testcase on an affected machine, you should see
non-deterministic results:

```
$ ./xgetbv
first execution, our flags: 0000000000
After 172775235 tests, our XINUSE was 0000000002 vs 0000000000
$ ./xgetbv
first execution, our flags: 0000000000
After 5620219 tests, our XINUSE was 0000000002 vs 0000000000
$ ./xgetbv
first execution, our flags: 0000000000
After 700881 tests, our XINUSE was 0000000002 vs 0000000000
$ ./xgetbv
first execution, our flags: 0000000000
After 169544692 tests, our XINUSE was 0000000002 vs 0000000000
$ ./xgetbv
first execution, our flags: 0000000000
After 113335157 tests, our XINUSE was 0000000002 vs 0000000000
```

If you also artificially induce context switching between another process, the
average number of tests required reduces:

```
$ cc -mavx hammer.c -o hammer
$ ./hammer &
[1] 2775472
$ ./xgetbv 
first execution, our flags: 0000000000
After 722148 tests, our XINUSE was 0000000002 vs 0000000000
$ ./xgetbv 
first execution, our flags: 0000000000
After 705312 tests, our XINUSE was 0000000002 vs 0000000000
$ ./xgetbv 
first execution, our flags: 0000000000
After 473381 tests, our XINUSE was 0000000002 vs 0000000000
```

However, if you make this other process not use avx, then the average number of
tests required does not reduce.

```
$ cc hammer.c -o hammer-noavx
# Note: remember to stop any existing hammer process
$ ./xgetbv
first execution, our flags: 0000000000
After 9348279 tests, our XINUSE was 0000000002 vs 0000000000
```

Note that the number of tests is an order of magnitude difference, while there
are fluctuations this appears to be reliable.

It seems that you can determine whether another process on the same core is
using AVX instructions. It's not clear what the implications are of this, or if
it's possible to influence this, or determine what the other process is doing.


## Relevant Architectures

We have reproduced this on the following CPUs.

### Skylake
```
cpu family      : 6
model           : 85
model name      : Intel(R) Xeon(R) CPU @ 2.00GHz
stepping        : 3
microcode       : 0x1
```
```
cpu family   : 6
model        : 85
model name   : Intel(R) Xeon(R) Gold 6154 CPU @ 3.00GHz
stepping     : 4
microcode    : 0x2006e05
```

### Broadwell
```
cpu family      : 6
model           : 79
model name      : Intel(R) Xeon(R) CPU E5-2690 v4 @ 2.60GHz
stepping        : 1
microcode       : 0xb000040
```

### Tigerlake
```
cpu family  : 6
model       : 140
model name  : 11th Gen Intel(R) Core(TM) i7-1185G7 @ 3.00GHz
stepping    : 1
microcode   : 0xa6
```

# Analysis

Further research is required to determine if this behaviour has any security consequences.

## References

[^1]: https://robert.ocallahan.org/2017/06/another-case-of-obscure-cpu.html
