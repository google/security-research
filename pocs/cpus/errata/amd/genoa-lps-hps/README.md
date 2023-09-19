# EVEX encoded MOVLPS/MOVHPS can modify incorrect destination
<p align="right">
Tavis Ormandy <br/>
</p>

> *This document is a Work In Progress and represents an errata currently under investigation*

## Introduction

We have observed an error on the AMD Zen 4 family of processors with
EVEX encoded `VMOVLPS` and `VMOVHPS`.

The `MOVLPS` and `MOVHPS` instructions load two 32-bit packed single precision
floats from the source operand into the low or high 64-bits of a vector
register.

To illustrate this, consider this minimal example:

```asm
section .data
    a: dd 0x11111111, 0x22222222
    b: dd 0x33333333, 0x44444444

section .text
    movhps  xmm0, [rel a]
    movlps  xmm0, [rel b]
```

The result should be `xmm0` has the value `0x22222222111111114444444433333333`.

## Details

It is possible to use a three operand form of these instructions, where the two
merged source operands are placed in a third destination operand. For example:

```
    vmovhps xmm0, xmm1, [rel a]
```

Consider this sequence:

```asm
section .data
    data: dd 0x11111111, 0x22222222, 0x33333333, 0x44444444
    zero: dd 0,0,0,0

section .text
    vmovdqu  xmm0, [rel data]
    vmovlps  xmm1, xmm0, [rel zero]
    vmovhps  xmm17, xmm0, [rel zero]
```

The expected result would be:

```
xmm0  = 0x44444444333333332222222211111111
xmm1  = 0x44444444333333330000000000000000
xmm17 = 0x00000000000000002222222211111111
```

However, on genoa we non-deterministically get `xmm1=0`.

- `Family=0x19 Model=0x11 Stepping=0x01 Patch=0xa10113b`

You can verify the current Model, Family, Stepping and Patch level by
examining `/proc/cpuinfo`.

### Reproducing

The program `movhps.c` is the testcase.

It should not produce any output unless an affected core detected.

#### Building

```
$ gcc -mavx512vl -o movhps movhps.c
```

#### Running

The normal expected output of `movhps` should be empty.

On an affected CPU, the output might look like this:

```
$ ./movhps
After 1: 0000000000000000, 0000000000000000
After 2: 0000000000000000, 0000000000000000
After 1: 0000000000000000, 0000000000000000
After 2: 0000000000000000, 0000000000000000
After 1: 0000000000000000, 0000000000000000
After 2: 0000000000000000, 0000000000000000
```

This indicates that sometimes the wrong value was tested.

### Conclusion

It is possible for incorrect code to be generated when using compiler
intrinsics. It is not clear what values are being tested, or if it is possible
to infer any other state.

AMD have indicated that they do not believe this is a security issue, but gave
no further explanation when asked.
