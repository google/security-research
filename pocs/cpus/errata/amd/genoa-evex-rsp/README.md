# The EVEX.X bit can load the wrong RSP value into vector registers

<p align="right">
Tavis Ormandy <br/>
</p>

> *This document is a Work In Progress and represents an errata currently under investigation*

## Introduction

We have observed an error on the AMD Zen 4 family of processors with
EVEX encoded instructions that access the stack pointer.

The error can be observed with instructions that operate on both vector
registers and general purpose registers simultaneously, such as `vpinsrw`,
`vmovq`, `vctsi2ss`, and so on.

The error only occurs if you use `RSP` with these instructions.

It would be a valid but unusual operation to use `RSP` with these instructions,
we believe it is unlikely that any compiler generated code is affected.

## Details

If you attempt to load the value of `RSP` into a vector register, the value
actually loaded may lag behind the actual stack pointer.

We have confirmed the bug is reproducible on the following SKU:

- `Family=0x19 Model=0x11 Stepping=0x01 Patch=0xa10113b`

You can verify the current Model, Family, Stepping and Patch level by
examining `/proc/cpuinfo`.

### Reproducing

The program `zenrsp.c` is the testcase.

It should not produce any output unless an affected core detected.

#### Building

```
$ gcc -mavx512vl -o zenrsp zenrsp.c
```

#### Running

The normal expected output of `zenrsp` should be empty.

On an affected CPU, the output might look like this:

```
$ ./zenrsp
after 11125090: 0x697e1d18 vs 0x697e1d20
after 23257786: 0x697e1d18 vs 0x697e1d20
after 34307607: 0x697e1d18 vs 0x697e1d20
after 80446822: 0x697e1d18 vs 0x697e1d20
after 85419804: 0x697e1d18 vs 0x697e1d20
after 110056364: 0x697e1d18 vs 0x697e1d20
after 140417725: 0x697e1d18 vs 0x697e1d20
after 152543052: 0x697e1d18 vs 0x697e1d20
after 163199133: 0x697e1d18 vs 0x697e1d20
after 177559018: 0x697e1d18 vs 0x697e1d20
```

This indicates that sometimes the wrong value was loaded into a vector register.

### Analysis

The code simply manipulates `rsp` with a `push`/`pop` sequence, then loads
the stackpointer into `xmm13` with the following instruction:

```
{evex} vmovq xmm13, rsp
```

We believe that stack operations are not correctly considered dependencies when
the EVEX.X bit is set.

This results in stale values occasionally being loaded into registers.

## Conclusion

It is not clear if any code ever loads the stack pointer into vector registers,
but it is not impossible, and we document it here for reference.
