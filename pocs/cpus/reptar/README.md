# REP MOVSB Redundant Prefixes Can Corrupt Ice Lake Microarchitectural State
<p><sup>aka "Reptar", CVE-2023-23583</sup></p>
<p align="right">
Tavis Ormandy<br/>
Eduardo Vela Nava<br/>
Josh Eads<br/>
Alexandra Sandulescu<br/>
</p>

## Introduction

If you've ever written any x86 assembly at all, you've probably used `rep movsb`.
It's the idiomatic way of moving memory around on x86. You set the *source*,
*destination*, *direction* and the *count* - then just let the processor handle
all the details!

```nasm
lea rdi, [rel dst]
lea rsi, [rel src]
std
mov rcx, 32
rep movsb
```

The actual instruction here is `movsb`, the `rep` is simply a prefix that
changes how the instruction works. In this case, it indicates that you want
this operation **rep**eated multiple times.

There are lots of other prefixes too, but they don't all apply to every
instruction.

#### Prefix Decoding

An interesting feature of x86 is that the instruction decoding is generally
quite relaxed. If you use a prefix that doesn't make sense or conflicts with
other prefixes nothing much will happen, it will usually just be ignored.

This fact is sometimes useful; compilers can use redundant prefixes to pad a
single instruction to a desirable alignment boundary.

Take a look at this snippet, this is exactly the same code as above, just a
bunch of useless or redundant prefixes have been added:

```nasm
            rep lea rdi, [rel dst]
             cs lea rsi, [rel src]
       gs gs gs std
          repnz mov rcx, 32
rep rep rep rep movsb
```

Perhaps the most interesting prefixes are `rex`, `vex` and `evex`, all of which
change how subsequent instructions are decoded.

Let's take a look at how they work.

#### The REX prefix

The i386 only had 8 general purpose registers, so you could specify which
register you want to use in just 3 bits (because 2^3 is 8).

The way that instructions were encoded took advantage of this fact, and reserved
*just* enough bits to specify any of those registers.

This is a problem, because x86-64 added 8 additional general purpose registers.
We now have sixteen possible registers..that's 2^4, so we're going
to need another bit.

The solution to this is the `rex` prefix, which gives us some spare bits that
the next instruction can borrow.

When we're talking about rex, we usually write it like this:

```nasm
rex.rxb
```

`rex` is a single-byte prefix, the first four bits are mandatory and the
remaining four bits called `b`, `x`, `r` and `w` are all optional. If you see
`rex.rb` that means only the `r` and `b` bits are set, all the others are
unset.

These optional bits give us room to encode more general purpose registers in
the following instruction.

#### Encoding Rules

So now we know that `rex` increases the available space for encoding operands,
and that useless or redundant prefixes are usually ignored on x86. So... what
should this instruction do?

```nasm
rex.rxb rep movsb
```

The `movsb` instruction doesn't have any operands - they're all implicit - so
any `rex` bits are meaningless.

If you guessed that the processor will just silently ignore the `rex` prefix,
you would be correct!

Well... except on machines that support a new feature called *fast short
repeat move*! We discovered that a bug with redundant `rex` prefixes could
interact with this feature in an unexpected way and introduce a serious
vulnerability.

#### Reproduce

We're publishing all of our research today to our [security research
repository](https://github.com/google/security-research/). If you want to
reproduce the vulnerability you can use our `icebreak` tool, I've also made a
local mirror available [here](files/icebreak.tar.gz).

```
$ ./icebreak -h
usage: ./icebreak [OPTIONS]
    -c N,M      Run repro threads on core N and M.
    -d N        Sleep N usecs between repro attempts.
    -H N        Spawn a hammer thread on core N.
icebreak: you must at least specify a core pair with -c! (see -h for help)
```

The testcase enters what should be an infinite loop, and unaffected systems
should see no output at all. On affected systems, a `.` is printed on each
successful reproduction.

```
$ ./icebreak -c 0,4
starting repro on cores 0 and 4
.........................................................................
.........................................................................
.........................................................................
.........................................................................
.........................................................................
```

In general, if the cores are <abbr title="Symmetric Multithreading">SMT</abbr>
siblings then you may observe random branches and if they're <abbr
title="Symmetric Multiprocessing">SMP</abbr> siblings from the same package
then you may observe machine checks.

If you do *not* specify two different cores, then you might need to use a
hammer thread to trigger a reproduction.

## Solution

Intel have
[published](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00950.html)
updated microcode for all affected processors. Your operating system or BIOS
vendor may already have an update available!

