# RISC86 Programming Reference
<p align="right">
    <sup>Tavis Ormandy taviso@</sup>
</p>

There is no official documentation of RISC86, the microarchitecture used on Zen
processors. However, the book ***The Anatomy of a High-Performance
Microprocessor: A Systems Perspective*** (ISBN 0818684003) was written with support
from engineers who designed the system, so serves as the most complete
reference guide we have.

> There is also a paper ***Reverse Engineering x86 Processor Microcode*** by
> researchers at Ruhr-University Bochum who studied some pre-Zen RISC86 systems.

Understanding the current state of RISC86 is an ongoing challenge, but what little
we do know is documented here.

This is mostly discovered experimentally. For example, setting a few bits,
observing the result, and creating hypotheses for what operation could have
caused the observed result.

> It is likely there are a lot of errors in this document!

# OpQuads

The format of OpQuads does not appear to match the format described in AOHM,
however some fields have simply moved around. The most important one is
probably the Type field, which determines how the other fields are
interpreted.

## Op Type

Table 3.4 from from the Scheduler chapter, reproduced below, does appear
to still be accurate:

| Type(2:0) | Type of Op
|-----------|--------------------------------
| 000       | a SpecOp -- not issued to an execution unit
| 010       | a LdOp -- issued to the Load Unit
| 10x       | applies to all StOps
| 100       | a StOp that does not reference memory -- issued to the Store Unit
| 101       | a StOp that references memory or at least can result in a memory fault -- issues to a Store Unit
| 110       | a RegOp that can only be executed by RUX
| 111       | a RegOp that can be executed by RUX or RUY -- issues to either RUX or RUY

This means we can check what bits are in this field, then interpret the other
bits according to their value.

## Register Units

In the table above *RUX* and *RUY* are *Register Unit X* and *Register Unit Y*.
RUX is the more capable unit, whereas RUY can only handle a subset of the
operations RUX can.

## RegOps

The following opcodes are known

| Opcode    | Description
|-----------|---------------------------------
| `and`     | Bitwise AND
| `shl`     | Shift Left
| `rol`     | Rotate Left
| `src`     | Shift Left w/Carry
| `shr`     | Shift Right
| `ror`     | Rotate Right
| `sub`     | Subtract
| `sbb`     | Subtract w/Borrow
| `adc`     | Add w/Carry
| `add`     | Add
| `popcnt`  | Population Count
| `sbit`    | Set bit
| `xor`     | Exclusive Or
| `or`      | Inclusive Or
| `bswap`   | Byte Swap
| `mov`     | Move

The assembler, `mcas`, understands most of these forms.

```
$ ./mcas "xor rbx, rax, rcx"
	; 385A9C1208E00000 0011100001011010100111000001001000001000111000000000000000000000
	; .imm16    :    0                                                 0000000000000000
	; .isig     :    0                                                0
	; .mode3    :    0                                             0
	; .reg0     :    7                                       00111
	; .reg1     :    2                                  00010
	; .reg2     :    4                             00100
	; .rmod     :    1                            1
	; .cc       :    0                        0000
	; .ss       :    0                       0
	; .size     :    3                     11
	; .sizemsb  :    1                    1
	; .pada     :    0                  00
	; .type     :   B5          10110101
	; .ext      :    0      0000
	; .class    :    7   111
	xor     	rbx, rax, rcx
```

You can see that the known fields are listed, these are described below.

## RegOp Fields

| Field         | Description
| ------------- | ---------------------------
| `.imm16`      | A 16-bit immediate operand, e.g. `add rax, rax, 0x32`
| `.isig`       | If set, the immediate should be sign extended to instruction width.
| `.mode3`      | This is a 3-operand form
| `.reg0`       | First source register
| `.reg1`       | Second source register
| `.reg2`       | Destination register
| `.rmod`       | Instruction form
| `.cc`         | Condition Codes requested
| `.ss`         | Set Status, used to request flags update
| `.size`       | Data size, byte, word or qword.
| `.type`       | Opcode
| `.class`      | Op type, always RegOp

If you want to set these values, you can use `mcop`:

```
$ mcop --set reg2=21 385A9C1208E00000
	; 385A9C1A88E00000 0011100001011010100111000001101010001000111000000000000000000000
	; .imm16    :    0                                                 0000000000000000
	; .isig     :    0                                                0
	; .mode3    :    0                                             0
	; .reg0     :    7                                       00111
	; .reg1     :    2                                  00010
	; .reg2     :   15                             10101
	; .rmod     :    1                            1
	; .cc       :    0                        0000
	; .ss       :    0                       0
	; .size     :    3                     11
	; .sizemsb  :    1                    1
	; .pada     :    0                  00
	; .type     :   B5          10110101
	; .ext      :    0      0000
	; .class    :    7   111
	xor     	rbp, rax, rcx
```

Alternatively, use `zentool` directly, e.g.:

```
$ zentool edit --insn-field q1i0.ss=1 microcode.bin
```

## Registers

The mapping from macro-registers to micro-registers does not appear to match
AOHM, here are some of the known mappings.

```c
typedef enum {
    REG_RAX    = 16,
    REG_RCX    = 17,
    REG_RDX    = 18,
    REG_RBX    = 19,
    REG_RSP    = 20,
    REG_RBP    = 21,
    REG_RSI    = 22,
    REG_RDI    = 23,
    REG_R8     = 24,
    REG_R9     = 25,
    REG_R10    = 26,
    REG_R11    = 27,
    REG_R12    = 28,
    REG_R13    = 29,
    REG_R14    = 30,
    REG_R15    = 31,
} zen_reg_t;
```

The lower register numbers appear to be reserved for "environment
substitutions" (see AOHM Chapter 2, figure 2.10). That is, they are
automatically populated with instruction parameters by the decoder.

The full details of how the substitution mechanism works is not entirely
understood.

# LdStOps

A *LdStOp* can move to or from memory, but does not necessarily have to. The `mcas` utility recognizes
a few forms, here are some examples:

```
$ mcas "ld.q [rax], rax"
	; 284BDC3108009800 0010100001001011110111000011000100001000000000001001100000000000
	; .imm      :    0                                                       0000000000
	; .segment  :    6                                                   0110
	; .unkn1    :    0                                                  0
	; .nop3     :    1                                                 1
	; .unkn2    :    0                                                0
	; .mode     :    0                                              00
	; .wordsz   :    0                                             0
	; .unknf    :    0                                            0
	; .reg0     :    0                                       00000
	; .reg1     :    2                                  00010
	; .reg2     :    2                             00010
	; .rmod     :    1                            1
	; .op3      :    1                           1
	; .unkn6    :    0                       0000
	; .size     :    3                     11
	; .width    :    1                    1
	; .ldst     :    0                   0
	; .unkn3    :   2F             101111
	; .unknx    :    4          100
	; .type     :    0      0000
	; .class    :    5   101
	ld      	[rax], rax
```

## LdStOp Fields

| Field         | Description
| ------------- | ---------------------------
| `.imm`        | An immediate value or displacement, depending on mode
| `.segment`    | Segment number, see below for known values.
| `.mode`       | Addressing mode.
| `.wordsz`     | Appears to toggle between dword/qword
| `.reg0`       | Src register 1
| `.reg1`       | Src register 2
| `.reg2`       | Destination register
| `.rmod`       | Addressing mode selection
| `.op3`        | 3 operand form
| `.size`       | Address/destination size
| `.width`      | 
| `.ldst`       | If set, this is a load, otherwise it's a store

## Segments

These are the known segment values

| Segment       | Description
| ------------- | ----------------------------
|  `ms`         | Various internal regions, such as MSRs, cache, ucode RAM?
|  `ls`         | The linear virtual address space
|  `ps`         | Physical RAM

There are others that are IDT/GDT relative, or architectural segment relative.


## Flags

The following flags can be appended to mnemonics, e.g. `add.qs`:

| Flags         | Description
| ------------- | ----------------------------
|  `s`          | Sync macro status flags (RFLAGS) with emulated status flags.
|  `q`          | Force qword operation size (this is the default)
|  `w`          | Operation is word size.
|  `b`          | Operation is byte size.
|  `x`          | Direct operation to RUX.
|  `p`          | Mark operation as non-faulting.

See also, [status](status.md) documentation. The `.s` flag simply modifies the *set status* bit.

# Examples

These examples are tested and appear to be working.

```
    add.b rax, rax, 0xAA
    add.b rax, rax, rbx
    add.q rax, rax, rbx
    add.qs rax, rbx, 1
    add rax, rax, 0x123
    add.w rax, rax, rbx
    bswap.q rax, rax
    mov rax, rbx
    nadd.b rax, rax, 0xAA
    nadd rax, rax, rbx
    nadd rax, rbx, rax
    nsub rax, rax, rbx
    nsub rax, rbx, rax
    or rax, rax, 0x42
    popcnt.q rax, rbx
    popcnt rax, rax
    popcnt.w rax, rax
    rol rax, rax, 4
    rol rax, rax, 8
    ror rax, rax, 1
    ror rax, rax, 4
    ror rax, rax, 8
    ror.s rax, rax, 1
    shl rax, rax, rbx
    ld.d rax, ls:[rax]
    ld.d rax, ms:[rbx+0x62]
    ld.pd [rax], rbx
    ld.p ms:[rax], rbx
    ld.pq ls:[rbp+8], rax
    ld.pq [rax], rbx
    ld.p [rax], rbx
    ld.q rax, ls:[rax]
    ld.q rax, ls:[rbp+8]
    ld.q rax, ms:[rax]
    ld rax, 5:[rax+rbx]
    sub rax, rax, 42
    sub rax, rax, rbx
    sub.sq rax, rax, 1
    xor.q rax, rax, rbx
    xor rax, rax, rax
    xor rax, rax, rbx
```

# Model Specific Registers

You can modify MSRs from within microcode using stores to `ms`.

It's not currently obvious what the relationship is between MSR number and
equivalent address, but they can be discovered experimentally easily.

For example, `MSR_AMD64_PATCH_LEVEL` appears to be stored at address
`ms:0x262`.

Interestingly, the `wrmsr` instruction will not usually permit modifications to
this MSR, but microcode can do so like this:

```
    mov rax, rax, 0x262
    mov rbx, rbx, 0x41
    ld.p ms:[rax], rbx
```

# Notes

-   It seems possible that the modern RISC86 implementation of some microcoded
    instructions shares some distant ancestry with the *NexGen Nx586 Hypercode*
    implementation (see
    [fpatan](https://www.memotech.franken.de/cgi-bin/AsmColor.cgi?f=../NexGen/Source/FPATAN.ASM),
    for example). It is certainly no longer written in x86, but could plausibly
    be a reimplementation of the same logic after the [acquisition by
    AMD](https://www.latimes.com/archives/la-xpm-1995-10-21-fi-59417-story.html)?
