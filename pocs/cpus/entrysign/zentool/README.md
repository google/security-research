# Zentool -- AMD Zen Microcode Manipulation Utility

This package provides a suite of tools for analyzing, manipulating and
generating microcode patches for AMD Zen processors.

The command `zentool` is a frontend to various utilities. There is also a
`mcas`, a simple assembler and `mcop` a simple disassembler.

> Note: We also have an [introduction](docs/intro.md) to microcoding, and
> a programming [reference](docs/reference.md).

# Usage

The general format of a command is:

```
$ zentool [GLOBALOPTIONS] CMD [COMANDOPTIONS] [FILE...]
```

Type `zentool help` to see a list of available commands.

## Examples

You can examine the header of a microcode update file using the `print`
command:

```
$ zentool print data/cpu00860F01_ver0860010F_2024-11-18_785D74AB.bin
Date:        11182024 (Mon Nov 18 2024)
Revision:    0860010f
Format:      8004
Patchlen:    00
Init:        00
Checksum:    00000000
NorthBridge: 0000:0000
SouthBridge: 0000:0000
Cpuid:       00008601 AMD Ryzen (Grey Hawk, Renoir)
  Stepping   1
  Model:     0
  Extmodel:  6
  Extfam:    8
BiosRev:     00
Flags:       00
Reserved:    0000
Signature:   9c... (use --verbose to see) (GOOD)
Modulus:     c7... (use --verbose to see)
Check:       5a... (use --verbose to see) (GOOD)
Autorun:     false
Encrypted:   false
Revision:    0860010f (Signed)
```

Let's modify that revision number using the `edit` command, and save the result
to `modified.bin`:

```
$ zentool --output modified.bin edit --hdr-revision 0x8600141 data/cpu00860F01_ver0860010F_2024-11-18_785D74AB.bin
$ zentool print modified.bin | grep -m1 ^Revision:
Revision:   08600141
```

That worked, but now the signature will be incorrect:

```
$ zentool verify modified.bin
modified.bin: BAD
```

You can use the `resign` command to compensate for the changes you made:

```
$ zentool resign modified.bin
$ zentool verify modified.bin
modified.bin: GOOD
```

Now you can apply that update to your processor with the `load` command, this
requires root privileges:

```
$ sudo zentool load --cpu=2 modified.bin
```

Now we can verify that worked by querying the microcode revision:

```
$ sudo rdmsr -c -a 0x8b
0x8608103
0x8608103
0x8608141 <---
0x8608103
0x8608103
0x8608103
0x8608103
0x8608103
```

The core we specified accepted the microcode update.

## Advanced Usage

You can examine most structures in the microcode file with the `print` command,
such as the match registers and instruction quads.

```
$ zentool print --match-regs modified.bin
; Patch 0x8600141 Match Registers (22 total)
; (use --verbose to see empty slots)
	[0 ] 07CE
	[1 ] 092D
	[2 ] 1129
	[3 ] 12E9
	[4 ] 08F6
	[5 ] 0940
	[6 ] 0545
	[7 ] 08A5
	[8 ] 0BF8
	[9 ] 124D
	[10] 0526
	[11] 111A
	[12] 107D
	[13] 1026
```

You can also change any of these using `edit`, for example:

```
$ zentool edit --match 0=0x1234 modified.bin
```

The general format for specifying a match register is `range=value`, where
range can be a single value `12`, a list of values `1,2,0x12`, a span
`1,2,3-9`, or the special name `all`.

You can also use some symbolic names, by prefixing them with `@`.

For example, `--match 0=@rdtsc` will attempt to set the first match register to
the address of `rdtsc` if it is known for the processor this patch applies to.

> Note: These symbolic names are stored in `json` files in the `data` directory.

### Disassembly

You can also try to disassemble the instruction quads, like this:

```
$ zentool print --disassemble modified.bin
; Patch 0x8600141 OpQuad Disassembly (64 total)
; (use --verbose to see further details)
.quad  2, 0x04021ff3
	shr     	reg12, reg12, reg11
	mov.b   	reg10, reg10, reg17
	nop.q
	nop.q
.quad  4, 0x00221ffa
	mov     	reg9, reg9, 0x0006
	ld      	vs:[reg9+reg1], reg0
	ld.w    	reg9, 1:[reg1+reg1]
	sreg.w  	reg9, reg9, reg1
.quad  5, 0x00400001
	mov     	reg9, reg9, 0x1ff0
	sreg.w  	reg9, reg9, reg1
	mov     	reg9, reg9, 0x0305
	nop.q
```

## Patching Instructions

The `edit` command can be used to replace instructions, effectively creating
custom microcode patches. The general format is `--insn range=op`. The `range`
can be specified in the same format as a match register (see above).

> Note: You can also use the syntax `q3i1` to refer to *quad 3, instruction 1*

The `op` is either a numeric constant, or a symbolic instruction.

For example,

```
$ zentool edit --insn q0i0="xor rax, rax, rax" modified.bin
```

This will set the first instruction of the first quad to `xor rax, rax, rax`.

There is also the special shortcut `--nop` which will make the specified
instruction a no-op.

Putting it all together, here is a command to make the `fpatan` instruction put
a constant in `rax`:

```
$ zentool edit --nop all                                   \
               --match all=0                               \
               --match 0,1=@fpatan                         \
               --seq 0,1=7                                 \
               --insn q1i0="xor rax, rax, rax"             \
               --insn q1i1="add rax, rax, 0x1337"          \
               --hdr-revlow 0xff                           \
               modified.bin
```

Of course, you also need to sign the file and then load it:

```
$ zentool resign modified.bin
$ sudo zentool load --cpu=2 modified.bin
```

Then you can try executing `fpatan` with gcc (e.g. `asm volatile ("fpatan" : "=a"(result))`)

> Note: Remember to use `taskset` to choose the core with the new microcode!
>       For example, `taskset -c 2 ./a.out`.

## Disassembly

You've already seen that the `print` command includes a dissasembler, however
you may find the simple `mcop` utility more convenient for debugging.

You simply give it an opcode in hex, and it describes each bit:

```
$ ./mcop 382E9C1108081337
	; 382E9C1108081337 0011100000101110100111000001000100001000000010000001001100110111
	; .imm16    : 1337                                                 0001001100110111
	; .isig     :    0                                                0
	; .mode3    :    1                                             1
	; .reg0     :    0                                       00000
	; .reg1     :    2                                  00010
	; .reg2     :    2                             00010
	; .rmod     :    1                            1
	; .cc       :    0                        0000
	; .ss       :    0                       0
	; .size     :    3                     11
	; .sizemsb  :    1                    1
	; .pada     :    0                  00
	; .type     :   5D          01011101
	; .ext      :    0      0000
	; .class    :    7   111
	add     	rax, rax, 0x1337
```

In addition, `mcop` can change named fields for you:

```
$ ./mcop --set type=0x41 --set reg2=2 0x382E9C1108081337
```

## Assembly

The inverse of the `mcop` command is `mcas`:

```
$ ./mcas "ld ls:[rax], rsi"
	; 204BDC3188009800 0010000001001011110111000011000110001000000000001001100000000000
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
	; .reg2     :    3                             00011
	; .rmod     :    1                            1
	; .op3      :    1                           1
	; .unkn6    :    0                       0000
	; .size     :    3                     11
	; .width    :    1                    1
	; .ldst     :    0                   0
	; .unkn3    :   2F             101111
	; .unknx    :    4          100
	; .type     :    0      0000
	; .class    :    4   100
	ld      	[rax], rsi
```

The `mcas` command can also accept instructions on stdin.

# Development

There are several scripts for adding support for new processors.

> TODO: describe

# Authors

This tool is built on the work of members of the Google Hardware Security Team.

In particular, Josh Eads, Matteo Rizzo, Kristoffer Janke, Eduardo Vela Nava,
Tavis Ormandy, Sophie Schmieg, and others.

The work was also influenced by the book "Anatomy of a High Performance
Microprocessor" (ISBN 0818684003), and the work of Ruhr-Univeritat Bochum
researchers Koppe et al in the paper "Reverse Engineering x86 Processor
Microcode".
