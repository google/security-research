# Condition Codes

The `.ss` bit in a RegOp is *Set Status*, and causes flags to be set based on
the result of a micro-op. These flags can either be the normal `RFLAGS` flags
visible to macro instructions, or emulated flags. These are sometimes written
like `ECF` for *emulated carry flag* instead of `CF`, for the `RFLAGS` carry
flag.


# Experimental Results


.ss = 1
    .cc = 0b1000    seems to set CF

