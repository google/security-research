/* SPDX-License-Identifier: GPL-3.0-only */
OUTPUT_FORMAT("binary")

SECTIONS
{
    . = 0;

    .text : {
        *(.start.text)
        *(.text)
    }

    .data : {
        *(.data)
        *(.rodata)
        . = ALIGN(8);
    }

}
