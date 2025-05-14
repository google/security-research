#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#ifndef MODULES_HELPER
#define MODULES_HELPER

#define KMALLOC_16 (0x10)
#define KMALLOC_32 (0x20)
#define KMALLOC_64 (0x40)
#define KMALLOC_96 (0x60)
#define KMALLOC_128 (0x80)
#define KMALLOC_192 (0xc0)
#define KMALLOC_256 (0x100)
#define KMALLOC_512 (0x200)
#define KMALLOC_1K (0x400)
#define KMALLOC_2K (0x800)
#define KMALLOC_4K (0x1000)
#define KMALLOC_8K (0x2000)
#define KMALLOC_16K (0x4000)
#define KMALLOC_32K (0x8000)
#define KMALLOC_64K (0x10000)
#define KMALLOC_128K (0x20000)

#define PAGE_SIZE KMALLOC_4K

void print_hex_bytes(uint8_t *buf, int l, int r);
void print_hex_8bytes(uint64_t *buf, int l, int r);

void cpu_affinity(int cpu);
void unshare_setup(int flags);

void get_root();

void win();
void get_shell();

struct regs {
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, rip, rflags;
    uint64_t cs, ss, ds, es, fs, gs;
};
struct regs *save_state();

uint64_t virt2page(uint64_t virt, uint64_t vmalloc_base, uint64_t vmemmap_base);

#endif