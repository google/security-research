/*
  Copyright 2000 Transmeta Corporation - All Rights Reserved
  Copyright 2004-2008 H. Peter Anvin - All Rights Reserved
  Copyright 2025 Google LLC

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  version 2 as published by the Free Software Foundation, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  Based on code from msr-tools (https://github.com/intel/msr-tools)
*/

#define _GNU_SOURCE

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>

#define PAGE_SHIFT 12
#define PAGE_SIZE (1ul << (PAGE_SHIFT))
#define MSR_AMD64_PATCH_LEVEL 0x0000008b
#define MSR_AMD64_PATCH_LOADER 0xc0010020

#define fatal(...) err(EXIT_FAILURE, __VA_ARGS__)
#define fatalx(...) errx(EXIT_FAILURE, __VA_ARGS__)

static void wrmsr_on_cpu(uint32_t reg, int cpu, uint64_t val)
{
	char msr_file_name[64];
	sprintf(msr_file_name, "/dev/cpu/%d/msr", cpu);

	int fd = open(msr_file_name, O_WRONLY);
	if (fd < 0) {
		if (errno == ENXIO) {
			fatalx("No CPU %d", cpu);
		} else if (errno == EIO) {
			fatalx("CPU %d doesn't support MSRs", cpu);
		} else {
			fatal("Open msr");
		}
	}

	if (pwrite(fd, &val, sizeof val, reg) != sizeof val) {
		if (errno == EIO) {
			fatal("CPU %d cannot set MSR 0x%08x to 0x%016lx", cpu, reg, val);
		} else {
			fatal("write msr");
		}
	}

	close(fd);
}

static uint64_t rdmsr_on_cpu(uint32_t reg, int cpu)
{
	char msr_file_name[64];
	sprintf(msr_file_name, "/dev/cpu/%d/msr", cpu);

	int fd = open(msr_file_name, O_RDONLY);
	if (fd < 0) {
		if (errno == ENXIO) {
			fatalx("rdmsr: No CPU %d", cpu);
		} else if (errno == EIO) {
			fatalx("rdmsr: CPU %d doesn't support MSRs", cpu);
		} else {
			fatal("rdmsr: open");
		}
	}

	uint64_t data;
	if (pread(fd, &data, sizeof data, reg) != sizeof data) {
		if (errno == EIO) {
			fatalx("CPU %d cannot read MSR 0x%08x", cpu, reg);
		} else {
			fatal("rdmsr: pread");
		}
	}

	close(fd);

	return data;
}

static uint64_t virt_to_phys(const void *addr)
{
	uint64_t val;

	uint64_t vfn = ((uint64_t)addr) >> PAGE_SHIFT;
	uint64_t offset = ((uint64_t)addr) & ((PAGE_SIZE - 1));

	int fd = open("/proc/self/pagemap", O_RDONLY);
	if (fd < 0) {
		fatal("open pagemap");
	}

	if (lseek(fd, vfn << 3, SEEK_SET) < 0) {
		fatal("lseek pagemap");
	}

	if (read(fd, &val, sizeof(val)) != sizeof(val)) {
		fatal("read pagemap");
	}

	close(fd);

	return (val << PAGE_SHIFT) | offset;
}

static void enable_thp(void)
{
	int fd = open("/sys/kernel/mm/transparent_hugepage/enabled", O_RDWR);
	if (fd < 0) {
		fatal("open thp");
	}

	const char msg[] = "always";
	if (write(fd, msg, sizeof(msg)) != sizeof(msg)) {
		fatal("write thp");
	}

	close(fd);
}

static noreturn void usage(const char *name)
{
	fprintf(stderr, "usage: %s <microcode file> <physmap base> <cpu>\n", name);
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	if (argc < 4) {
		usage(argv[0]);
	}

	errno = 0;
	uint64_t physmap_base = strtoul(argv[2], NULL, 0);
	if (errno != 0) {
		usage(argv[0]);
	}

	errno = 0;
	int cpu = strtoul(argv[3], NULL, 0);
	if (errno != 0) {
		usage(argv[0]);
	}

	int ucode_fd = open(argv[1], O_RDONLY);
	if (ucode_fd < 0) {
		fatal("Failed to open ucode");
	}

	struct stat statbuf;
	if (fstat(ucode_fd, &statbuf) < 0) {
		fatal("stat ucode");
	}

	if (!S_ISREG(statbuf.st_mode)) {
		fatalx("ucode is not a regular file");
	}

	enable_thp();

	printf("Reading %ld bytes\n", statbuf.st_size);

	uint8_t *data = mmap((void *)(1ul << 21), 1ul << 21, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
	if (data == MAP_FAILED) {
		fatalx("mmap memory");
	}

	if (read(ucode_fd, data, statbuf.st_size) != statbuf.st_size) {
		fatal("read ucode");
	}

	uint64_t patch_physaddr = virt_to_phys(data);
	printf("Patch at %#lx in physmem\n", patch_physaddr);
	if ((patch_physaddr & ((1ul << 21) - 1)) != 0) {
		fatalx("physical address not aligned");
	}

	uint64_t patch_kva = physmap_base + patch_physaddr;
	printf("Patch at %#lx in virtmem\n", patch_kva);

	uint64_t current_version = rdmsr_on_cpu(MSR_AMD64_PATCH_LEVEL, cpu);
	printf("Current ucode patch on cpu %d: %#lx\n", cpu, current_version);

	wrmsr_on_cpu(MSR_AMD64_PATCH_LOADER, cpu, patch_kva);

	uint64_t new_version = rdmsr_on_cpu(MSR_AMD64_PATCH_LEVEL, cpu);
	printf("New ucode patch on cpu %d: %#lx\n", cpu, new_version);
}
