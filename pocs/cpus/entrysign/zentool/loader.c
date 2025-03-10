/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <unistd.h>
#include <x86intrin.h>

#include <asm/prctl.h>
#include <linux/filter.h>
#include <linux/prctl.h>
#include <linux/seccomp.h>
#include <sys/cdefs.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ucontext.h>
#include <sys/user.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#include "options.h"
#include "util.h"

#define MSR_AMD64_PATCH_LEVEL 0x0000008b
#define MSR_AMD64_PATCH_LOADER 0xc0010020

#define fatal(...) err(EXIT_FAILURE, __VA_ARGS__)
#define fatalx(...) errx(EXIT_FAILURE, __VA_ARGS__)

#define PAGE_ROUND_UP(x) ((((uint64_t)(x)) + (PAGE_SIZE-1))  & (~(PAGE_SIZE-1)))

static bool wrmsr_on_cpu(uint32_t reg, int cpu, uint64_t val)
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
        if (errno != EIO) {
            fatal("write msr");
        }
        dbgmsg("cpu %d cannot set msr 0x%08x to 0x%016lx", cpu, reg, val);
        goto error;
    }

    close(fd);
    return true;

  error:
    close(fd);
    return false;
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

static uint64_t virt_to_phys_cheat(const void *addr)
{
    uint64_t pa_with_flags;

    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) {
        fatal("open pagemap");
    }

    if (lseek(fd, ((uint64_t)addr & (~(PAGE_SIZE - 1))) >> 9, SEEK_SET) < 0) {
        fatal("lseek pagemap");
    }

    if (read(fd, &pa_with_flags, sizeof(uint64_t)) != sizeof(uint64_t)) {
        fatal("read pagemap");
    }

    close(fd);

    return (pa_with_flags << 12) | ((uint64_t)addr & (PAGE_SIZE - 1));
}

static int retry;

static const struct option kLongOpts[] = {
    {          "help", false, NULL, 'h' },
    {  "physmap-base",  true, NULL, 'p' },
    {          "core",  true, NULL, 'c' },
    {           "cpu",  true, NULL, 'c' },
    {         "retry", false, &retry, true },
    {0},
};

static const char *kOptHelp[] = {
    "print this message",
    "choose kernel base, see documentation",
    "select cpu core number",
    "alias for --core",
    "keep trying on failure",
};

static void print_usage()
{
    logmsg("attempt to apply a cpu microcode update");

    print_usage_generic("load", "FILE", kLongOpts, kOptHelp);

    logmsg("This command requires root privileges.");

    // Give some hints if the user isn't using nokaslr.
    if (system("grep -Eq '\\<nokaslr\\>' /proc/cmdline") != 0) {
        logerr("");
        logerr(
            "You either need to boot with the `nokaslr` kernel option, or       \n"
            "provide a base using --physmap-base to use this command.           \n"
            "                                                                   \n"
            "You can try something like this to get the required value:         \n"
            "   # b=$(grep -Po '^.*(?= . page_offset_base)' /proc/kallsyms)     \n"
            "   # gdb --batch -q -ex \"x/gx 0x${b}\" --core /proc/kcore         \n"
        );
    }

}

static bool check_phys_contig(uint8_t *addr, size_t size)
{

    uint64_t baseaddr = virt_to_phys_cheat(addr);

    // This should be a page-aligned address.
    assert(((uint64_t)(addr) & (PAGE_SIZE - 1)) == 0);

    // Check each page is contiguous.
    for (size_t i = 0; i < size; i += PAGE_SIZE) {
        if (virt_to_phys_cheat(addr + i) != baseaddr + i) {
            dbgmsg("base %p, base+%#x %p", baseaddr, i, virt_to_phys_cheat(addr + i));
            return false;
        }
    }

    dbgmsg("base %p, base+%#x %p", baseaddr, size - 1, virt_to_phys_cheat(addr + size - 1));
    return true;
}


#define MAX_CONTIG_ATTEMPT 1024

static void *mmap_contig(size_t size)
{
    uint8_t *candidates[MAX_CONTIG_ATTEMPT] = {0};
    uint8_t *data = MAP_FAILED;

    assert(size <= 1 << 21);

    dbgmsg("attempting to map %u physically contiguous bytes", size);

    for (int i = 0; i < MAX_CONTIG_ATTEMPT; i++) {
        candidates[i] = mmap(NULL, 1 << 21, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_LOCKED, -1, 0);
        dbgmsg ("checking candidate %u/%u, %p", i, MAX_CONTIG_ATTEMPT, candidates[i]);
        if (check_phys_contig(candidates[i], size)) {
            data = candidates[i];
            break;
        }
    }

    for (int i = 0; i < MAX_CONTIG_ATTEMPT; i++) {
        if (candidates[i] != data && candidates[i])
            munmap(candidates[i], 1 << 21);
    }

    dbgmsg("result %p", data);
    return data;
}

static void munmap_contig(void *data)
{
    munmap(data, 1 << 21);
}

int cmd_load_main(int argc, char *argv[])
{
    int c;
    int longopt;
    int cpu = -1;
    uint64_t physmap_base = 0;

    reset_getopt();

    while ((c = getopt_long(argc, argv, "hp:c:", kLongOpts, &longopt)) != -1) {
    switch (c) {
            case 'h': print_usage();
                      return 0;
            case 'p': physmap_base = strtoull(optarg, NULL, 0);
                      break;
            case 'c': cpu = strtoul(optarg, NULL, 0);
                      break;
            case '?': print_usage();
                      errx(EXIT_FAILURE, "invalid options");
        }
    }

    if (geteuid() != 0) {
        errx(EXIT_FAILURE, "this command requires root");
    }

    if (physmap_base == 0) {
        if (system("grep -Eq '\\<nokaslr\\>' /proc/cmdline") != 0) {
            print_usage();
            errx(EXIT_FAILURE, "you didn't specify a physmapbase, you need one unless you boot with nokaslr");
        }

        // Assume a reasonable default
        physmap_base = 0xffff888000000000ULL;
    }

    if (argc == optind) {
        print_usage();
        errx(EXIT_FAILURE, "you must specify an update file to load");
    }

    int ucode_fd = open(argv[optind], O_RDONLY);
    if (ucode_fd < 0) {
        fatal("Failed to open ucode");
    }

    if (cpu < 0) {
        errx(EXIT_FAILURE, "you need to specify a core number, e.g. --cpu=2");
    }

    struct stat statbuf;

    if (fstat(ucode_fd, &statbuf) < 0) {
        fatal("stat ucode");
    }

    dbgmsg("Reading %ld bytes", statbuf.st_size);

    logmsg("old ucode patch on cpu %d: %#lx",
            cpu,
            rdmsr_on_cpu(MSR_AMD64_PATCH_LEVEL, cpu));

    while (true) {
        uint8_t *data = mmap_contig(statbuf.st_size);

        if (data == MAP_FAILED) {
            fatalx("mmap memory");
        }

        if (pread(ucode_fd, data, statbuf.st_size, 0) != statbuf.st_size) {
            fatal("pread ucode");
        }

        uint64_t patch_physaddr = virt_to_phys_cheat(data);
        uint64_t patch_kva = physmap_base + patch_physaddr;

        dbgmsg("Patch at %#lx in physmem", patch_physaddr);
        dbgmsg("Patch at %#lx in virtmem", patch_kva);

        if (wrmsr_on_cpu(MSR_AMD64_PATCH_LOADER, cpu, patch_kva) != true) {
            logerr("wrmsr failed, the CPU did not accept the update.");

            // Data no longer needed.
            munmap_contig(data);

            // Optionally repeat forever (used for testing).
            if (retry) continue;

            logerr("    - Check the signature, `zentool verify`                         \n"
                   "    - Check the cpuid matches, `zentool print`                      \n"
                   "    - Is the update revision >= current revision? Try `rdmsr 0x8b`  \n"
                   "    - This could be transient, try again?                             ");
            fatalx("wrmsr failed, the CPU did not accept the update.");
        }

        munmap_contig(data);
        break;
    };

    logmsg("new ucode patch on cpu %d: %#lx",
            cpu,
            rdmsr_on_cpu(MSR_AMD64_PATCH_LEVEL, cpu));
    return 0;
}
