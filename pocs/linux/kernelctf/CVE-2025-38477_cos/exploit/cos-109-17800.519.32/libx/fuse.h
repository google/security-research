#define _GNU_SOURCE
#define FUSE_USE_VERSION 34
#include <linux/fuse.h>
#include <fuse.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <sys/mman.h>
#include <pthread.h>
static int fault_cnt = 0;
