#define _GNU_SOURCE

#include "gateway.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define GATEWAY_IOC_MAGIC 7342

#define GATEWAY_GET_MAGIC_VALUE _IOR(GATEWAY_IOC_MAGIC, 0, uint64_t)
#define GATEWAY_READ_UINT64 _IOR(GATEWAY_IOC_MAGIC, 1, void *)
#define GATEWAY_WRITE_UINT64 _IOW(GATEWAY_IOC_MAGIC, 2, void *)
#define GATEWAY_ALLOC_CONTIGUOUS_BUFFER _IOWR(GATEWAY_IOC_MAGIC, 5, void *)
#define GATEWAY_FREE_CONTIGUOUS_BUFFER _IOW(GATEWAY_IOC_MAGIC, 6, void *)
#define GATEWAY_IOCTL_ISSUE_OUTB _IOW(GATEWAY_IOC_MAGIC, 7, void *)
#define GATEWAY_IOCTL_ISSUE_INB _IOW(GATEWAY_IOC_MAGIC, 8, void *)
#define GATEWAY_IOCTL_ISSUE_OUTW _IOW(GATEWAY_IOC_MAGIC, 9, void *)
#define GATEWAY_IOCTL_ISSUE_INW _IOW(GATEWAY_IOC_MAGIC, 10, void *)
#define GATEWAY_IOCTL_ISSUE_OUTL _IOW(GATEWAY_IOC_MAGIC, 11, void *)
#define GATEWAY_IOCTL_ISSUE_INL _IOW(GATEWAY_IOC_MAGIC, 12, void *)
#define GATEWAY_IOCTL_ISSUE_SEAMCALL _IOWR(GATEWAY_IOC_MAGIC, 15, void *)
#define GATEWAY_IOCTL_ISSUE_TDCALL _IOWR(GATEWAY_IOC_MAGIC, 16, void *)
#define GATEWAY_IOCTL_ISSUE_RDMSR _IOR(GATEWAY_IOC_MAGIC, 17, void *)
#define GATEWAY_IOCTL_ISSUE_WRMSR _IOW(GATEWAY_IOC_MAGIC, 18, void *)

#define GATEWAY_IOCTL_FDGET _IOWR(GATEWAY_IOC_MAGIC, 19, void *)
#define GATEWAY_IOCTL_FDPUT _IOR(GATEWAY_IOC_MAGIC, 20, void *)

#define GATEWAY_IOCTL_ISSUE_VMCLEAR _IOWR(GATEWAY_IOC_MAGIC, 21, void *)
#define GATEWAY_IOCTL_ISSUE_VMLAUNCH _IOWR(GATEWAY_IOC_MAGIC, 22, void *)
#define GATEWAY_IOCTL_ISSUE_VMRESUME _IOWR(GATEWAY_IOC_MAGIC, 23, void *)
#define GATEWAY_IOCTL_ISSUE_VMXOFF _IOWR(GATEWAY_IOC_MAGIC, 24, void *)
#define GATEWAY_IOCTL_ISSUE_VMXON _IOWR(GATEWAY_IOC_MAGIC, 25, void *)
#define GATEWAY_IOCTL_ISSUE_VMREAD _IOR(GATEWAY_IOC_MAGIC, 26, void *)
#define GATEWAY_IOCTL_ISSUE_VMWRITE _IOW(GATEWAY_IOC_MAGIC, 27, void *)
#define GATEWAY_IOCTL_ISSUE_VMPTRLD _IOWR(GATEWAY_IOC_MAGIC, 28, void *)
#define GATEWAY_IOCTL_ISSUE_VMPTRST _IOWR(GATEWAY_IOC_MAGIC, 29, void *)
#define GATEWAY_IOCTL_RESCHEDULE _IOW(GATEWAY_IOC_MAGIC, 30, void *)

#define GATEWAY_IOCTL_IPI_STORM _IOWR(GATEWAY_IOC_MAGIC, 32, void *)

int gateway_open(char *path) {
  // printf("gateway_open\n");

  int fd = open(path, O_RDWR);
  if (fd < 0) {
    printf("[-] can't open device file: %s\n", path);
    perror("can't open device file\n");
    return fd;
  }

  // printf("[+] %s opened device file: %d\n", path, fd);

  return fd;
}

void gateway_close(int fd) {
  // printf("gateway_close\n");

  close(fd);
}

void *gateway_mmap(int fd, phys_addr_t address, size_t size) {
  // printf("gateway_mmap\n");

  return mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, address);
}

int gateway_munmap(int fd, void *buffer, size_t size) {
  // printf("gateway_munmap\n");

  return munmap(buffer, size);
}

void gateway_memset(void *dst, int value, size_t size) {
  memset(dst, value, size);
}

void gateway_memcpy(void *dst, void *src, size_t size) {
  memcpy(dst, src, size);
}


typedef struct {
  kern_addr_t ka;
  uint64_t value;
} gateway_read_write_uint64_data_t;

int gateway_read_uint64(int fd, kern_addr_t address, uint64_t *value) {
  int status;
  gateway_read_write_uint64_data_t data;

  // printf("gateway_read_uint64\n");

  if (value == NULL) {
    return -1;
  }

  data.ka = address;
  data.value = 0;

  status = ioctl(fd, GATEWAY_READ_UINT64, &data);

  if (status != 0) {
    printf("[-] gateway_read_uint64 failed\n");
    return status;
  }

  *value = data.value;

  return 0;
}

int gateway_write_uint64(int fd, kern_addr_t address, uint64_t value) {
  int status;
  gateway_read_write_uint64_data_t data;

  // printf("gateway_write_uint64\n");

  data.ka = address;
  data.value = value;

  status = ioctl(fd, GATEWAY_WRITE_UINT64, &data);

  if (status != 0) {
    printf("[-] gateway_write_uint64 failed\n");
    return status;
  }

  return 0;
}

typedef struct {
  kern_addr_t ka;
  phys_addr_t pa;
  size_t size;
} gateway_alloc_free_contiguous_buffer_t;

int gateway_alloc_contiguous_buffer(int fd, size_t size, kern_addr_t *ka,
                                  phys_addr_t *pa) {
  int status;
  gateway_alloc_free_contiguous_buffer_t data;

  // printf("gateway_alloc_contiguous_buffer\n");

  if (ka == NULL || pa == NULL) {
    return -1;
  }

  data.size = size;

  status = ioctl(fd, GATEWAY_ALLOC_CONTIGUOUS_BUFFER, &data);

  if (status != 0) {
    printf("[-] gateway_alloc_contiguous_buffer failed\n");
    return status;
  }

  *ka = data.ka;
  *pa = data.pa;

  return 0;
}

int gateway_free_contiguous_buffer(int fd, kern_addr_t ka, size_t size) {
  int status;
  gateway_alloc_free_contiguous_buffer_t data;

  // printf("gateway_free_contiguous_buffer\n");

  data.ka = ka;
  data.size = size;

  status = ioctl(fd, GATEWAY_FREE_CONTIGUOUS_BUFFER, &data);

  if (status != 0) {
    printf("[-] gateway_free_contiguous_buffer failed\n");
    return status;
  }

  return 0;
}

int gateway_read_buffer(int fd, byte_t *buffer, kern_addr_t ka, size_t size) {
  int status;
  int i;

  // printf("gateway_read_buffer\n");

  if (size % sizeof(uint64_t)) {
    printf("[-] size must be a multiple of sizeof(uint64_t)\n");
    return -1;
  }

  memset(buffer, 0, size);

  for (i = 0; i < size; i += sizeof(uint64_t)) {
    status = gateway_read_uint64(fd, ka + i, (uint64_t *)&(buffer[i]));

    if (status != 0) {
      printf("[-] gateway_read_buffer failed\n");
      return status;
    }
  }

  return 0;
}

int gateway_write_buffer(int fd, byte_t *buffer, kern_addr_t ka, size_t size) {
  int status;
  int i;

  // printf("gateway_write_buffer\n");

  if (size % sizeof(uint64_t)) {
    printf("[-] size must be a multiple of sizeof(uint64_t)\n");
    return -1;
  }

  for (i = 0; i < size; i += sizeof(uint64_t)) {
    status = gateway_write_uint64(fd, ka + i, *(uint64_t *)&(buffer[i]));

    if (status != 0) {
      printf("[-] gateway_write_buffer failed\n");
      return status;
    }
  }

  return 0;
}

typedef struct {
  uint16_t port;
  uint32_t value;
} gateway_portio_data_t;

int gateway_issue_outb(int fd, uint16_t port, uint8_t value) {
  int status;

  // printf("gateway_issue_outb\n");

  gateway_portio_data_t data;

  data.port = port;
  data.value = value;

  status = ioctl(fd, GATEWAY_IOCTL_ISSUE_OUTB, &data);

  if (status != 0) {
    printf("[-] gateway_issue_outb failed\n");
  }

  return 0;
}

int gateway_issue_inb(int fd, uint16_t port, uint8_t *value) {
  int status;
  gateway_portio_data_t data;

  // printf("gateway_issue_inb\n");

  if (value == NULL) {
    return -1;
  }

  data.port = port;
  data.value = 0;

  status = ioctl(fd, GATEWAY_IOCTL_ISSUE_INB, &data);

  if (status != 0) {
    printf("[-] gateway_issue_inb failed\n");
    return status;
  }

  *value = data.value;

  return status;
}

int gateway_issue_outl(int fd, uint16_t port, uint32_t value) {
  int status;

  // printf("gateway_issue_outl\n");

  gateway_portio_data_t data;

  data.port = port;
  data.value = value;

  status = ioctl(fd, GATEWAY_IOCTL_ISSUE_OUTL, &data);

  if (status != 0) {
    printf("[-] gateway_issue_outb failed\n");
  }

  return 0;
}

int gateway_issue_inl(int fd, uint16_t port, uint32_t *value) {
  int status;
  gateway_portio_data_t data;

  // printf("gateway_issue_inl\n");

  if (value == NULL) {
    return -1;
  }

  data.port = port;
  data.value = 0;

  status = ioctl(fd, GATEWAY_IOCTL_ISSUE_INL, &data);

  if (status != 0) {
    printf("[-] gateway_issue_inb failed\n");
    return status;
  }

  *value = data.value;

  return 0;
}

typedef struct {
  uint64_t rax;
  uint64_t rcx;
  uint64_t rdx;
  uint64_t r8;
  uint64_t r9;
  uint64_t r10;
  uint64_t r11;
  uint64_t r12;
  uint64_t r13;
} gateway_issue_seamcall_tdcall_data_t;

int gateway_issue_seamcall(int fd, uint64_t *rax, uint64_t *rcx, uint64_t *rdx,
                         uint64_t *r8, uint64_t *r9, uint64_t *r10,
                         uint64_t *r11, uint64_t *r12, uint64_t *r13) {
  int status;
  gateway_issue_seamcall_tdcall_data_t data;

  // printf("gateway_issue_seamcall: 0x%lx\n", value);

  if (rax == NULL) {
    return -1;
  }

  data.rax = *rax;

  if (rcx != NULL) {
    data.rcx = *rcx;
  }

  if (rdx != NULL) {
    data.rdx = *rdx;
  }

  if (r8 != NULL) {
    data.r8 = *r8;
  }

  if (r9 != NULL) {
    data.r9 = *r9;
  }

  if (r10 != NULL) {
    data.r10 = *r10;
  }

  if (r11 != NULL) {
    data.r11 = *r11;
  }
  
  if (r12 != NULL) {
    data.r12 = *r12;
  }

  if (r13 != NULL) {
    data.r13 = *r13;
  }

  status = ioctl(fd, GATEWAY_IOCTL_ISSUE_SEAMCALL, &data);

  if (status != 0) {
    printf("[-] gateway_issue_seamcall failed\n");
    return status;
  }

  if (r13 != NULL) {
    *r13 = data.r13;
  }

  if (r12 != NULL) {
    *r12 = data.r12;
  }

  if (r11 != NULL) {
    *r11 = data.r11;
  }

  if (r10 != NULL) {
    *r10 = data.r10;
  }

  if (r9 != NULL) {
    *r9 = data.r9;
  }

  if (r8 != NULL) {
    *r8 = data.r8;
  }

  if (rdx != NULL) {
    *rdx = data.rdx;
  }

  if (rcx != NULL) {
    *rcx = data.rcx;
  }

  *rax = data.rax;

  return 0;
}

int gateway_issue_tdcall(int fd, uint64_t *rax, uint64_t *rcx, uint64_t *rdx,
                       uint64_t *r8, uint64_t *r9, uint64_t *r10,
                       uint64_t *r11, uint64_t *r12, uint64_t *r13) {
  int status;
  gateway_issue_seamcall_tdcall_data_t data;

  // printf("gateway_issue_tdcall: 0x%lx\n", value);

  if (rax == NULL) {
    return -1;
  }

  data.rax = *rax;

  if (rcx != NULL) {
    data.rcx = *rcx;
  }

  if (rdx != NULL) {
    data.rdx = *rdx;
  }

  if (r8 != NULL) {
    data.r8 = *r8;
  }

  if (r9 != NULL) {
    data.r9 = *r9;
  }

  if (r10 != NULL) {
    data.r10 = *r10;
  }

  if (r11 != NULL) {
    data.r11 = *r11;
  }

  if (r12 != NULL) {
    data.r12 = *r12;
  }

  if (r13 != NULL) {
    data.r13 = *r13;
  }
  
  status = ioctl(fd, GATEWAY_IOCTL_ISSUE_TDCALL, &data);

  if (status != 0) {
    printf("[-] gateway_issue_tdcall failed\n");
    return status;
  }

  if (r13 != NULL) {
    *r13 = data.r13;
  }

  if (r12 != NULL) {
    *r12 = data.r12;
  }

  
  if (r11 != NULL) {
    *r11 = data.r11;
  }

  if (r10 != NULL) {
    *r10 = data.r10;
  }

  if (r9 != NULL) {
    *r9 = data.r9;
  }

  if (r8 != NULL) {
    *r8 = data.r8;
  }

  if (rdx != NULL) {
    *rdx = data.rdx;
  }

  if (rcx != NULL) {
    *rcx = data.rcx;
  }

  *rax = data.rax;

  return 0;
}

typedef struct {
  uint32_t identifier;
  uint64_t value;
} gateway_issue_rdmsr_wrmsr_t;

int gateway_issue_rdmsr(int fd, uint32_t identifier, uint64_t *value) {
  int status;
  gateway_issue_rdmsr_wrmsr_t data;

  // printf("gateway_issue_rdmsr: 0x%lx\n", value);

  data.identifier = identifier;
  data.value = 0;

  status = ioctl(fd, GATEWAY_IOCTL_ISSUE_RDMSR, &data);

  if (status != 0) {
    printf("[-] gateway_issue_rdmsr failed\n");
    return status;
  }

  *value = data.value;

  return 0;
}

int gateway_issue_wrmsr(int fd, uint32_t identifier, uint64_t value) {
  int status;
  gateway_issue_rdmsr_wrmsr_t data;

  // printf("gateway_issue_wrmsr: 0x%lx\n", value);

  data.identifier = identifier;
  data.value = value;

  status = ioctl(fd, GATEWAY_IOCTL_ISSUE_WRMSR, &data);

  if (status != 0) {
    printf("[-] gateway_issue_wrmsr failed\n");
    return status;
  }

  return 0;
}

typedef struct {
  int pid;
  unsigned int fd;
  kern_addr_t f;
  uint32_t f_mode_offset;
  uint32_t private_data_offset;
} gateway_fd_get_put_t;

int gateway_fdget(int fd, int pid, unsigned int tgt, kern_addr_t *f,
                uint32_t *f_mode_offset, uint32_t *private_data_offset) {
  int status;
  gateway_fd_get_put_t data;

  // printf("gateway_fdget\n");

  if (f == NULL) {
    printf("[-] f is NULL\n");
    return -1;
  }

  memset(&data, 0, sizeof(data));

  data.pid = pid;
  data.fd = tgt;

  // printf("pid: %d, fd: %d\n", pid, tgt);

  status = ioctl(fd, GATEWAY_IOCTL_FDGET, &data);

  if (status != 0) {
    printf("[-] gateway_fdget failed\n");
    return status;
  }

  *f = data.f;

  if (f_mode_offset != NULL) {
    *f_mode_offset = data.f_mode_offset;
  }

  if (private_data_offset != NULL) {
    *private_data_offset = data.private_data_offset;
  }

  return 0;
}

int gateway_fdput(int fd, kern_addr_t f) {
  int status;
  gateway_fd_get_put_t data;

  // printf("gateway_fdput\n");

  memset(&data, 0, sizeof(data));

  data.f = f;

  status = ioctl(fd, GATEWAY_IOCTL_FDPUT, &data);

  if (status != 0) {
    printf("[-] gateway_fdput failed\n");
    return status;
  }

  return 0;
}

#ifdef ENABLE_ISSUE_VMX

typedef struct {
  uint64_t identifier;
  uint64_t value;
} gateway_issue_vmx_data_t;

int gateway_issue_vmclear(int fd, phys_addr_t pa) {
  int status;
  gateway_issue_vmx_data_t data;

  data.identifier = 0;
  data.value = pa;

  status = ioctl(fd, GATEWAY_IOCTL_ISSUE_VMCLEAR, &data);

  if (status != 0) {
    printf("[-] gateway_issue_vmclear failed\n");
    return status;
  }

  return 0;
}

int gateway_issue_vmlaunch(int fd) {
  int status;
  gateway_issue_vmx_data_t data;

  data.identifier = 0;
  data.value = 0;

  status = ioctl(fd, GATEWAY_IOCTL_ISSUE_VMLAUNCH, &data);

  if (status != 0) {
    printf("[-] gateway_issue_vmlaunch failed\n");
    return status;
  }

  return 0;
}

int gateway_issue_vmresume(int fd) {
  int status;
  gateway_issue_vmx_data_t data;

  data.identifier = 0;
  data.value = 0;

  status = ioctl(fd, GATEWAY_IOCTL_ISSUE_VMRESUME, &data);

  if (status != 0) {
    printf("[-] gateway_issue_vmresume failed\n");
    return status;
  }

  return 0;
}

int gateway_issue_vmxoff(int fd) {
  int status;
  gateway_issue_vmx_data_t data;

  data.identifier = 0;
  data.value = 0;

  status = ioctl(fd, GATEWAY_IOCTL_ISSUE_VMXOFF, &data);

  if (status != 0) {
    printf("[-] gateway_issue_vmxoff failed\n");
    return status;
  }

  return 0;
}

int gateway_issue_vmxon(int fd, phys_addr_t pa) {
  int status;
  gateway_issue_vmx_data_t data;

  data.identifier = 0;
  data.value = pa;

  status = ioctl(fd, GATEWAY_IOCTL_ISSUE_VMXON, &data);

  if (status != 0) {
    printf("[-] gateway_issue_vmxon failed\n");
    return status;
  }

  return 0;
}

int gateway_issue_vmread(int fd, uint64_t identifier, uint64_t *value) {
  int status;
  gateway_issue_vmx_data_t data;

  if (value == NULL) {
    return -1;
  }

  data.identifier = identifier;
  data.value = 0;

  status = ioctl(fd, GATEWAY_IOCTL_ISSUE_VMREAD, &data);

  if (status != 0) {
    printf("[-] gateway_issue_vmread failed\n");
    return status;
  }

  *value = data.value;

  return 0;
}

int gateway_issue_vmwrite(int fd, uint64_t identifier, uint64_t value) {
  int status;
  gateway_issue_vmx_data_t data;

  data.identifier = identifier;
  data.value = value;

  status = ioctl(fd, GATEWAY_IOCTL_ISSUE_VMWRITE, &data);

  if (status != 0) {
    printf("[-] gateway_issue_vmwrite failed\n");
    return status;
  }

  return 0;
}

int gateway_issue_vmptrld(int fd, phys_addr_t pa) {
  int status;
  gateway_issue_vmx_data_t data;

  data.identifier = 0;
  data.value = pa;

  status = ioctl(fd, GATEWAY_IOCTL_ISSUE_VMPTRLD, &data);

  if (status != 0) {
    printf("[-] gateway_issue_vmptrld failed\n");
    return status;
  }

  return 0;
}

int gateway_issue_vmptrst(int fd, phys_addr_t *pa) {
  int status;
  gateway_issue_vmx_data_t data;

  if (pa == NULL) {
    return -1;
  }

  data.identifier = 0;
  data.value = 0;

  status = ioctl(fd, GATEWAY_IOCTL_ISSUE_VMPTRST, &data);

  if (status != 0) {
    printf("[-] gateway_issue_vmptrst failed\n");
    return status;
  }

  *pa = data.value;

  return 0;
}

#endif  // ENABLE_ISSUE_VMX

typedef struct {
  uint32_t cpu;
  uint32_t count;
  uint32_t delay;
} gateway_reschedule_data_t;

int gateway_reschedule(int fd, uint32_t cpu, uint32_t count, uint32_t delay) {
  int status;
  gateway_reschedule_data_t data;

  data.cpu = cpu;
  data.count = count;
  data.delay = delay;
  
  status = ioctl(fd, GATEWAY_IOCTL_RESCHEDULE, &data);

  if (status != 0) {
    printf("[-] gateway_reschedule failed\n");
    return status;
  }

  return 0;
}

typedef struct {
  uint32_t cpu;
  uint32_t count;
  uint32_t delay;
} gateway_ipi_storm_data_t;

int gateway_ipi_storm(int fd, uint32_t cpu, uint32_t count, uint32_t delay) {
  int status;
  gateway_ipi_storm_data_t data;

  // printf("gateway_ipi_storm: 0x%lx\n", value);

  data.cpu = cpu;
  data.count = count;
  data.delay = delay;

  status = ioctl(fd, GATEWAY_IOCTL_IPI_STORM, &data);

  if (status != 0) {
    printf("[-] gateway_ipi_storm failed\n");
    return status;
  }

  return 0;
}

int gateway_set_thread_affinity(pthread_t thread, uint32_t core) {
  cpu_set_t cpuset;
  int status;

  // printf("thread_set_affinity\n");

  CPU_ZERO(&cpuset);
  CPU_SET(core, &cpuset);

  status = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
  if (status != 0) {
    return status;
  }

  // printf("thread id: %lu executing on core: %d\n", (unsigned long)thread,
  // core);

  return 0;
}

int gateway_set_process_priority(int policy, int priority) {
  // SCHED_NORMAL - default divided among runnable processes
  // SCHED_FIFO - real-time runs until they block
  // SCHED_BATCH - non-interactive jobs that don't require rapid responses
  // SCHED_DEADLINE -
  // SCHED_RR - round robin real-time similar to SCHED_FIFO
  // SCHED_IDLE - only run when the cpu is idle

  struct sched_param param;
  int status;

  param.sched_priority = priority;
  status = sched_setscheduler(0, policy, &param);

  return status;
}

void *gateway_load_file(const char *filename, size_t *size) {
  FILE *fp;
  void *buffer;

  printf("gateway_load_file\n");

  buffer = NULL;

  fp = fopen(filename, "rb");
  if (fp < 0) {
    printf("[-] failed to open file: %s\n", filename);
    goto cleanup;
  }

  if (fseek(fp, 0, SEEK_END) != 0) {
    printf("Error seeking to the end of the file");
    goto cleanup;
  }
  *size = ftell(fp);
  if (*size == -1L) {
    printf("Error getting the file size");
    goto cleanup;
  }

  if (fseek(fp, 0, SEEK_SET) != 0) {
    printf("Error seeking to start of file");
    goto cleanup;
  }

  buffer = malloc(*size);

  if (buffer == NULL) {
    printf("Error allocating %ld sized buffer\n", *size);
    goto cleanup;
  }

  if (fread(buffer, 1, *size, fp) != *size) {
    printf("Error reading the file\n");
    goto cleanup;
  }

  fclose(fp);

  return buffer;

cleanup:

  if (buffer != NULL) {
    free(buffer);
  }

  if (fp > 0) {
    fclose(fp);
  }

  return NULL;
}

void gateway_hexdump(uint8_t *buf, size_t len) {
  int i;
  for (i = 0; i < len; i++) {
    if (i % 16 == 0) {
      if (i != 0) {
        printf("\n");
      }
      printf("%08x: ", i);
    }
    printf("%02x ", buf[i]);
  }
  printf("\n");
}
