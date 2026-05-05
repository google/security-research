#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef ENABLE_ISSUE_PORTIO
#include <sys/io.h>
#endif  // ENABLE_ISSUE_PORTIO

#include <pthread.h>

#define FOUR_KILOBYTES (4 * 1024)
#define ONE_MEGABYTE (1024 * 1024ULL)
#define TWO_MEGABYTES (2 * ONE_MEGABYTE)
#define ONE_GIGABYTE (1024 * ONE_MEGABYTE)

#ifdef ENABLE_ISSUE_PORTIO
#define gateway_ioperm(from, count, enable) ioperm(from, count, enable)

#define gateway_inb(port) inb(port)
#define gateway_outb(value, port) outb(value, port)

#define gateway_inw(port) inw(port)
#define gateway_outw(value, port) outw(value, port)

#define gateway_inl(port) inl(port)
#define gateway_outl(value, port) outl(value, port)
#endif  // ENABLE_ISSUE_PORTIO

typedef unsigned char byte_t;
typedef uint64_t phys_addr_t;
typedef uint64_t virt_addr_t;
typedef uint64_t kern_addr_t;

int gateway_open(char* path);
void gateway_close(int fd);

void* gateway_mmap(int fd, phys_addr_t address, size_t size);
int gateway_munmap(int fd, void* buffer, size_t size);

void gateway_memset(void* dst, int value, size_t size);

void gateway_memcpy(void* dst, void* src, size_t size);

int gateway_read_uint64(int fd, kern_addr_t ka, uint64_t* value);
int gateway_read_buffer(int fd, byte_t* buffer, kern_addr_t ka, size_t size);

int gateway_write_uint64(int fd, kern_addr_t ka, uint64_t value);
int gateway_write_buffer(int fd, byte_t* buffer, kern_addr_t ka, size_t size);

int gateway_alloc_contiguous_buffer(int fd, size_t size, kern_addr_t* ka,
                                    phys_addr_t* pa);
int gateway_free_contiguous_buffer(int fd, kern_addr_t ka, size_t size);

#ifdef GATEWAY_ENABLE_ISSUE_PORTIO
int gateway_issue_outb(int fd, uint16_t port, uint8_t value);
int gateway_issue_inb(int fd, uint16_t port, uint8_t* value);

int gateway_issue_outl(int fd, uint16_t port, uint32_t value);
int gateway_issue_inl(int fd, uint16_t port, uint32_t* value);
#endif  // GATEWAY_ENABLE_ISSUE_PORTIO

#ifdef GATEWAY_ENABLE_ISSUE_SEAMCALL_TDCALL
int gateway_issue_seamcall(int fd, uint64_t* rax, uint64_t* rcx, uint64_t* rdx,
                           uint64_t* r8, uint64_t* r9, uint64_t* r10,
                           uint64_t* r11, uint64_t* r12, uint64_t* r13);
int gateway_issue_tdcall(int fd, uint64_t* rax, uint64_t* rcx, uint64_t* rdx,
                         uint64_t* r8, uint64_t* r9, uint64_t* r10,
                         uint64_t* r11, uint64_t* r12, uint64_t* r13);
#endif  // GATEWAY_ENABLE_ISSUE_SEAMCALL_TDCALL

#ifdef GATEWAY_ENABLE_ISSUE_RDMSR_WRMSR
int gateway_issue_rdmsr(int fd, uint32_t identifier, uint64_t* value);
int gateway_issue_wrmsr(int fd, uint32_t identifier, uint64_t value);
#endif  // GATEWAY_ENABLE_ISSUE_RDMSR_WRMSR

int gateway_fdget(int fd, int pid, unsigned int tgt, kern_addr_t* f,
                  uint32_t* f_mode_offset, uint32_t* private_data_offset);
int gateway_fdput(int fd, kern_addr_t f);

#ifdef ENABLE_ISSUE_VMX
int gateway_issue_vmclear(int fd, phys_addr_t value);
int gateway_issue_vmlaunch(int fd);
int gateway_issue_vmresume(int fd);
int gateway_issue_vmxoff(int fd);
int gateway_issue_vmxon(int fd, phys_addr_t value);
int gateway_issue_vmread(int fd, uint64_t identifier, uint64_t* value);
int gateway_issue_vmwrite(int fd, uint64_t identifier, uint64_t value);
int gateway_issue_vmptrld(int fd, phys_addr_t pa);
int gateway_issue_vmptrst(int fd, phys_addr_t* pa);
#endif  // ENABLE_ISSUE_VMX

int gateway_reschedule(int fd, uint32_t cpu, uint32_t count, uint32_t delay);

int gateway_ipi_storm(int fd, uint32_t cpu, uint32_t count, uint32_t delay);

int gateway_set_thread_affinity(pthread_t thread, uint32_t core);
int gateway_set_process_priority(int policy, int priority);

void* gateway_load_file(const char* filename, size_t* size);
void gateway_hexdump(uint8_t* buf, size_t len);
