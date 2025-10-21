#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h> 

// choose_random_location is the function set KASLR
// -  find_random_phys_addr for phys_map
// -  find_random_virt_addr for kernel




// There is less than 9 bits randomization for kernel image 

// The following code comes from https://elixir.bootlin.com/linux/v6.11/source/arch/x86/boot/compressed/kaslr.c#L796
// which enables KASLR

    // static unsigned long find_random_virt_addr(unsigned long minimum,
    // 					   unsigned long image_size)
    // {
    // 	unsigned long slots, random_addr;

    // 	/*
    // 	 * There are how many CONFIG_PHYSICAL_ALIGN-sized slots
    // 	 * that can hold image_size within the range of minimum to
    // 	 * KERNEL_IMAGE_SIZE?
    // 	 */
    // 	slots = 1 + (KERNEL_IMAGE_SIZE - minimum - image_size) / CONFIG_PHYSICAL_ALIGN;

    // 	random_addr = kaslr_get_random_long("Virtual") % slots;

    // 	return random_addr * CONFIG_PHYSICAL_ALIGN + minimum;
    // }
// From the code, we have:
/*
    - KERNEL_IMAGE_SIZE = 0x40000000 (CONFIG_RANDOMIZE_BASE=y)
    - minimum = 0x1000000
    - CONFIG_PHYSICAL_ALIGN = 0x0x200000
    - img_size is depedned on the image loaded

    ------------------------------------------------------
    slots <- 1+(0x40000000-0x1000000-img_size) / 0x200000
    if 
        img_size > 0
    then 
        slots < 505
    There is not much randomazation in Kernel Text 
*/

// Do the similar computing for Phys_map area and found it has 16-bit randomization
// 2M
#define STEP                        0x200000ull // CONFIG_PHYSICAL_ALIGN=0x200000
#define KERNEL_LOWER_BOUND          0xffffffff80000000ull
#define KERNEL_UPPER_BOUND          0xffffffffc0000000ull
#define entry_SYSCALL_64_offset     0x1400000ull
#define SCAN_START                  KERNEL_LOWER_BOUND 
#define SCAN_END                    KERNEL_UPPER_BOUND 
#define ARR_SIZE                    (SCAN_END - SCAN_START) / STEP





// 0x40000000 == 1GB which is slot_areas's step
// 1GB
#define STEP_PHYS                           0x40000000ull
#define PHYS_LOWER_BOUND            0xffff887000000000ull
#define PHYS_UPPER_BOUND            0xffffa45555555555ull
                                    
#define SCAN_START_PHYS             PHYS_LOWER_BOUND
#define SCAN_END_PHYS               PHYS_UPPER_BOUND
#define ARR_SIZE_PHYS               (SCAN_END_PHYS - SCAN_START_PHYS) / STEP_PHYS



#define DUMMY_ITERATIONS            2ull
#define ITERATIONS                  12ull




#define size_t                      unsigned long long 
typedef unsigned char       u8;
typedef unsigned short      u16;
typedef unsigned int        u32;
typedef unsigned long long  u64;

size_t get_kaslr_precise(int pti);