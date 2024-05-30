#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/atomic.h>
#include <linux/delay.h>

#define UINT32_MAX U32_MAX

// How many CPU cores to scan MSRs on.
#define NUM_THREADS 8

// The first and last MSR you want to test.
const static uint32_t kFirstMSR = 0xc0000000;
const static uint32_t kFinalMSR = 0xc0100000;

struct msr_scan_range {
    uint32_t start;
    uint32_t stop;
};

static struct task_struct * kmsrscan[NUM_THREADS];
static struct msr_scan_range kmsrrange[NUM_THREADS];

// This is a blocklist of chicken bits known to cause instability just by
// flipping them, and so should not be tested.
static const bool msr_c001_range_unsafe[][64] = {
    [0x0010][21 ... 22]     = true,     // MSR_AMD64_SYSCFG verified
    [0x0017][11]            = true,     // verified
    [0x0019][11]            = true,     // verified
    [0x001d][34]            = true,     // MSR_K8_TOP_MEM2 verified
    [0x001d][35]            = true,     // crashes rembrandt
    [0x0020][0 ... 63]      = true,     // MSR_AMD64_PATCH_LOADER verified
    [0x0058][5]             = true,     // MSR_FAM10H_MMIO_CONF_BASE verified
    [0x1029][27]            = true,     // MSR_AMD64_DE_CFG verified
    [0x1092][27]            = true,     // verified
    [0x10e1][14 ... 17]     = true,     // verified
    [0x10e1][20]            = true,     // verified
    [0x10e1][22 ... 25]     = true,     // verified
    [0x10e1][32 ... 38]     = true,     // verified
    [0x10e1][52 ... 57]     = true,     // verified
    [0x10e1][58]            = true,     // verified
    [0x10e1][59 ... 62]     = true,     // verified
};
static const bool msr_c000_range_unsafe[][64] = {
    [0x0080][0]             = true,     // MSR_EFER
    [0x0080][8]             = true,
    [0x0080][10 ... 14]     = true,
    [0x0080][21]            = true,
    [0x0081][0 ... 63]      = true,     // MSR_STAR
    [0x0082][0 ... 63]      = true,     // MSR_LSTAR
    [0x0083][0 ... 63]      = true,     // MSR_CSTAR
    [0x0084][0 ... 63]      = true,     // MSR_SYSCALL_MASK
    [0x0100][0 ... 63]      = true,     // MSR_FS_BASE
    [0x0101][0 ... 63]      = true,     // MSR_GS_BASE
    [0x0102][0 ... 63]      = true,     // MSR_KERNEL_GS_BASE
    [0x0103][0 ... 63]      = true,     // MSR_TSC_AUX
    [0x0104][0 ... 63]      = true,     // MSR_AMD64_TSC_RATIO
};
static const bool msr_0000_range_unsafe[][64] = {
    [0x001a][0 ... 63]      = true,
    [0x001b][0 ... 63]      = true,     // MSR_IA32_APICBASE
    [0x0174][0 ... 63]      = true,     // MSR_IA32_SYSENTER_CS
    [0x0175][0 ... 63]      = true,     // MSR_IA32_SYSENTER_ESP
    [0x0176][0 ... 63]      = true,     // MSR_IA32_SYSENTER_EIP
    [0x01a6][0 ... 53]      = true,     // MSR_OFFCORE_RSP_0
    [0x01a7][0 ... 53]      = true,     // MSR_OFFCORE_RSP_1
    [0x01ad][0 ... 53]      = true,     // MSR_TURBO_RAIO_LIMIT
    [0x01ae][0 ... 53]      = true,     // MSR_TURBO_RAIO_LIMIT1
    [0x01af][0 ... 53]      = true,     // MSR_TURBO_RAIO_LIMIT2
    [0x01fc][0 ... 63]      = true,     // MSR_IA32_POWER_CTL
    [0x01ff][0 ... 63]      = true,
    [0x0200][0 ... 63]      = true,
    [0x0206][0 ... 63]      = true,
    [0x0207][0 ... 63]      = true,
    [0x0209][0 ... 63]      = true,
    [0x020a][0 ... 63]      = true,
    [0x020b][0 ... 63]      = true,
    [0x020c][0 ... 63]      = true,
    [0x020d][0 ... 63]      = true,
    [0x020e][0 ... 63]      = true,
    [0x020f][0 ... 63]      = true,
    [0x02ff][0 ... 63]      = true,
};

static inline bool check_msr_unsafe(uint32_t msr, uint8_t bit)
{
    uint16_t hi = msr >> 16;
    uint16_t lo = msr & 0xffff;

    if (hi == 0xc001 && lo < ARRAY_SIZE(msr_c001_range_unsafe)) {
        return msr_c001_range_unsafe[lo][bit];
    }

    if (hi == 0xc000 && lo < ARRAY_SIZE(msr_c000_range_unsafe)) {
        return msr_c000_range_unsafe[lo][bit];
    }

    if (hi == 0x0000 && lo < ARRAY_SIZE(msr_0000_range_unsafe)) {
        return msr_0000_range_unsafe[lo][bit];
    }

    return false;
}

// This is where the thread sets random chicken bits.
static int kthread_scan_msrs(struct msr_scan_range *rng)
{
    uint64_t value;
    uint32_t msr;
    uint8_t bit;

    for (msr = rng->start; msr < rng->stop; msr++) {

        // Check if we are supposed to abort.
        if (kthread_should_stop())
            break;

        if ((msr & 0x1ff) == 0) {
            printk(KERN_INFO "cpu %d testing msr %#x... (%u%%)\n",
                    smp_processor_id(),
                    msr,
                    (msr - rng->start) / ((rng->stop - rng->start) / 100));
        }

        // Be nice to system...
        cond_resched();

        // First learn the existing value.
        value = __rdmsr(msr);

        // Disable interrupts during testing.
        local_irq_disable();

        for (bit = 0; bit < 64; bit++) {
            // Check if we know this bit is bad.
            if (check_msr_unsafe(msr, bit))
                continue;

#if 1
            printk(KERN_INFO "msr %#x bit %u\n", msr, bit);
            msleep(50);
            cond_resched();
#endif
            // Okay, begin the test.
            wrmsrl(msr, value ^ (1ULL << bit));

            // XXX: PERFORM TESTING HERE
            // xxx
            // xxx
            // xxx

            // Test complete, restore previous value.
            wrmsrl(msr, value);
        }

        // Renenable interrupts.
        local_irq_enable();
    }

    printk(KERN_INFO "cpu %d completed scanning msrs\n", smp_processor_id());

    return 0;
}

static int __init kmod_init(void)
{
    uint32_t range;

    printk(KERN_INFO "kernel module is loaded\n");

    // How many msrs we have to test.
    range = kFinalMSR - kFirstMSR;

    for (int i = 0; i < NUM_THREADS; i++) {
        // Yes, this might miss a few.
        kmsrrange[i].start = kFirstMSR + ((i + 0) * (range / NUM_THREADS));
        kmsrrange[i].stop  = kFirstMSR + ((i + 1) * (range / NUM_THREADS));

        kmsrscan[i] = kthread_create((void *)kthread_scan_msrs, &kmsrrange[i], "kmsrscan");

        // Assign this thread to a specific core.
        kthread_bind(kmsrscan[i], i);

        // Okay, Go.
        wake_up_process(kmsrscan[i]);
    }
    return 0;
}

static void __exit kmod_exit(void)
{
    printk(KERN_INFO "kernel module is stopping threads...\n");

    for (int i = 0; i < NUM_THREADS; i++)
        kthread_stop(kmsrscan[i]);

    printk(KERN_INFO "Complete.\n");
    return;
}

module_init(kmod_init);
module_exit(kmod_exit);

MODULE_LICENSE("GPL v2");
