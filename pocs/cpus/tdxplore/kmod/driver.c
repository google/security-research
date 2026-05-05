#include <asm/uaccess.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/efi.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/kdev_t.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/kvm_host.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/workqueue.h>

#include "config.h"
#include "ioctl.h"

#define GATEWAY_IOC_MAGIC 7342

#define GATEWAY_GET_MAGIC_VALUE _IOR(GATEWAY_IOC_MAGIC, 0, uint64_t)
#define GATEWAY_READ_UINT64 _IOR(GATEWAY_IOC_MAGIC, 1, void*)
#define GATEWAY_WRITE_UINT64 _IOW(GATEWAY_IOC_MAGIC, 2, void*)

#ifdef ENABLE_ALLOC_FREE_CONTIGUOUS_BUFFER
#define GATEWAY_ALLOC_CONTIGUOUS_BUFFER _IOWR(GATEWAY_IOC_MAGIC, 5, void*)
#define GATEWAY_FREE_CONTIGUOUS_BUFFER _IOW(GATEWAY_IOC_MAGIC, 6, void*)
#endif  // ENABLE_ALLOC_FREE_CONTIGUOUS_BUFFER

#ifdef ENABLE_ISSUE_PORTIO
#define GATEWAY_ISSUE_OUTB _IOW(GATEWAY_IOC_MAGIC, 7, void*)
#define GATEWAY_ISSUE_INB _IOR(GATEWAY_IOC_MAGIC, 8, void*)
#define GATEWAY_ISSUE_OUTW _IOW(GATEWAY_IOC_MAGIC, 9, void*)
#define GATEWAY_ISSUE_INW _IOR(GATEWAY_IOC_MAGIC, 10, void*)
#define GATEWAY_ISSUE_OUTL _IOW(GATEWAY_IOC_MAGIC, 11, void*)
#define GATEWAY_ISSUE_INL _IOR(GATEWAY_IOC_MAGIC, 12, void*)
#endif  // ENABLE_ISSUE_PORTIO

#ifdef ENABLE_ISSUE_SEAMCALL_TDCALL
#define GATEWAY_ISSUE_SEAMCALL _IOWR(GATEWAY_IOC_MAGIC, 15, void*)
#define GATEWAY_ISSUE_TDCALL _IOWR(GATEWAY_IOC_MAGIC, 16, void*)
#endif  // ENABLE_ISSUE_SEAMCALL_TDCALL

#ifdef ENABLE_ISSUE_RDMSR_WRMSR
#define GATEWAY_ISSUE_RDMSR _IOR(GATEWAY_IOC_MAGIC, 17, void*)
#define GATEWAY_ISSUE_WRMSR _IOW(GATEWAY_IOC_MAGIC, 18, void*)
#endif  // ENABLE_ISSUE_RDMSR_WRMSR]

#ifdef ENABLE_UNEXPORTED_SYMBOLS
#define GATEWAY_IOCTL_FDGET _IOWR(GATEWAY_IOC_MAGIC, 19, void*)
#define GATEWAY_IOCTL_FDPUT _IOR(GATEWAY_IOC_MAGIC, 20, void*)
#endif  // ENABLE_UNEXPORTED_SYMBOLS

#ifdef ENABLE_ISSUE_VMX
#define GATEWAY_IOCTL_ISSUE_VMCLEAR _IOWR(GATEWAY_IOC_MAGIC, 21, void*)
#define GATEWAY_IOCTL_ISSUE_VMLAUNCH _IOWR(GATEWAY_IOC_MAGIC, 22, void*)
#define GATEWAY_IOCTL_ISSUE_VMRESUME _IOWR(GATEWAY_IOC_MAGIC, 23, void*)
#define GATEWAY_IOCTL_ISSUE_VMXOFF _IOWR(GATEWAY_IOC_MAGIC, 24, void*)
#define GATEWAY_IOCTL_ISSUE_VMXON _IOWR(GATEWAY_IOC_MAGIC, 25, void*)
#define GATEWAY_IOCTL_ISSUE_VMREAD _IOR(GATEWAY_IOC_MAGIC, 26, void*)
#define GATEWAY_IOCTL_ISSUE_VMWRITE _IOW(GATEWAY_IOC_MAGIC, 27, void*)
#define GATEWAY_IOCTL_ISSUE_VMPTRLD _IOWR(GATEWAY_IOC_MAGIC, 28, void*)
#define GATEWAY_IOCTL_ISSUE_VMPTRST _IOWR(GATEWAY_IOC_MAGIC, 29, void*)
#endif  // ENABLE_ISSUE_VMX

#define GATEWAY_IOCTL_RESCHEDULE _IOW(GATEWAY_IOC_MAGIC, 30, void*)

#define GATEWAY_IOCTL_IPI_STORM _IOWR(GATEWAY_IOC_MAGIC, 32, void*)

#define GATEWAY_BUFFER_SIZE 0x1000
#define GATEWAY_BLOCK_SIZE 0x200

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kirk Swidowski (swidowski@google.com)");
MODULE_DESCRIPTION("Gateway");
MODULE_VERSION("0.01");

typedef struct {
  unsigned char* _data;
  unsigned long _buf_sz;
  unsigned long _blk_sz;
  struct mutex _mutex;
  struct cdev _cdev;
} gateway_device_t;

#define GATEWAY_DEVICE_NAME "gateway"
int gateway_major = 1;
int gateway_minor = 0;
static struct class* gateway_class = NULL;
gateway_device_t* gateway_device = NULL;

static int gateway_open(struct inode* inodep, struct file* filep) {
  printk(KERN_INFO "gateway_open\n");
  return 0;
}

static int gateway_release(struct inode* inodep, struct file* filep) {
  printk(KERN_INFO "gateway_release\n");
  return 0;
}

static long int gateway_ioctl(struct file* file, unsigned int cmd,
                              unsigned long arg) {
  void __user* p = (void __user*)arg;

  // printk(KERN_INFO "IOCTL %#08x called\n", cmd);

  switch (cmd) {
    case GATEWAY_GET_MAGIC_VALUE:
      break;
    case GATEWAY_READ_UINT64:
      // printk(KERN_INFO "Reading UINT64\n");
      return ioctl_read_uint64(p);
    case GATEWAY_WRITE_UINT64:
      // printk(KERN_INFO "Writing UINT64\n");
      return ioctl_write_uint64(p);

#ifdef ENABLE_ALLOC_FREE_CONTIGUOUS_BUFFER
    case GATEWAY_ALLOC_CONTIGUOUS_BUFFER:
      printk(KERN_INFO "Allocing Contiguous Buffer\n");
      return ioctl_alloc_contiguous_buffer(p);
    case GATEWAY_FREE_CONTIGUOUS_BUFFER:
      printk(KERN_INFO "Freeing Contiguous Buffer\n");
      return ioctl_free_contiguous_buffer(p);
#endif  // ENABLE_ALLOC_FREE_CONTIGUOUS_BUFFER

#ifdef ENABLE_ISSUE_PORTIO
    case GATEWAY_ISSUE_OUTB:
      printk(KERN_INFO "Issuing OUTB\n");
      return ioctl_issue_outb(p);
    case GATEWAY_ISSUE_INB:
      printk(KERN_INFO "Issuing INB\n");
      return ioctl_issue_inb(p);
    case GATEWAY_ISSUE_OUTW:
      printk(KERN_INFO "Issuing OUTW\n");
      return ioctl_issue_outw(p);
    case GATEWAY_ISSUE_INW:
      printk(KERN_INFO "Issuing INW\n");
      return ioctl_issue_inw(p);
    case GATEWAY_ISSUE_OUTL:
      printk(KERN_INFO "Issuing OUTL\n");
      return ioctl_issue_outl(p);
    case GATEWAY_ISSUE_INL:
      printk(KERN_INFO "Issuing INL\n");
      return ioctl_issue_inl(p);
#endif  // ENABLE_ISSUE_PORTIO

#ifdef ENABLE_ISSUE_SEAMCALL_TDCALL
    case GATEWAY_ISSUE_SEAMCALL:
      printk(KERN_INFO "Issue SEAMCALL\n");
      return ioctl_issue_seamcall(p);
    case GATEWAY_ISSUE_TDCALL:
      printk(KERN_INFO "Issue TDCALL\n");
      return ioctl_issue_tdcall(p);
#endif  // ENABLE_ISSUE_SEAMCALL_TDCALL

#ifdef ENABLE_ISSUE_RDMSR_WRMSR
    case GATEWAY_ISSUE_RDMSR:
      printk(KERN_INFO "Issue RDMSR\n");
      return ioctl_issue_rdmsr(p);
    case GATEWAY_ISSUE_WRMSR:
      printk(KERN_INFO "Issue WRMSR\n");
      return ioctl_issue_wrmsr(p);
#endif  // ENABLE_ISSUE_RDMSR_WRMSR

#ifdef ENABLE_UNEXPORTED_SYMBOLS
    case GATEWAY_IOCTL_FDGET:
      printk(KERN_INFO "GetFD\n");
      return ioctl_fdget(p);
    case GATEWAY_IOCTL_FDPUT:
      printk(KERN_INFO "PutFD\n");
      return ioctl_fdput(p);
#endif  // ENABLE_UNEXPORTED_SYMBOLS

#ifdef ENABLE_ISSUE_VMX
    case GATEWAY_IOCTL_ISSUE_VMCLEAR:
      printk(KERN_INFO "Issue VMCLEAR\n");
      return ioctl_issue_vmclear(p);
    case GATEWAY_IOCTL_ISSUE_VMLAUNCH:
      printk(KERN_INFO "Issue VMLAUNCH\n");
      return ioctl_issue_vmlaunch(p);
    case GATEWAY_IOCTL_ISSUE_VMRESUME:
      printk(KERN_INFO "Issue VMRESUME\n");
      return ioctl_issue_vmresume(p);
    case GATEWAY_IOCTL_ISSUE_VMXOFF:
      printk(KERN_INFO "Issue VMXOFF\n");
      return ioctl_issue_vmxoff(p);
    case GATEWAY_IOCTL_ISSUE_VMXON:
      printk(KERN_INFO "Issue VMXON\n");
      return ioctl_issue_vmxon(p);
    case GATEWAY_IOCTL_ISSUE_VMREAD:
      printk(KERN_INFO "Issue VMREAD\n");
      return ioctl_issue_vmread(p);
    case GATEWAY_IOCTL_ISSUE_VMWRITE:
      printk(KERN_INFO "Issue VMWRITE\n");
      return ioctl_issue_vmwrite(p);
    case GATEWAY_IOCTL_ISSUE_VMPTRLD:
      printk(KERN_INFO "Issue VMPTRLD\n");
      return ioctl_issue_vmptrld(p);
    case GATEWAY_IOCTL_ISSUE_VMPTRST:
      printk(KERN_INFO "Issue VMPTRST\n");
      return ioctl_issue_vmptrst(p);
#endif  // ENABLE_ISSUE_VMX

    case GATEWAY_IOCTL_RESCHEDULE:
      // printk(KERN_INFO "Reschedule\n");
      return ioctl_reschedule(p);

    case GATEWAY_IOCTL_IPI_STORM:
      printk(KERN_INFO "IPI STORM\n");
      return ioctl_ipi_storm(p);
  }

  return 0;
}

static int gateway_mmap(struct file* filp, struct vm_area_struct* vma) {
  unsigned long offset = vma->vm_pgoff;

  if (offset >= __pa(high_memory) || (filp->f_flags & O_SYNC)) {
#ifdef USE_VM_FLAGS_API
    vm_flags_set(vma, VM_IO);
#else
    vma->vm_flags |= VM_IO;
#endif
  }

#ifdef USE_VM_FLAGS_API
  vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);
#else
  vma->vm_flags |= (VM_DONTEXPAND | VM_DONTDUMP);
#endif

  if (io_remap_pfn_range(vma, vma->vm_start, offset,
                         vma->vm_end - vma->vm_start, vma->vm_page_prot)) {
    return -EAGAIN;
  }
  return 0;
}

static struct file_operations fops = {.owner = THIS_MODULE,
                                      .unlocked_ioctl = gateway_ioctl,
                                      .open = gateway_open,
                                      .release = gateway_release,
                                      .mmap = gateway_mmap,
                                      .owner = THIS_MODULE};

static void cleanup(void) {
  printk(KERN_INFO "cleanup\n");

  if (gateway_device) {
    device_destroy(gateway_class, MKDEV(gateway_major, gateway_minor));
    cdev_del(&gateway_device->_cdev);
    kfree(gateway_device->_data);
    mutex_destroy(&gateway_device->_mutex);
    kfree(gateway_device);
  }

  if (gateway_class) {
    class_destroy(gateway_class);
  }

  unregister_chrdev_region(MKDEV(gateway_major, gateway_minor), 1);
}

static int initialize(void) {
  int error;
  struct device* device = NULL;
  dev_t number = 0;

  printk(KERN_INFO "initialize\n");

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
  gateway_class = class_create(THIS_MODULE, GATEWAY_DEVICE_NAME);
#else
  gateway_class = class_create(GATEWAY_DEVICE_NAME);
#endif
  if (IS_ERR(gateway_class)) {
    printk(KERN_WARNING "Error while trying to create class %s\n",
           GATEWAY_DEVICE_NAME);
    error = PTR_ERR(gateway_class);
    goto fail;
  }

  error = alloc_chrdev_region(&number, gateway_minor, 1, GATEWAY_DEVICE_NAME);

  if (error < 0) {
    printk(KERN_ALERT "alloc_chrdev_region failed\n");
    return error;
  }

  gateway_major = MAJOR(number);

  printk(KERN_INFO "Allocated major: %d, minor: %d\n", MAJOR(number),
         MINOR(number));

  gateway_device = kzalloc(sizeof(gateway_device_t), GFP_KERNEL);
  if (!gateway_device) {
    printk(KERN_WARNING
           "Error while trying to kzalloc sizeof(gateway_device_t)\n");
    error = -ENOMEM;
    goto fail;
  }

  gateway_device->_data = NULL;
  gateway_device->_buf_sz = GATEWAY_BUFFER_SIZE;
  gateway_device->_blk_sz = GATEWAY_BLOCK_SIZE;
  mutex_init(&gateway_device->_mutex);
  cdev_init(&gateway_device->_cdev, &fops);

  error = cdev_add(&gateway_device->_cdev, number, 1);

  if (error) {
    printk(KERN_WARNING "Error %d while trying to add %s\n", error,
           GATEWAY_DEVICE_NAME);
    goto fail;
  }

  device =
      device_create(gateway_class, NULL, number, NULL, GATEWAY_DEVICE_NAME);

  if (IS_ERR(device)) {
    printk(KERN_WARNING "Error %d while trying to create %s\n", error,
           GATEWAY_DEVICE_NAME);
    cdev_del(&gateway_device->_cdev);
    goto fail;
  }

  return 0;
fail:

  cleanup();
  return error;
}

#define KERNEL_FUNCTION_REQUIRED_ALIGNMENT 0x10
#define KERNEL_LOOKUP_LIMIT 0x100000

#ifdef ENABLE_UNEXPORTED_SYMBOLS
static int resolve_unexported_symbols(void) {
  unsigned long kaddr;
  kaddr = (unsigned long)&sprint_symbol;
  char fname_lookup[KSYM_NAME_LEN];
  int i;

  for (i = 0; i < KERNEL_LOOKUP_LIMIT; i++) {
    memset(fname_lookup, 0, sizeof(fname_lookup));
    sprint_symbol(fname_lookup, kaddr);

    if (strncmp(fname_lookup, "kallsyms_lookup_name",
                strlen("kallsyms_lookup_name")) == 0) {
      _kallsyms_lookup_name = (kallsyms_lookup_name_function_t)kaddr;
      break;
    }

    kaddr += KERNEL_FUNCTION_REQUIRED_ALIGNMENT;
  }

  if (!_kallsyms_lookup_name) {
    printk(KERN_ERR "kallsyms_lookup_name not found via kprobe\n");
    return -ENOENT;
  }
  printk(KERN_INFO "kallsyms_lookup_name found at %lx\n",
         (unsigned long)_kallsyms_lookup_name);

  _find_task_by_vpid =
      (find_task_by_vpid_function_t)_kallsyms_lookup_name("find_task_by_vpid");
  if (!_find_task_by_vpid) {
    printk(KERN_ERR "find_task_by_vpid not found.\n");
    return -ENOENT;
  }
  printk(KERN_INFO "find_task_by_vpid found at %lx\n",
         (unsigned long)_find_task_by_vpid);

  _task_lookup_fdget_rcu =
      (task_lookup_fdget_rcu_function_t)_kallsyms_lookup_name(
          "task_lookup_fdget_rcu");
  if (!_task_lookup_fdget_rcu) {
    printk(KERN_ERR "task_lookup_fd_rcu not found.\n");
    return -ENOENT;
  }
  printk(KERN_INFO "task_lookup_fdget_rcu found at %lx\n",
         (unsigned long)_task_lookup_fdget_rcu);

  return 0;
}
#endif  // ENABLE_UNEXPORTED_SYMBOLS

static int __init gateway_init(void) {
  printk(KERN_INFO "Gateway Init!! \n");

#ifdef ENABLE_UNEXPORTED_SYMBOLS
  if (resolve_unexported_symbols()) {
    printk(KERN_ERR "Error resolving unexported symbols\n");
    return -EFAULT;
  }
#endif  // ENABLE_UNEXPORTED_SYMBOLS

  printk(KERN_INFO "sizeof(struct kvm): %lu\n", sizeof(struct kvm));
  printk(KERN_INFO "sizeof(struct kvm_vcpu): %lu\n", sizeof(struct kvm_vcpu));

  initialize();

  return 0;
}

static void __exit gateway_exit(void) {
  printk(KERN_INFO "Gateway Exit!!\n");

  cleanup();
}

module_init(gateway_init);
module_exit(gateway_exit);