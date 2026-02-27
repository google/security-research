#include "ioctl.h"

#include <linux/dcache.h>
#include <linux/efi.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/smp.h>
#include <trace/events/ipi.h>
#include <linux/version.h>
#include <linux/delay.h>

#include "config.h"

#ifdef ENABLE_ISSUE_RDMSR_WRMSR
#include <asm/msr.h>
#endif  // ENABLE_ISSUE_RDMSR_WRMSR

typedef uint64_t virt_addr_t;
typedef uint64_t kern_addr_t;

typedef struct {
  kern_addr_t ka;
  size_t size;
} gateway_efi_data_t;

int ioctl_get_efi(void __user *p) {
  gateway_efi_data_t data;

  printk(KERN_INFO "ioctl_get_efi\n");

  if (copy_from_user(&data, p, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  data.ka = (virt_addr_t)&efi;
  data.size = sizeof(efi);

  printk(KERN_INFO "0x%016llx(%016lx) --> %p\n", data.ka, data.size, p);

  if (copy_to_user(p, &data, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  return 0;
}

typedef struct {
  kern_addr_t ka;
  uint64_t value;
} gateway_read_write_uint64_data_t;

int ioctl_read_uint64(void __user *p) {
  gateway_read_write_uint64_data_t data;

  // printk(KERN_INFO "ioctl_read_uint64\n");

  if (copy_from_user(&data, p, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  data.value = *(uint64_t *)(data.ka);

  // printk(KERN_INFO "0x%016llx --> 0x%lx\n", data.ka, (unsigned long)p);

  if (copy_to_user(p, &data, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  return 0;
}

int ioctl_write_uint64(void __user *p) {
  gateway_read_write_uint64_data_t data;

  // printk(KERN_INFO "ioctl_read_uint64\n");

  if (copy_from_user(&data, p, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  // printk(KERN_INFO "0x%016llx --> %lx\n", data.ka, (unsigned long)p);

  *(uint64_t *)(data.ka) = data.value;

  return 0;
}

#ifdef ENABLE_ALLOC_FREE_CONTIGUOUS_BUFFER
typedef struct {
  kern_addr_t ka;
  phys_addr_t pa;
  size_t size;
} gateway_alloc_free_contiguous_buffer_t;

int ioctl_alloc_contiguous_buffer(void __user *p) {
  void *tmp;
  gateway_alloc_free_contiguous_buffer_t data;

  printk(KERN_INFO "ioctl_alloc_contiguous_buffer\n");

  if (copy_from_user(&data, p, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  tmp = alloc_pages_exact(data.size, GFP_KERNEL | GFP_DMA);

  if (tmp != NULL) {
    memset(tmp, 0, data.size);
    data.ka = (kern_addr_t)tmp;
    // data.pa = virt_to_phys(tmp);
    data.pa = vmalloc_to_pfn(tmp) << PAGE_SHIFT;
  }

  if (copy_to_user(p, &data, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  return 0;
}
int ioctl_free_contiguous_buffer(void __user *p) {
  gateway_alloc_free_contiguous_buffer_t data;

  printk(KERN_INFO "ioctl_free_contiguous_buffer\n");

  if (copy_from_user(&data, p, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  free_pages_exact((void *)data.ka, data.size);

  return 0;
}
#endif  // ENABLE_ALLOC_FREE_CONTIGUOUS_BUFFER

#ifdef ENABLE_ISSUE_PORTIO
typedef struct {
  uint16_t port;
  uint32_t value;
} gateway_portio_data_t;

int ioctl_issue_outb(void __user *p) {
  gateway_portio_data_t data;

  printk(KERN_INFO "ioctl_issue_outb\n");

  if (copy_from_user(&data, p, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  printk(KERN_INFO "value: 0x%x --> port: 0x%x\n", data.value, data.port);

  asm volatile("outb %b0, %w1" : : "a"(data.value), "d"(data.port) : "memory");

  return 0;
}

int ioctl_issue_inb(void __user *p) {
  gateway_portio_data_t data;

  printk(KERN_INFO "ioctl_issue_inb\n");

  if (copy_from_user(&data, p, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  asm volatile("inb %w1, %b0" : "=a"(data.value) : "d"(data.port) : "memory");

  printk(KERN_INFO "port: 0x%x --> value 0x%x\n", data.port, data.value);

  return 0;
}

int ioctl_issue_outw(void __user *p) {
  gateway_portio_data_t data;

  printk(KERN_INFO "ioctl_issue_outb\n");

  if (copy_from_user(&data, p, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  printk(KERN_INFO "value: 0x%x --> port: 0x%x\n", data.value, data.port);

  asm volatile("outw %w0, %w1" : : "a"(data.value), "d"(data.port) : "memory");

  return 0;
}

int ioctl_issue_inw(void __user *p) {
  gateway_portio_data_t data;

  printk(KERN_INFO "ioctl_issue_inb\n");

  if (copy_from_user(&data, p, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  asm volatile("inw %w1, %w0" : "=a"(data.value) : "d"(data.port) : "memory");

  printk(KERN_INFO "port: 0x%x --> value 0x%x\n", data.port, data.value);

  return 0;
}

int ioctl_issue_outl(void __user *p) {
  gateway_portio_data_t data;

  printk(KERN_INFO "ioctl_issue_outl\n");

  if (copy_from_user(&data, p, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  printk(KERN_INFO "value: 0x%x --> port: 0x%x\n", data.value, data.port);

  asm volatile("outl %d0, %w1" : : "a"(data.value), "d"(data.port) : "memory");

  return 0;
}

int ioctl_issue_inl(void __user *p) {
  gateway_portio_data_t data;

  printk(KERN_INFO "ioctl_issue_inl\n");

  if (copy_from_user(&data, p, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  asm volatile("inl %w1, %d0" : "=a"(data.value) : "d"(data.port) : "memory");

  printk(KERN_INFO "port: 0x%x --> value 0x%x\n", data.port, data.value);

  return 0;
}

#endif  // ENABLE_ISSUE_PORTIO

#ifdef ENABLE_ISSUE_SEAMCALL_TDCALL
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

int ioctl_issue_seamcall(void __user *p) {
  gateway_issue_seamcall_tdcall_data_t data;

  printk(KERN_INFO "ioctl_issue_seamcall\n");

  if (copy_from_user(&data, p, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  // printk(KERN_INFO "data: %lx\n", (unsigned long)&data);

  // printk(KERN_INFO "data.rax: %lx\n", (unsigned long)data.rax);
  // printk(KERN_INFO "data.rcx: %lx\n", (unsigned long)data.rcx);
  // printk(KERN_INFO "data.rdx: %lx\n", (unsigned long)data.rdx);
  // printk(KERN_INFO "data.r8: %lx\n", (unsigned long)data.r8);
  // printk(KERN_INFO "data.r9: %lx\n", (unsigned long)data.r9);
  // printk(KERN_INFO "data.r10: %lx\n", (unsigned long)data.r10);
  // printk(KERN_INFO "data.r11: %lx\n", (unsigned long)data.r11);
  // printk(KERN_INFO "data.r12: %lx\n", (unsigned long)data.r12);
  // printk(KERN_INFO "data.r13: %lx\n", (unsigned long)data.r13);

  asm volatile(
    "movq 0(%[data_ptr]), %%rax \n\t"
    "movq 8(%[data_ptr]), %%rcx \n\t"
    "movq 16(%[data_ptr]), %%rdx \n\t"
    "movq 24(%[data_ptr]), %%r8 \n\t"
    "movq 32(%[data_ptr]), %%r9 \n\t"
    "movq 40(%[data_ptr]), %%r10 \n\t"
    "movq 48(%[data_ptr]), %%r11 \n\t"
    "movq 56(%[data_ptr]), %%r12 \n\t"
    "movq 64(%[data_ptr]), %%r13 \n\t"
    "seamcall \n\t"
    "movq %%rax, 0(%[data_ptr]) \n\t"
    "movq %%rcx, 8(%[data_ptr]) \n\t"
    "movq %%rdx, 16(%[data_ptr]) \n\t"
    "movq %%r8, 24(%[data_ptr]) \n\t"
    "movq %%r9, 32(%[data_ptr]) \n\t"
    "movq %%r10, 40(%[data_ptr]) \n\t"
    "movq %%r11, 48(%[data_ptr]) \n\t"
    "movq %%r12, 56(%[data_ptr]) \n\t"
    "movq %%r13, 64(%[data_ptr]) \n\t"
    :
    : [data_ptr] "D"(&data)
    : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "r12", "r13", "cc","memory"
  );

  if (copy_to_user(p, &data, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  return 0;
}

int ioctl_issue_tdcall(void __user *p) {
  gateway_issue_seamcall_tdcall_data_t data;

  printk(KERN_INFO "ioctl_issue_tdcall\n");

  if (copy_from_user(&data, p, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }


  // printk(KERN_INFO "data: %lx\n", (unsigned long)&data);

  // printk(KERN_INFO "data.rax: %lx\n", (unsigned long)data.rax);
  // printk(KERN_INFO "data.rcx: %lx\n", (unsigned long)data.rcx);
  // printk(KERN_INFO "data.rdx: %lx\n", (unsigned long)data.rdx);
  // printk(KERN_INFO "data.r8: %lx\n", (unsigned long)data.r8);
  // printk(KERN_INFO "data.r9: %lx\n", (unsigned long)data.r9);
  // printk(KERN_INFO "data.r10: %lx\n", (unsigned long)data.r10);
  // printk(KERN_INFO "data.r11: %lx\n", (unsigned long)data.r11);
  // printk(KERN_INFO "data.r12: %lx\n", (unsigned long)data.r12);
  // printk(KERN_INFO "data.r13: %lx\n", (unsigned long)data.r13);

  asm volatile(
    "movq 0(%[data_ptr]), %%rax \n\t"
    "movq 8(%[data_ptr]), %%rcx \n\t"
    "movq 16(%[data_ptr]), %%rdx \n\t"
    "movq 24(%[data_ptr]), %%r8 \n\t"
    "movq 32(%[data_ptr]), %%r9 \n\t"
    "movq 40(%[data_ptr]), %%r10 \n\t"
    "movq 48(%[data_ptr]), %%r11 \n\t"
    "movq 56(%[data_ptr]), %%r12 \n\t"
    "movq 64(%[data_ptr]), %%r13 \n\t"
    "tdcall \n\t"
    "movq %%rax, 0(%[data_ptr]) \n\t"
    "movq %%rcx, 8(%[data_ptr]) \n\t"
    "movq %%rdx, 16(%[data_ptr]) \n\t"
    "movq %%r8, 24(%[data_ptr]) \n\t"
    "movq %%r9, 32(%[data_ptr]) \n\t"
    "movq %%r10, 40(%[data_ptr]) \n\t"
    "movq %%r11, 48(%[data_ptr]) \n\t"
    "movq %%r12, 56(%[data_ptr]) \n\t"
    "movq %%r13, 64(%[data_ptr]) \n\t"
    :
    : [data_ptr] "D"(&data)
    : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "r12", "r13", "cc","memory"
  );

  if (copy_to_user(p, &data, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  return 0;
}
#endif  // ENABLE_ISSUE_SEAMCALL_TDCALL

#ifdef ENABLE_ISSUE_RDMSR_WRMSR
typedef struct {
  uint32_t identifier;
  uint64_t value;
} gateway_issue_rdmsr_wrmsr_data_t;

int ioctl_issue_rdmsr(void __user *p) {
  gateway_issue_rdmsr_wrmsr_data_t data;

  printk(KERN_INFO "ioctl_issue_rdmsr\n");

  if (copy_from_user(&data, p, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  rdmsrl_safe(data.identifier, &data.value);

  if (copy_to_user(p, &data, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  return 0;
}

int ioctl_issue_wrmsr(void __user *p) {
  gateway_issue_rdmsr_wrmsr_data_t data;

  printk(KERN_INFO "ioctl_issue_wrmsr\n");

  if (copy_from_user(&data, p, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  wrmsrl_safe(data.identifier, data.value);

  return 0;
}
#endif  // ENABLE_ISSUE_RDMSR_WRMSR

#ifdef ENABLE_UNEXPORTED_SYMBOLS
typedef struct {
  int pid;
  unsigned int fd;
  struct file *f;
  uint32_t f_mode_offset;
  uint32_t private_data_offset;
} gateway_fd_get_put_data_t;

find_task_by_vpid_function_t _find_task_by_vpid = NULL;
task_lookup_fdget_rcu_function_t _task_lookup_fdget_rcu = NULL;
kallsyms_lookup_name_function_t _kallsyms_lookup_name = NULL;

int ioctl_fdget(void __user *p) {
  struct task_struct *t;
  struct file *f = NULL;
  int ret = 0;
  gateway_fd_get_put_data_t data;

  printk(KERN_INFO "ioctl_fdget\n");

  if (copy_from_user(&data, p, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  rcu_read_lock();
  t = _find_task_by_vpid(data.pid);
  if (t) {
    get_task_struct(t);
  }
  rcu_read_unlock();

  if (!t) {
    printk(KERN_ERR "pid %d not found.\n", data.pid);
    ret = -ESRCH;
    goto cleanup;
  }

  rcu_read_lock();
  f = _task_lookup_fdget_rcu(t, data.fd);
  rcu_read_unlock();

  if (!f) {
    printk(KERN_ERR "fd %d not found or invalid for pid %d\n", data.fd,
           data.pid);
    ret = -EBADF;
    goto cleanup;
  }

  printk(KERN_INFO "obtained file pointer for PID %d, FD %d: %lx\n", data.pid,
         data.fd, (unsigned long)f);

  if (f->f_inode) {
    printk(
        KERN_INFO "file inode: %lu, type: %s\n", f->f_inode->i_ino,
        S_ISREG(f->f_inode->i_mode)
            ? "Regular File"
            : (S_ISDIR(f->f_inode->i_mode)
                   ? "Directory"
                   : (S_ISLNK(f->f_inode->i_mode)
                          ? "Symbolic Link"
                          : (S_ISCHR(f->f_inode->i_mode)
                                 ? "Character Device"
                                 : (S_ISBLK(f->f_inode->i_mode)
                                        ? "Block Device"
                                        : (S_ISFIFO(f->f_inode->i_mode)
                                               ? "FIFO/Pipe"
                                               : (S_ISSOCK(f->f_inode->i_mode)
                                                      ? "Socket"
                                                      : "Other")))))));

    if (f->f_path.dentry && f->f_path.dentry->d_name.name) {
      printk(KERN_INFO "file name: %s\n", f->f_path.dentry->d_name.name);
    }
  }

  data.f = f;
  data.f_mode_offset = offsetof(struct file, f_mode);
  data.private_data_offset = offsetof(struct file, private_data);

  if (copy_to_user(p, &data, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    ret = -EFAULT;
    fput(f);
    goto cleanup;
  }

cleanup:
  if (t) {
    rcu_read_lock();
    put_task_struct(t);
    rcu_read_unlock();
  }

  return ret;
}

int ioctl_fdput(void __user *p) {
  gateway_fd_get_put_data_t data;

  printk(KERN_INFO "ioctl_fdput\n");

  if (copy_from_user(&data, p, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  fput(data.f);

  return 0;
}
#endif  // ENABLE_UNEXPORTED_SYMBOLS

#ifdef ENABLE_ISSUE_VMX
typedef struct {
  uint64_t identifier;
  uint64_t value;
} gateway_issue_vmx_data_t;

#define RFLAGS_CF_ZF_MASK 0x41

int ioctl_issue_vmclear(void __user *p) {
  gateway_issue_vmx_data_t data;

  printk(KERN_INFO "ioctl_issue_vmclear\n");

  if (copy_from_user(&data, p, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  asm volatile("vmclear %0" ::"m"(data.value) : "memory", "cc");

  return 0;
}

int ioctl_issue_vmlaunch(void __user *p) {
  printk(KERN_INFO "ioctl_issue_vmlaunch\n");

  asm volatile("vmlaunch" ::: "memory", "cc");

  return 0;
}

int ioctl_issue_vmresume(void __user *p) {
  printk(KERN_INFO "ioctl_issue_vmlaunch\n");

  asm volatile("vmresume" ::: "memory", "cc");

  return 0;
}

int ioctl_issue_vmxoff(void __user *p) {
  printk(KERN_INFO "ioctl_issue_vmxoff\n");

  asm volatile("vmxoff" ::: "memory", "cc");

  return 0;
}

int ioctl_issue_vmxon(void __user *p) {
  gateway_issue_vmx_data_t data;

  printk(KERN_INFO "ioctl_issue_vmxon\n");

  if (copy_from_user(&data, p, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  asm volatile("vmxon %0" ::"m"(data.value) : "memory", "cc");

  return 0;
}

int ioctl_issue_vmread(void __user *p) {
  gateway_issue_vmx_data_t data;
  uint64_t rflags;

  printk(KERN_INFO "ioctl_issue_vmread\n");

  if (copy_from_user(&data, p, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  asm volatile(
      "vmreadq %2,%0\n"
      "pushfq\n"
      "popq %1"
      : "=m"(data.value), "=r"(rflags)
      : "r"(data.identifier)
      : "memory", "cc");

  if (copy_to_user(p, &data, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  return rflags & RFLAGS_CF_ZF_MASK;
}

int ioctl_issue_vmwrite(void __user *p) {
  gateway_issue_vmx_data_t data;
  uint64_t rflags;

  printk(KERN_INFO "ioctl_issue_vmwrite\n");

  if (copy_from_user(&data, p, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  asm volatile(
      "vmwriteq %1,%2\n"
      "pushfq\n"
      "popq %0"
      : "=r"(rflags)
      : "r"(data.value), "r"(data.identifier)
      : "cc");

  return rflags & RFLAGS_CF_ZF_MASK;
}

int ioctl_issue_vmptrld(void __user *p) {
  gateway_issue_vmx_data_t data;
  uint64_t rflags;

  printk(KERN_INFO "ioctl_issue_vmptrld\n");

  if (copy_from_user(&data, p, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  asm volatile(
      "vmptrld %1\n"
      "pushfq\n"
      "popq %0\n"
      : "=r"(rflags)
      : "m"(data.value)
      : "memory", "cc");

  return rflags & RFLAGS_CF_ZF_MASK;
}

int ioctl_issue_vmptrst(void __user *p) {
  gateway_issue_vmx_data_t data;

  printk(KERN_INFO "ioctl_issue_vmptrst\n");

  if (copy_from_user(&data, p, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  asm volatile("vmptrst %0" ::"m"(data.value) : "memory", "cc");

  if (copy_to_user(p, &data, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  return 0;
}
#endif  // ENABLE_ISSUE_VMX

typedef struct {
  uint32_t cpu;
  uint32_t count;
  uint32_t delay;
} gateway_issue_reschedule_data_t;

int ioctl_reschedule(void __user *p) {
gateway_issue_reschedule_data_t data;
  
  printk(KERN_INFO "starting ioctl_reschedule: %d\n", smp_processor_id());

  if (copy_from_user(&data, p, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  printk(KERN_INFO "cpu: %d, count: %d, delay: %d\n", data.cpu, data.count, data.delay);

  for (int i = 0; i < data.count; i++) {
    smp_send_reschedule(data.cpu);
    if (data.delay > 0) {
      msleep(data.delay);
    }
  }

  printk(KERN_INFO "finished ioctl_reschedule: %d\n", smp_processor_id());
  
  return 0;
}

typedef struct {
  uint32_t cpu;
  uint32_t count;
  uint32_t delay;
} gateway_ipi_storm_data_t;

static void ipi_storm_handler(void *info) {}

int ioctl_ipi_storm(void __user *p) {
  gateway_ipi_storm_data_t data;

  if (copy_from_user(&data, p, sizeof(data))) {
    printk(KERN_ALERT "copy_to_user failed\n");
    return -EFAULT;
  }

  printk(KERN_INFO "cpu: %d, count: %d, delay: %d\n", data.cpu, data.count, data.delay);

  printk(KERN_INFO "starting interrupt storm from cpu %d\n", smp_processor_id());

  for (int i = 0; i < data.count; i++) {
    smp_call_function_single(data.cpu, ipi_storm_handler, NULL, 0);
    if (data.delay > 0) {
      msleep(data.delay);
    }
  }

  printk(KERN_INFO "ending interrupt storm from cpu %d\n", smp_processor_id());

  return 0;
}


