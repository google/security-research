#ifndef __GATEWAY_IOCTL_H__
#define __GATEWAY_IOCTL_H__

#include <linux/uaccess.h>
#include <linux/version.h>

#include "config.h"

int ioctl_get_efi(void __user *p);
int ioctl_read_uint64(void __user *p);
int ioctl_write_uint64(void __user *p);

#ifdef ENABLE_ALLOC_FREE_CONTIGUOUS_BUFFER
int ioctl_alloc_contiguous_buffer(void __user *p);
int ioctl_free_contiguous_buffer(void __user *p);
#endif  // ENABLE_ALLOC_FREE_CONTIGUOUS_BUFFER

#ifdef ENABLE_ISSUE_PORTIO
int ioctl_issue_outb(void __user *p);
int ioctl_issue_inb(void __user *p);
int ioctl_issue_outw(void __user *p);
int ioctl_issue_inw(void __user *p);
int ioctl_issue_outl(void __user *p);
int ioctl_issue_inl(void __user *p);
#endif  // ENABLE_ISSUE_PORTIO

#ifdef ENABLE_ISSUE_SEAMCALL_TDCALL
int ioctl_issue_seamcall(void __user *p);
int ioctl_issue_tdcall(void __user *p);
#endif  // ENABLE_ISSUE_SEAMCALL_TDCALL

#ifdef ENABLE_ISSUE_RDMSR_WRMSR
int ioctl_issue_rdmsr(void __user *p);
int ioctl_issue_wrmsr(void __user *p);
#endif  // ENABLE_ISSUE_RDMSR_WRMSR

#ifdef ENABLE_ISSUE_VMX
int ioctl_issue_vmclear(void __user *p);
int ioctl_issue_vmlaunch(void __user *p);
int ioctl_issue_vmresume(void __user *p);
int ioctl_issue_vmxoff(void __user *p);
int ioctl_issue_vmxon(void __user *p);
int ioctl_issue_vmread(void __user *p);
int ioctl_issue_vmwrite(void __user *p);
int ioctl_issue_vmptrld(void __user *p);
int ioctl_issue_vmptrst(void __user *p);
#endif  // ENABLE_ISSUE_VMX

int ioctl_reschedule(void __user *p);
int ioctl_ipi_storm(void __user *p);

typedef struct task_struct *(*find_task_by_vpid_function_t)(pid_t vpid);
typedef struct file *(*task_lookup_fdget_rcu_function_t)(struct task_struct *task,
                                                      unsigned int fd);

typedef unsigned long (*kallsyms_lookup_name_function_t)(const char *name);

extern find_task_by_vpid_function_t _find_task_by_vpid;
extern task_lookup_fdget_rcu_function_t _task_lookup_fdget_rcu;
extern kallsyms_lookup_name_function_t _kallsyms_lookup_name;

int ioctl_fdget(void __user *p);
int ioctl_fdput(void __user *p);

#endif  // __GATEWAY_IOCTL_H__