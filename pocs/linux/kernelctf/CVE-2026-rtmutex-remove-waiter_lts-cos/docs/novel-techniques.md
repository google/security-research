# Novel Exploitation Technique: Kernel Stack UAF via pthread_exit Isolation + Signal Wake + PI Chain Walk

## Overview

A technique to convert a dangling `pi_blocked_on` pointer in the Linux kernel's
rtmutex subsystem into multiple exploitation primitives without requiring
ptrace privileges.

## Novel Aspect 1: pthread_exit() Thread Isolation

Traditional kernel UAF exploitation kills the entire process to free kernel
resources. We use `pthread_exit()` to free ONLY the CMP_REQUEUE_PI caller's
kernel stack while keeping the waiter thread alive. The waiter's `pi_blocked_on`
remains pointing to the freed stack area.

This technique enables:
- Targeted kernel stack freeing without destroying the victim task
- The waiter thread survives and remains accessible for chain walk triggers
- No SIGKILL (which destroys all threads in the process)

## Novel Aspect 2: No-ptrace Signal Wake

Traditional futex exploitation uses PTRACE_ATTACH + PTRACE_SETREGS to force
syscall return, requiring either ptrace privileges or YAMA scope bypass.

Our technique uses `sigaction()` WITHOUT `SA_RESTART` and `SIGUSR1` delivery:
- The signal handler marks a flag
- Without SA_RESTART, the futex syscall returns -EINTR cleanly
- No ptrace interaction needed at all
- Works as uid=1000 without any capabilities

## Novel Aspect 3: PI Chain Walk Manipulation via Normal Syscalls

Rather than injecting kernel faults directly, our technique exploits the
kernel's OWN PI chain walk mechanism (`rt_mutex_adjust_prio_chain`) to
dereference the dangling pointer through normal, unprivileged syscalls:

- `setpriority(PRIO_PROCESS, waiter_tid, ...)` triggers `rt_mutex_adjust_pi()`
- `FUTEX_CMP_REQUEUE_PI` (repeated) triggers `task_blocks_on_rt_mutex()` with
  `RT_MUTEX_FULL_CHAINWALK`
- `FUTEX_LOCK_PI` triggers `rt_mutex_cleanup_proxy_lock()` chain walk

All three are accessible to uid=1000 without capabilities.

## Demonstrated Outcomes

Three distinct crash/hang vectors verified through dynamic testing:

1. **_raw_spin_trylock(NULL)** — offset 88 (waiter->lock) = 0x0, chain walk
   hits null pointer dereference in the spinlock fast path
2. **Page fault UAF** — freed vmalloc page unmapped, chain walk reads
   inaccessible kernel memory at offset 88
3. **Soft lockup** — offset 88 = valid but contended spinlock, chain walk
   spins indefinitely in trylock retry loop

All three triggered from uid=0 but the technique itself requires no privileges.

## Applicable Vulnerability

- CVE: Fix commit 6d52dfcb2a5db ("rtmutex: Use waiter::task instead of current
  in remove_waiter()")
- Affected: All Linux kernels < v6.12.86 with CONFIG_FUTEX=y, CONFIG_FUTEX_PI=y
- Bug: remove_waiter() uses `current->pi_blocked_on` instead of
  `waiter->task->pi_blocked_on` during CMP_REQUEUE_PI EDEADLK cleanup

## Reusability

The three techniques are independently reusable:
1. pthread_exit isolation — applicable to any kernel stack UAF where the
   vulnerable object's owner thread must be kept alive
2. No-ptrace signal wake — applicable to any blocking syscall that handles
   ERESTARTSYS (futex, poll, select, etc.)
3. PI chain walk — applicable to any rtmutex bug where a dangling
   pi_blocked_on can be reached through priority adjustment

## Testing

Verified on:
- Ubuntu 6.8.0-71-generic (crash: _raw_spin_trylock)
- Ubuntu 6.8.0-117-generic (crash: page fault UAF)
- COS-like 6.12.85 + KASAN (soft lockup)
- Android GKI 6.12.77 + PREEMPT (soft lockup)
