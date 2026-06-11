# Vulnerability

CVE-2026-46242 ("Bad Epoll") is a race condition that leads to use-after-free in 
epoll's file-release path. When one eventpoll fd monitors another eventpoll fd, closing 
both fds concurrently triggers a race in `fs/eventpoll.c`. Once `__ep_remove()` runs
`WRITE_ONCE(file->f_ep, NULL)`, a concurrent `__fput()` on the same target file
sees `f_ep == NULL` on the lockless fast path of `eventpoll_release()`, skips
`eventpoll_release_file()`, and goes on to free the target's `eventpoll` and
`file`. `__ep_remove()` keeps writing through pointers into those freed objects,
which is the use-after-free.

## Thread interleaving

Two epoll fds `ep_waiter` and `ep_target` are created, with `ep_waiter`
monitoring `ep_target`. For each fd `ep_X`, `epoll_X` is its `struct eventpoll`
and `file_X` its `struct file`. The bug needs this interleaving:

```
  CPU 1, Thread A (close ep_waiter)     CPU 0, Thread B (close ep_target, open /dev/null)
  ===========================           ==========================
  ep_eventpoll_release
    ep_clear_and_put
      mutex_lock(&epoll_waiter->mtx)
      ep_remove_safe
        __ep_remove
          spin_lock(&file_target->f_lock)
          WRITE_ONCE(file_target->f_ep, NULL)
                                        __fput
                                          eventpoll_release(file_target)
                                            // lockless fast check!
                                            READ_ONCE(file_target->f_ep) == NULL
                                            return
                                          ep_eventpoll_release
                                            ep_clear_and_put
                                              ep_free
                                                kfree(epoll_target)
                                          file_free
                                            kmem_cache_free(file_target)
                                        // [0] reclaims the freed file_target
                                        open("/dev/null")
          // [1] UAF read on the freed file_target
          if (!is_file_epoll(file_target))
            to_free = &epoll_target->refs
          hlist_del_rcu(&epi->fllink)
            // [2] UAF write 0 to freed &epoll_target->refs
            *pprev = next
          spin_unlock(&file_target->f_lock)
          // [3] invalid free of the freed epoll_target
          free_ephead(to_free)
```

Thread B frees two objects that Thread A's `__ep_remove()` still references, so
the race causes two distinct use-after-frees:

- **UAF on `struct eventpoll` (write 0 at offset 160 of kmalloc-192).**
  `hlist_del_rcu(&epi->fllink)` writes `*pprev = 0` through the dangling
  `epi->fllink.pprev`, which points into the freed `&epoll_target->refs` (160 bytes
  into the freed eventpoll object). This is the slab-use-after-free write KASAN
  reports [2].

- **Silent UAF on `struct file`, leading to an invalid free.** `epi->ffd.file`
  holds the target file without ever raising its `f_count`, so `__ep_remove()`
  keeps operating on the freed (and possibly reclaimed) `file_target` while
  holding its `f_lock`. The `is_file_epoll(file)` read is the resulting UAF read
  [1]. KASAN does not detect the file UAF even with
  [`CONFIG_SLUB_RCU_DEBUG`](https://github.com/torvalds/linux/commit/b8c8ba73c68bb3c3e9dad22f488b86c540c839f9)
  because i) `struct file` comes from a `SLAB_TYPESAFE_BY_RCU` cache, and ii) this path is holding a spinlock (`f_lock`).
  If the freed file is reclaimed right away as a non-eventpoll file [0],
  `free_ephead()` then frees `&epoll_target->refs` into the wrong cache
  (kmalloc-192), an invalid free [3].

  That invalid free is observable only when the freed file object can be reclaimed immediately,
  which requires `CONFIG_SLUB_RCU_DEBUG` to be disabled. However, the 6.12 stable tree
  never backported the follow-up [`CONFIG_SLUB_RCU_DEBUG` fix](https://github.com/torvalds/linux/commit/56bdf83de7f1151d141e1d020e19cc1c56ff0db4).
  As a result, even a KASAN=y and `CONFIG_SLUB_RCU_DEBUG`=n build does not report the
  invalid free on 6.12. We therefore disabled KASAN and observed the invalid free through
  the WARNING raised by `free_ephead()`.

Note that holding `file_target->f_lock` (a spinlock) disables preemption on
Thread A's CPU, so Thread B cannot run there during the window. The two threads
must run concurrently on separate CPUs (CPU 0 and CPU 1 above) to trigger the
bug.

## Requirements to trigger the vulnerability
- Capabilities: NONE
- Kernel configuration: `CONFIG_EPOLL`
- Are user namespaces needed?: No

## Commit which introduced the vulnerability
- [commit 58c9b016e128 ("epoll: use refcount to reduce ep_mutex contention")](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=58c9b016e12855286370dfb704c08498edbc857a)

## Commit which fixed the vulnerability
- [commit a6dc643c693 ("eventpoll: fix ep_remove struct eventpoll / struct file UAF
")](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a6dc643c69311677c574a0f17a3f4d66a5f3744b)

## Affected kernel versions
- 6.4-rc1 - 7.0

## Affected component, subsystem
- fs/eventpoll

## Cause
- Race condition / UAF

## Relationship to CVE-2026-43074

This bug is distinct from CVE-2026-43074 (exploited in exp510,
[PR #380](https://github.com/google/security-research/pull/380)), though both
were introduced by the same [commit 58c9b016e128](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=58c9b016e12855286370dfb704c08498edbc857a). The CVE-2026-43074 fix
([commit 07712db8](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=07712db80857d5d09ae08f3df85a708ecfc3b61f),
mainline 2026-04-02) made the `struct eventpoll` free RCU-deferred. Because 
this bug's race window runs with a spinlock held, the `struct eventpoll`
is no longer freed during the window, so the eventpoll UAF disappears.
The `struct file` UAF and the underlying root cause remained until
[this bug's own fix](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a6dc643c69311677c574a0f17a3f4d66a5f3744b).
Our exploit was finished before the CVE-2026-43074 patch and therefore uses the
eventpoll UAF.

## Timeline

| Date | Event |
|------|-------|
| 2026-02-11 | We captured flags on lts-6.12.67 and cos-121-18867.294.100 |
| 2026-02-17 | We reported the bug to security@kernel.org |
| 2026-02-17 | Maintainers proposed a patch prototype, but it was not a correct fix and the discussion then stalled |
| 2026-04-02 | CVE-2026-43074 fix (`07712db8`) landed in mainline, making `struct eventpoll` RCU-freed |
| 2026-04-22 | We re-reported the remaining `struct file` UAF, which was not detected by KASAN |
| 2026-04-24 | The fix for this bug landed in mainline (`a6dc643c693`) |