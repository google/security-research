/**
 * @name Non-syscall entry-reachable pairs
 * @description Emits (entry_kind, entry, function, file) for every function reachable
 *   from each categorized non-syscall entry root over the direct + points-to/taint
 *   call graph (call_graph_edges.qll). Mirrors syscall-node-pairs.ql over the same
 *   edges relation while leaving ops_targets and async_edges as separate 1-hop layers
 *   composed at query time.
 * @id cpp/dashboard/entry-node-pairs
 * @kind table
 */

import cpp
import call_graph_edges

/**
 * Unwraps function pointer expressions (`fn`, `&fn`, `(cast)fn`, `cond ? a : b`).
 */
Function resolveFunctionTarget(Expr expr) {
  exists(Expr u | u = expr.getUnconverted() |
    result = u.(FunctionAccess).getTarget()
    or
    result = u.(AddressOfExpr).getAddressable()
    or
    result = resolveFunctionTarget(u.(ConditionalExpr).getThen())
    or
    result = resolveFunctionTarget(u.(ConditionalExpr).getElse())
    or
    result = resolveFunctionTarget(u.(CommaExpr).getRightOperand())
  )
}

/**
 * Holds if `fn` is registered on `structName.fieldName` via either a
 * struct aggregate initializer or a direct field assignment `s->field = fn`.
 */
predicate registeredStructCallback(string structName, string fieldName, Function fn) {
  exists(ClassAggregateLiteral cal, Field f, Expr fe |
    f.getDeclaringType().getName() = structName and
    f.getName() = fieldName and
    fe = cal.getAFieldExpr(f) and
    fn = resolveFunctionTarget(fe)
  )
  or
  exists(AssignExpr assign, FieldAccess fa, Field f |
    fa = assign.getLValue() and
    f = fa.getTarget() and
    f.getDeclaringType().getName() = structName and
    f.getName() = fieldName and
    fn = resolveFunctionTarget(assign.getRValue())
  )
}

/**
 * Holds if `fn` is an eBPF kfunc registered via `BTF_ID_FLAGS(func, fn, ...)`.
 * Note: `____BTF_ID_FLAGS` emits `__BTF_ID__func__<fn>__*` inside an inline
 * `asm(...)` statement rather than a C `Variable` declaration, so we resolve
 * the `BTF_ID_FLAGS` macro invocation directly.
 */
predicate isBpfKfunc(Function fn) {
  exists(MacroInvocation mi |
    mi.getMacroName() = "BTF_ID_FLAGS" and
    mi.getUnexpandedArgument(0).trim() = "func" and
    fn.getName() = mi.getUnexpandedArgument(1).trim()
  )
}

/**
 * Holds if `fn` is the body of a `bpf_func_proto.func` helper.
 * `BPF_CALL_x` defines `name` as a 1-line register-cast wrapper around `____name`,
 * so we seed `____name` when it exists (analogous to `__do_sys_*` for syscalls).
 */
predicate isBpfHelperBody(Function fn) {
  exists(Function protoFn |
    registeredStructCallback("bpf_func_proto", "func", protoFn) and
    (
      fn.getName().matches("____%") and
      fn.getName().regexpCapture("____(.+)", 1) = protoFn.getName()
      or
      fn = protoFn and
      not exists(Function impl |
        impl.getName().matches("____%") and
        impl.getName().regexpCapture("____(.+)", 1) = protoFn.getName() and
        not notInteresting(impl)
      )
    )
  )
}

/**
 * Holds if `entry` is a categorized non-syscall entry root with category `entry_kind`.
 * Follows the "seed true entries, not chokepoints" principle.
 */
cached
predicate nonSyscallEntry(Function entry, string entry_kind) {
  not notInteresting(entry) and
  not entry.getName().regexpMatch("__do_sys_.*") and
  (
    // 1. compat_syscall: 32-bit / compat syscall bodies (__do_compat_sys_*)
    entry_kind = "compat_syscall" and
    entry.getName().regexpMatch("__do_compat_sys_.*")
    or
    // 2. page_fault: true fault entries (excludes handle_mm_fault chokepoint)
    entry_kind = "page_fault" and
    entry.getName() in ["exc_page_fault", "do_user_addr_fault"]
    or
    // 3. net_rx: inbound packet / NAPI / softirq RX entries (excludes nf_hook_slow)
    entry_kind = "net_rx" and
    entry.getName() in [
        "__netif_receive_skb_core", "netif_receive_skb", "napi_gro_receive",
        "ip_rcv", "ipv6_rcv", "tcp_v4_rcv", "tcp_v6_rcv",
        "udp_rcv", "icmp_rcv", "arp_rcv", "packet_rcv"
      ]
    or
    // 4. vfs_writeback: background writeback workqueue entry
    entry_kind = "vfs_writeback" and
    entry.getName() = "wb_workfn"
    or
    // 5. vfs_reclaim: shrinker reclaim entry and shrinker callbacks
    entry_kind = "vfs_reclaim" and
    (
      entry.getName() in ["shrink_slab", "super_cache_scan", "prune_icache_sb", "prune_dcache_sb"]
      or
      registeredStructCallback("shrinker", ["scan_objects", "count_objects"], entry)
    )
    or
    // 6. io_uring: async / SQE execution entries
    entry_kind = "io_uring" and
    entry.getName() in [
        "io_issue_sqe", "io_wq_submit_work", "io_apoll_task_func",
        "io_poll_task_func", "io_req_task_submit"
      ]
    or
    // 7. bpf_entry: BPF helper callbacks (bpf_func_proto.func) and BTF kfuncs
    entry_kind = "bpf_entry" and
    (
      isBpfHelperBody(entry) or
      isBpfKfunc(entry)
    )
    or
    // 8. device_usb: USB/HID/Virtio/VMBus hotplug probe/disconnect & URB completion
    entry_kind = "device_usb" and
    (
      registeredStructCallback("usb_driver", ["probe", "disconnect"], entry)
      or
      registeredStructCallback("hid_driver", ["probe", "remove", "raw_event", "event"], entry)
      or
      registeredStructCallback("virtio_driver", ["probe", "remove", "config_changed"], entry)
      or
      registeredStructCallback("hv_driver", ["probe", "remove"], entry)
      or
      registeredStructCallback("urb", "complete", entry)
      or
      exists(FunctionCall fc |
        fc.getTarget().getName() in [
            "usb_fill_control_urb", "usb_fill_bulk_urb", "usb_fill_int_urb"
          ] and
        entry = resolveFunctionTarget(fc.getArgument(5))
      )
    )
  )
}

class NonSyscallEntry extends Function {
  NonSyscallEntry() { nonSyscallEntry(this, _) }
}

pragma[nomagic]
predicate entryReachableNode(NonSyscallEntry entryFn, ControlFlowNode n) {
  edges(entryFn, n)
  or
  exists(ControlFlowNode mid |
    entryReachableNode(entryFn, mid) and
    edges(mid, n)
  )
}

from NonSyscallEntry entryFn, string entry_kind, Function reached
where
  entryReachableNode(entryFn, reached) and
  reached != entryFn and
  not notInteresting(reached) and
  nonSyscallEntry(entryFn, entry_kind)
select
  entry_kind,
  entryFn.getName() as entry,
  reached.getName() as function,
  reached.getFile().getRelativePath() as file
