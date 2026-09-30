/**
 * @name Asynchronous callback call-graph edges
 * @description Recovers asynchronous callback edges that synchronous call-graph
 *              queries (all-calls.ql and ops_edges.ql) miss: callbacks registered
 *              now and invoked later by a kernel dispatcher (workqueue, timer,
 *              hrtimer, RCU, IRQ, IPI, NAPI, kthread, notifier, task_work,
 *              io_uring, USB URB, crypto, waitqueue, poll, socket, skb,
 *              netfilter, block_io, firmware, async).
 *              Emits rendered strings (caller, callee, mechanism, form, file, line)
 *              to avoid entity serialization overhead in BQRS.
 * @id cpp/dashboard/async-edges
 * @kind table
 * @tags security kernel callgraph async
 */

import cpp

/**
 * Internal delayed-work / kthread timer trampolines that macro-expand alongside
 * the real workqueue callback at INIT_DELAYED_WORK / DECLARE_DELAYED_WORK sites.
 */
predicate isInternalWorkTrampoline(Function f) {
  f.getName() =
    ["delayed_work_timer_fn", "kthread_delayed_work_timer_fn", "rcu_work_rcufn"]
}

/**
 * Resolves an expression (unwrapping implicit/explicit casts and address-of `&fn`)
 * to a defined callback function, excluding internal macro trampolines.
 */
predicate resolveCallback(Expr expr, Function cb) {
  exists(Expr e | e = expr.getUnconverted() |
    cb = e.(FunctionAccess).getTarget() or
    cb = e.(AddressOfExpr).getAddressable()
  ) and
  cb.hasDefinition() and
  not isInternalWorkTrampoline(cb)
}

/**
 * Holds if `fld` is declared directly on `structName` or inside an anonymous
 * struct/union nested within `structName` (e.g., `sk_buff.destructor`).
 */
predicate fieldInStruct(Field fld, string structName) {
  fld.getDeclaringType().hasName(structName)
  or
  exists(Struct enc |
    enc = fld.getDeclaringType().getEnclosingElement+() and
    enc.hasName(structName)
  )
}

/**
 * Holds if `fa` accesses a field belonging to `structName`, either directly
 * or through an anonymous struct/union qualifier chain.
 */
predicate fieldAccessInStruct(FieldAccess fa, string structName) {
  fieldInStruct(fa.getTarget(), structName)
  or
  exists(Expr q, Type t |
    q = fa.getQualifier+() and
    t = q.getType().getUnderlyingType() and
    (
      t.(Struct).hasName(structName) or
      t.(PointerType).getBaseType().getUnderlyingType().(Struct).hasName(structName)
    )
  )
}

/**
 * Form A: registrars whose function-pointer argument is the deferred callback.
 * Covers kernel versions 6.1 through 6.18 (e.g., `init_timer_key` in 6.1-6.12
 * and `timer_init_key` / `hrtimer_setup` in 6.18).
 */
predicate asyncRegistrarArg(string name, string mechanism) {
  name =
    ["call_rcu", "call_rcu_hurry", "call_srcu", "__call_srcu",
      "call_rcu_tasks", "call_rcu_tasks_rude", "call_rcu_tasks_trace",
      "ipc_rcu_putref", "rhashtable_free_and_destroy", "percpu_ref_init"] and
  mechanism = "rcu"
  or
  name =
    ["request_irq", "request_threaded_irq", "devm_request_irq",
      "devm_request_threaded_irq", "request_any_context_irq",
      "devm_request_any_context_irq", "setup_irq", "__request_percpu_irq",
      "request_percpu_irq", "pci_request_irq", "vfio_virqfd_enable",
      "init_irq_work", "irq_poll_init", "irq_set_chip_and_handler_name",
      "__irq_set_handler", "bind_evtchn_to_irqhandler",
      "bind_evtchn_to_irqhandler_lateeoi",
      "bind_interdomain_evtchn_to_irqhandler",
      "bind_interdomain_evtchn_to_irqhandler_lateeoi",
      "bind_virq_to_irqhandler", "bind_ipi_to_irqhandler"] and
  mechanism = "irq"
  or
  name =
    ["kthread_create", "kthread_run", "kthread_create_on_node",
      "kthread_run_on_cpu", "kthread_create_on_cpu", "md_register_thread"] and
  mechanism = "kthread"
  or
  name = ["kthread_init_work", "kthread_init_delayed_work"] and
  mechanism = "kthread_worker"
  or
  name =
    ["tcf_queue_work", "btrfs_init_work", "xfs_pwork_init",
      "vhost_work_init", "mlxsw_sp_router_schedule_work",
      "queue_stop_cpus_work", "schedule_on_each_cpu", "work_on_cpu",
      "work_on_cpu_key", "work_on_cpu_safe", "start_async_work",
      "switchdev_deferred_enqueue", "wg_packet_queue_init"] and
  mechanism = "workqueue"
  or
  name =
    ["smp_call_function_single", "smp_call_function", "smp_call_function_many",
      "smp_call_function_any", "smp_call_on_cpu", "on_each_cpu",
      "on_each_cpu_mask", "on_each_cpu_cond", "on_each_cpu_cond_mask",
      "cpu_function_call", "task_function_call", "task_call_func",
      "call_on_cpu", "queue_balance_callback", "stop_one_cpu",
      "stop_one_cpu_nowait", "stop_two_cpus", "stop_machine",
      "stop_machine_cpuslocked", "stop_cpus"] and
  mechanism = "ipi"
  or
  name =
    ["async_schedule", "async_schedule_domain", "async_schedule_node",
      "async_schedule_node_domain", "async_schedule_dev", "dpm_async_fn",
      "dpm_async_with_cleanup"] and
  mechanism = "async"
  or
  name = "request_firmware_nowait" and mechanism = "firmware"
  or
  name =
    ["netif_napi_add", "netif_napi_add_weight", "netif_napi_add_tx",
      "netif_napi_add_tx_weight", "netif_napi_add_config",
      "netif_napi_add_config_locked", "__netif_napi_add",
      "__netif_napi_add_config", "gve_add_napi"] and
  mechanism = "napi"
  or
  name = ["tasklet_init", "tasklet_setup"] and mechanism = "tasklet"
  or
  name = "open_softirq" and mechanism = "softirq"
  or
  name =
    ["init_timer_key", "timer_init_key", "init_timer_on_stack_key",
      "timer_init_on_stack_key", "timer_setup", "timer_setup_on_stack",
      "inet_csk_init_xmit_timers"] and
  mechanism = "timer"
  or
  name = ["hrtimer_setup", "hrtimer_setup_on_stack", "rtc_timer_init"] and
  mechanism = "hrtimer"
  or
  name = ["init_task_work", "set_delayed_call"] and mechanism = "task_work"
  or
  name =
    ["io_uring_cmd_do_in_task_lazy", "io_uring_cmd_complete_in_task",
      "io_queue_worker_create", "__io_req_task_work_add",
      "io_req_task_work_add"] and
  mechanism = "io_uring"
  or
  name = ["usb_fill_control_urb", "usb_fill_bulk_urb", "usb_fill_int_urb"] and
  mechanism = "usb"
  or
  name =
    ["aead_request_set_callback", "ahash_request_set_callback",
      "skcipher_request_set_callback", "akcipher_request_set_callback",
      "kpp_request_set_callback", "acomp_request_set_callback"] and
  mechanism = "crypto"
  or
  name =
    ["init_waitqueue_func_entry", "__init_waitqueue_func_entry",
      "out_of_line_wait_on_bit", "out_of_line_wait_on_bit_lock",
      "wait_on_bit_action", "wait_on_bit_lock_action"] and
  mechanism = "waitqueue"
  or
  name = ["init_poll_funcptr", "vhost_poll_init"] and mechanism = "poll"
  or
  name =
    ["register_fib_notifier", "acpi_install_notify_handler",
      "acpi_dev_install_notify_handler", "register_sys_off_handler",
      "amd_iommu_register_ga_log_notifier"] and
  mechanism = "notifier"
  or
  name =
    ["NF_HOOK", "NF_HOOK_COND", "nf_hook", "xt_hook_ops_alloc",
      "flow_block_cb_setup_simple", "flow_block_cb_alloc"] and
  mechanism = "netfilter"
  or
  name =
    ["dma_fence_add_callback", "set_closure_fn", "closure_call",
      "init_async_submit", "mark_buffer_async_write_endio",
      "ext4_read_bh_nowait", "cifs_call_async", "btrfs_bio_alloc"] and
  mechanism = "block_io"
  or
  name = ["kref_put", "kref_put_mutex", "kref_put_lock"] and
  mechanism = "kref"
  or
  name =
    ["__devres_alloc_node", "devres_alloc_node", "devm_add_action",
      "__devm_add_action", "devm_add_action_or_reset",
      "__devm_add_action_or_reset", "drmm_add_action", "__drmm_add_action",
      "drmm_add_action_or_reset", "__drmm_add_action_or_reset"] and
  mechanism = "teardown"
  or
  name =
    ["cpuhp_setup_state", "cpuhp_setup_state_nocalls",
      "cpuhp_setup_state_multi", "__cpuhp_setup_state",
      "__cpuhp_setup_state_cpuslocked",
      "cpuhp_setup_state_nocalls_cpuslocked"] and
  mechanism = "cpuhp"
}

/**
 * Form B/C: 1-to-1 `(structName, fieldName)` pairs holding deferred callbacks.
 * Keyed strictly by declaring/enclosing struct to prevent field-name collisions.
 */
predicate asyncCallbackField(string structName, string fieldName, string mechanism) {
  (
    structName = "work_struct" and fieldName = "func"
    or
    structName = "btrfs_work" and fieldName = ["func", "ordered_func"]
  ) and
  mechanism = "workqueue"
  or
  structName = "kthread_work" and fieldName = "func" and mechanism = "kthread_worker"
  or
  structName = "timer_list" and fieldName = "function" and mechanism = "timer"
  or
  structName = "hrtimer" and fieldName = "function" and mechanism = "hrtimer"
  or
  structName = "tasklet_struct" and fieldName = ["callback", "func"] and mechanism = "tasklet"
  or
  structName = "softirq_action" and fieldName = "action" and mechanism = "softirq"
  or
  (
    structName = "irqaction" and fieldName = ["handler", "thread_fn"]
    or
    structName = "irq_work" and fieldName = "func"
    or
    structName = "kvm_irq_ack_notifier" and fieldName = "irq_acked"
    or
    structName = "kvm_irq_mask_notifier" and fieldName = "func"
    or
    structName = "clock_event_device" and fieldName = "event_handler"
    or
    structName = "virtqueue_info" and fieldName = "callback"
    or
    structName = "vhost_virtqueue" and fieldName = "handle_kick"
  ) and
  mechanism = "irq"
  or
  (
    structName = "__call_single_data" and fieldName = "func"
    or
    structName = "balance_callback" and fieldName = "func"
  ) and
  mechanism = "ipi"
  or
  structName = "napi_struct" and fieldName = "poll" and mechanism = "napi"
  or
  (
    structName = "notifier_block" and fieldName = "notifier_call"
    or
    structName = "irq_affinity_notify" and fieldName = ["notify", "release"]
    or
    structName = "user_return_notifier" and fieldName = "on_user_return"
    or
    structName = "acpi_hotplug_context" and fieldName = "notify"
  ) and
  mechanism = "notifier"
  or
  (
    structName = "callback_head" and fieldName = "func"
    or
    structName = "delayed_call" and fieldName = "fn"
    or
    structName = "restart_block" and fieldName = "fn"
  ) and
  mechanism = "task_work"
  or
  structName = "rcu_head" and fieldName = "func" and mechanism = "rcu"
  or
  structName = "urb" and fieldName = "complete" and mechanism = "usb"
  or
  (
    structName = "crypto_async_request" and fieldName = "complete"
    or
    structName = "virtio_crypto_request" and fieldName = "alg_cb"
  ) and
  mechanism = "crypto"
  or
  structName = ["wait_queue_entry", "__wait_queue"] and
  fieldName = "func" and
  mechanism = "waitqueue"
  or
  structName = "poll_table_struct" and fieldName = "_qproc" and mechanism = "poll"
  or
  (
    structName = "sock" and
    fieldName =
      ["sk_data_ready", "sk_write_space", "sk_state_change", "sk_error_report",
        "sk_destruct", "sk_backlog_rcv"]
    or
    structName = "netlink_kernel_cfg" and fieldName = "input"
    or
    structName = "udp_tunnel_sock_cfg" and
    fieldName = ["encap_rcv", "gro_receive", "gro_complete"]
  ) and
  mechanism = "socket"
  or
  (
    structName = "sk_buff" and fieldName = "destructor"
    or
    structName = ["ubuf_info", "ubuf_info_msgzc"] and fieldName = "callback"
  ) and
  mechanism = "skb"
  or
  (
    structName = "nf_hook_ops" and fieldName = "hook"
    or
    structName = "nf_conntrack_expect" and fieldName = "expectfn"
    or
    structName = "dst_entry" and fieldName = ["input", "output"]
  ) and
  mechanism = "netfilter"
  or
  (
    structName = "io_task_work" and fieldName = "func"
    or
    structName = "io_wq_work_node" and fieldName = "func"
    or
    structName = "io_wq_data" and fieldName = ["do_work", "free_work"]
  ) and
  mechanism = "io_uring"
  or
  (
    structName = "bio" and fieldName = "bi_end_io"
    or
    structName = "buffer_head" and fieldName = "b_end_io"
    or
    structName = "kiocb" and fieldName = "ki_complete"
    or
    structName = "request" and fieldName = "end_io"
    or
    structName = "ib_cqe" and fieldName = "done"
    or
    structName = "rpc_task" and fieldName = "tk_action"
    or
    structName = "dma_fence_cb" and fieldName = "func"
    or
    structName = "closure" and fieldName = "fn"
    or
    structName = "se_cmd" and
    fieldName = ["execute_cmd", "transport_complete_callback"]
    or
    structName = "ata_queued_cmd" and fieldName = "complete_fn"
    or
    structName = "dm_io_notify" and fieldName = "fn"
    or
    structName = "xfs_buf" and fieldName = "b_iodone"
    or
    structName = "nfs_pgio_header" and fieldName = "pgio_done_cb"
    or
    structName = "nfs_commit_data" and fieldName = "commit_done_cb"
    or
    structName = ["ceph_osd_request", "ceph_mds_request"] and
    fieldName = "r_callback"
    or
    structName = "fuse_args" and fieldName = "end"
    or
    structName = "mid_q_entry" and fieldName = "callback"
  ) and
  mechanism = "block_io"
  or
  (
    structName = "device" and fieldName = "release"
    or
    structName = "class" and fieldName = "dev_release"
    or
    structName = "kobj_type" and fieldName = "release"
    or
    structName = "net_device" and fieldName = "priv_destructor"
    or
    structName = "perf_event" and fieldName = "destroy"
    or
    structName = "bpf_link" and fieldName = "detach"
    or
    structName = "crypto_tfm" and fieldName = "exit"
  ) and
  mechanism = "teardown"
}

/** Form A: function pointer passed as an argument to a known async registrar. */
predicate formArg(string caller, Function cb, string mechanism, string file, int line) {
  exists(FunctionCall fc, Expr arg, string name |
    asyncRegistrarArg(name, mechanism) and
    fc.getTarget().getName() = name and
    arg = fc.getAnArgument() and
    resolveCallback(arg, cb) and
    file = fc.getLocation().getFile().toString() and
    line = fc.getLocation().getStartLine() and
    (
      if exists(fc.getEnclosingFunction())
      then caller = fc.getEnclosingFunction().getName()
      else caller = "<file-scope:" + file + ">"
    )
  )
}

/** Form B: function pointer assigned into a known callback struct field. */
predicate formAssign(string caller, Function cb, string mechanism, string file, int line) {
  exists(AssignExpr ae, FieldAccess fa, string s, string f, string rawMech |
    asyncCallbackField(s, f, rawMech) and
    fa = ae.getLValue() and
    fa.getTarget().getName() = f and
    fieldAccessInStruct(fa, s) and
    resolveCallback(ae.getRValue(), cb) and
    file = ae.getLocation().getFile().toString() and
    line = ae.getLocation().getStartLine() and
    (
      // Disambiguate `struct rcu_head` (#define alias for `callback_head`) in RCU core
      if s = "callback_head" and file.matches("%/kernel/rcu/%")
      then mechanism = "rcu"
      else mechanism = rawMech
    ) and
    (
      if exists(ae.getEnclosingFunction())
      then caller = ae.getEnclosingFunction().getName()
      else caller = "<file-scope:" + file + ">"
    )
  )
}

/** Form C: function pointer set via a designated initializer on a known field. */
predicate formInit(string caller, Function cb, string mechanism, string file, int line) {
  exists(ClassAggregateLiteral cal, Field fld, Expr fe, string s, string f |
    asyncCallbackField(s, f, mechanism) and
    fld.getName() = f and
    fieldInStruct(fld, s) and
    fe = cal.getAFieldExpr(fld) and
    resolveCallback(fe, cb) and
    file = cal.getLocation().getFile().toString() and
    line = cal.getLocation().getStartLine() and
    (
      if exists(cal.getEnclosingFunction())
      then caller = cal.getEnclosingFunction().getName()
      else caller = "<file-scope:" + file + ">"
    )
  )
}

from string caller, Function cb, string mechanism, string form, string file, int line
where
  (
    formArg(caller, cb, mechanism, file, line) and form = "arg"
    or
    formAssign(caller, cb, mechanism, file, line) and form = "assign"
    or
    formInit(caller, cb, mechanism, file, line) and form = "init"
  ) and
  caller != cb.getName()
select
  caller,
  cb.getName() as callee,
  mechanism,
  form,
  file,
  line
