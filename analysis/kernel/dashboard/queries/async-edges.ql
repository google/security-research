/**
 * @name Asynchronous callback call-graph edges
 * @description Recovers asynchronous and conditional indirect callback edges
 *              that synchronous call-graph queries (all-calls.ql and ops_edges.ql)
 *              miss: callbacks registered now and invoked later by a kernel
 *              dispatcher (workqueue, timer, hrtimer, RCU, IRQ, IPI, NAPI,
 *              kthread, notifier, task_work, io_uring, USB URB, crypto,
 *              waitqueue, poll, socket, skb, netfilter, block_io, firmware,
 *              async, teardown, cpuhp) plus inline conditional indirect
 *              callbacks (kref, rhashtable_destroy, nf_hook_inline).
 *              Emits rendered strings (caller, callee, mechanism, form, file, line)
 *              to avoid entity serialization overhead in BQRS.
 * @id cpp/dashboard/async-edges
 * @kind table
 * @tags security kernel callgraph async
 */

import cpp
import async_edges

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
      // Disambiguate `struct rcu_head` (#define alias for `callback_head` in <linux/types.h>)
      if s = "callback_head" and isRcuCallbackHeadAssign(fa, cb)
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

/**
 * Form C: function pointer set via a designated initializer on a known field.
 *
 * When the initializer is at file scope (e.g., `DECLARE_WORK`, static
 * `notifier_block`, or static `nf_hook_ops[]`), `staticInitRegistrarCaller`
 * bridges the edge directly to any enclosing function that passes the static
 * variable to a registration or scheduling call (Recommendation D2). If no
 * such call exists in the translation unit, `<file-scope:...>` is emitted.
 */
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
      else
        if exists(Function regFn | staticInitRegistrarCaller(cal, regFn))
        then
          exists(Function regFn |
            staticInitRegistrarCaller(cal, regFn) and
            caller = regFn.getName()
          )
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
