/**
 * @name Universal Linux Kernel Structural & Subgraph Invariants
 * @description Evaluates universal Linux kernel structural invariants across core built-in
 *              anchors (__sys_setsockopt, vfs_write, vfs_read, do_sys_openat2, unix_stream_connect).
 *              Verifies that core entry points and their direct callees have 100% resolved
 *              definitions and 0 ErrorExpr nodes, independent of kernel version or Kconfig.
 * @kind table
 * @id cpp/kernel-db-test/kernel-invariants
 */

import cpp

predicate isCoreAnchor(string name) {
  name in [
      "__sys_setsockopt", "sk_setsockopt", "vfs_write", "vfs_read",
      "do_sys_openat2", "unix_stream_connect"
    ]
}

predicate isDirectKernelCall(Function caller, Function callee) {
  exists(FunctionCall fc |
    fc.getEnclosingFunction() = caller and
    fc.getTarget() = callee and
    not callee.getName().matches("__builtin_%") and
    not callee.getName().matches("__compiletime_%")
  )
}

from
  string anchorName,
  int hasValidBody,
  int directCallees,
  int resolvedCallees,
  int unresolvedCallees,
  int twoHopUnresolved,
  int calleeErrorExprs
where
  isCoreAnchor(anchorName) and
  (
    if exists(Function f | f.getName() = anchorName and f.hasDefinition() and exists(f.getBlock()))
    then hasValidBody = 1
    else hasValidBody = 0
  ) and
  directCallees = count(Function callee |
    exists(Function caller | caller.getName() = anchorName and isDirectKernelCall(caller, callee))
  ) and
  resolvedCallees = count(Function callee |
    exists(Function caller |
      caller.getName() = anchorName and
      isDirectKernelCall(caller, callee) and
      callee.hasDefinition()
    )
  ) and
  unresolvedCallees = directCallees - resolvedCallees and
  twoHopUnresolved = count(Function f2 |
    exists(Function caller, Function f1 |
      caller.getName() = anchorName and
      isDirectKernelCall(caller, f1) and
      isDirectKernelCall(f1, f2) and
      not f2.hasDefinition()
    )
  ) and
  calleeErrorExprs = count(ErrorExpr e |
    exists(Function caller, Function callee |
      caller.getName() = anchorName and
      (e.getEnclosingFunction() = caller or (isDirectKernelCall(caller, callee) and e.getEnclosingFunction() = callee))
    )
  )
select
  anchorName,
  hasValidBody,
  directCallees,
  resolvedCallees,
  unresolvedCallees,
  twoHopUnresolved,
  calleeErrorExprs
