/**
 * @name Indirect ops call targets
 * @description Resolves indirect call sites (ExprCall) invoking function-pointer struct fields
 *              to concrete callback implementations registered in kernel ops initializers.
 * @id cpp/dashboard/ops-edges
 * @kind table
 */

import cpp
import async_edges

string locationString(Locatable l) {
  result = l.getFile().toString() + ":" +
    l.getLocation().getStartLine().toString() + ":" +
    l.getLocation().getStartColumn().toString() + ":" +
    l.getLocation().getEndLine().toString() + ":" +
    l.getLocation().getEndColumn().toString()
}

/**
 * Resolves `expr` (unwrapping implicit/explicit conversions, address-of `&fn`,
 * and ternary `cond ? a : b` branches) to a target `Function`.
 */
predicate resolvesToFunction(Expr expr, Function target) {
  exists(Expr e | e = expr.getUnconverted() |
    target = e.(FunctionAccess).getTarget()
    or
    target = e.(AddressOfExpr).getAddressable()
    or
    resolvesToFunction(e.(ConditionalExpr).getThen(), target)
    or
    resolvesToFunction(e.(ConditionalExpr).getElse(), target)
  )
}

/**
 * Holds if `v` is a local variable or parameter initialized or assigned
 * directly from an access to function-pointer `field`.
 */
predicate stackVarFromFieldStep1(StackVariable v, Field field) {
  field.getType() instanceof FunctionPointerIshType and
  (
    v.getInitializer().getExpr().getUnconverted() = field.getAnAccess()
    or
    exists(AssignExpr ae |
      ae.getLValue().(VariableAccess).getTarget() = v and
      ae.getRValue().getUnconverted() = field.getAnAccess()
    )
  )
}

/**
 * Holds if `v` is a local variable or parameter holding an access to `field`
 * either directly (e.g., `open = f->f_op->open` in `do_dentry_open`) or via
 * up to two local variable copies (e.g., `INDIRECT_CALL_2` / `INDIRECT_CALL_3`
 * macro temporaries `__f3 -> __f2 -> __f1`).
 */
predicate stackVarHoldsOpsField(StackVariable v, Field field) {
  stackVarFromFieldStep1(v, field)
  or
  exists(StackVariable prev |
    (
      stackVarFromFieldStep1(prev, field)
      or
      exists(StackVariable prev0 |
        stackVarFromFieldStep1(prev0, field) and
        (
          prev.getInitializer().getExpr().getUnconverted().(VariableAccess).getTarget() = prev0
          or
          exists(AssignExpr ae0 |
            ae0.getLValue().(VariableAccess).getTarget() = prev and
            ae0.getRValue().getUnconverted().(VariableAccess).getTarget() = prev0
          )
        )
      )
    ) and
    (
      v.getInitializer().getExpr().getUnconverted().(VariableAccess).getTarget() = prev
      or
      exists(AssignExpr ae |
        ae.getLValue().(VariableAccess).getTarget() = v and
        ae.getRValue().getUnconverted().(VariableAccess).getTarget() = prev
      )
    )
  )
}

/**
 * Holds if `child` is an anonymous C struct/union nested directly inside
 * `parent` (either via AST element nesting, an unnamed member field of type
 * `child`, or a field-access qualifier of type `parent`).
 */
predicate anonStructParentStep(Class child, Class parent) {
  child.getName().matches(["", "(unnamed%"]) and
  (
    parent = child.getEnclosingElement()
    or
    exists(Field anonField |
      anonField.getDeclaringType() = parent and
      anonField.getType().getUnderlyingType() = child
    )
    or
    exists(FieldAccess fa, Expr q, Type t |
      fa.getTarget().getDeclaringType() = child and
      q = fa.getQualifier() and
      t = q.getType().getUnderlyingType() and
      (
        parent = t or
        parent = t.(PointerType).getBaseType().getUnderlyingType()
      )
    )
  )
}

/**
 * Resolves `fld` to its declaring struct name, walking out of anonymous C
 * structs/unions (such as `struct genl_split_ops`'s anonymous union/struct
 * members `doit`, `dumpit`, `start`, `done`, `pre_doit`, `post_doit`).
 */
string opsContainerName(Field fld) {
  exists(string n | n = fld.getDeclaringType().getName() |
    if n != "" and not n.matches("(unnamed%")
    then result = n
    else
      exists(Class enc |
        anonStructParentStep+(fld.getDeclaringType(), enc) and
        enc.getName() != "" and
        not enc.getName().matches("(unnamed%") and
        result = enc.getName()
      )
  )
}

/**
 * Holds if `fieldExpr` registers `target` on `regField` either via a struct
 * aggregate initializer (`ClassAggregateLiteral`) or via a dynamic field
 * assignment (`AssignExpr`, such as `shrinker->scan_objects = ...` in 6.7+),
 * excluding asynchronous callback fields already modeled in `async_edges`.
 */
predicate opsFieldRegistration(Field regField, Expr fieldExpr, Function target) {
  regField.getType() instanceof FunctionPointerIshType and
  (
    exists(ClassAggregateLiteral cal |
      fieldExpr = cal.getAFieldExpr(regField) and
      resolvesToFunction(fieldExpr, target)
    )
    or
    not asyncCallbackField(opsContainerName(regField), regField.getName(), _) and
    exists(AssignExpr ae |
      ae.getLValue().(FieldAccess).getTarget() = regField and
      fieldExpr = ae.getRValue() and
      resolvesToFunction(fieldExpr, target)
    )
  )
}

/**
 * Holds if `ec` invokes function-pointer `callField` either directly
 * (`ec.getExpr() = callField.getAnAccess()`) or through a same-function local
 * variable / parameter (`stackVarHoldsOpsField`).
 */
predicate opsFieldCall(Field callField, ExprCall ec) {
  callField.getType() instanceof FunctionPointerIshType and
  (
    ec.getExpr().getUnconverted() = callField.getAnAccess()
    or
    not asyncCallbackField(opsContainerName(callField), callField.getName(), _) and
    exists(StackVariable v |
      stackVarHoldsOpsField(v, callField) and
      ec.getExpr().getUnconverted().(VariableAccess).getTarget() = v
    )
  )
}

/**
 * Holds if an ops callback registered on `regField` is invoked through
 * `callField` — either directly (`regField = callField`), via Generic
 * Netlink's `genl_ops` / `genl_small_ops` / `genl_family` ->
 * `genl_ops` / `genl_split_ops` normalization in `net/netlink/genetlink.c`,
 * or via `netlink_kernel_cfg.input` -> `netlink_sock.netlink_rcv` in
 * `net/netlink/af_netlink.c`.
 */
predicate compatibleOpsField(Field regField, Field callField) {
  regField = callField
  or
  opsContainerName(regField) in ["genl_ops", "genl_small_ops"] and
  opsContainerName(callField) in ["genl_ops", "genl_split_ops"] and
  regField.getName() = callField.getName() and
  regField.getName() in ["doit", "dumpit", "start", "done"]
  or
  opsContainerName(regField) = "genl_family" and
  opsContainerName(callField) = "genl_split_ops" and
  regField.getName() = callField.getName() and
  regField.getName() in ["pre_doit", "post_doit"]
  or
  opsContainerName(regField) = "netlink_kernel_cfg" and
  opsContainerName(callField) = "netlink_sock" and
  regField.getName() = "input" and
  callField.getName() = "netlink_rcv"
}

from
  Field regField,
  Field callField,
  Expr fieldExpr,
  Function target,
  ExprCall ec,
  Function caller,
  BlockStmt targetBody,
  BlockStmt callerBody,
  string parentName
where
  // 1. Ops registration (aggregate initializer or dynamic field assignment)
  opsFieldRegistration(regField, fieldExpr, target) and
  compatibleOpsField(regField, callField) and

  // 2. Indirect call invocation (direct field access or local variable)
  opsFieldCall(callField, ec) and
  caller = ec.getEnclosingFunction() and

  // 3. Body and identifier validity
  target.getBlock() = targetBody and
  caller.getBlock() = callerBody and
  regField.getName() != "" and
  target.getName() != "" and
  parentName = opsContainerName(regField) and
  parentName != "" and
  parentName != "<anon>"
select
  locationString(fieldExpr) as definition,
  parentName as parent,
  regField.getName(),
  target.getName(),
  targetBody.getFile().toString() as target_file,
  targetBody.getLocation().getStartLine() as target_start,
  targetBody.getLocation().getEndLine() as target_end,
  ec.getFile().toString() as exprcall_file,
  ec.getLocation().getStartLine() as exprcall_line,
  callerBody.getLocation().getStartLine() as exprcall_parent_start,
  callerBody.getLocation().getEndLine() as exprcall_parent_end