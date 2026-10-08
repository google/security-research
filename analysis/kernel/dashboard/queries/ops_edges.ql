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
 * ternary `cond ? a : b` branches, and comma expressions) to a `Function`.
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
    or
    resolvesToFunction(e.(CommaExpr).getRightOperand(), target)
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
 * Holds if local variable `dst` is initialized or assigned directly from `src`.
 */
predicate stackVarCopyStep(StackVariable src, StackVariable dst) {
  dst.getInitializer().getExpr().getUnconverted().(VariableAccess).getTarget() = src
  or
  exists(AssignExpr ae |
    ae.getLValue().(VariableAccess).getTarget() = dst and
    ae.getRValue().getUnconverted().(VariableAccess).getTarget() = src
  )
}

/**
 * Holds if `v` is a local variable or parameter holding an access to `field`
 * either directly (e.g., `open = f->f_op->open` in `do_dentry_open`) or via
 * up to three local variable copies (covering `INDIRECT_CALL_1` through
 * `INDIRECT_CALL_4` macro temporaries `__f4 -> __f3 -> __f2 -> __f1`).
 */
predicate stackVarHoldsOpsField(StackVariable v, Field field) {
  stackVarFromFieldStep1(v, field)
  or
  exists(StackVariable v1 |
    stackVarFromFieldStep1(v1, field) and
    (
      stackVarCopyStep(v1, v)
      or
      exists(StackVariable v2 |
        stackVarCopyStep(v1, v2) and
        (
          stackVarCopyStep(v2, v)
          or
          exists(StackVariable v3 |
            stackVarCopyStep(v2, v3) and
            stackVarCopyStep(v3, v)
          )
        )
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
 * Resolves `cal` to its outermost enclosing `ClassAggregateLiteral` when `cal`
 * initializes an anonymous inner struct or union (e.g. `genl_split_ops`), so
 * all sibling fields initialized in the same ops struct instance share one
 * canonical registration-site span.
 */
ClassAggregateLiteral outermostOpsAggregate(ClassAggregateLiteral cal) {
  if
    cal.getType().getUnderlyingType().getName().matches(["", "(unnamed%"]) and
    cal.getEnclosingElement() instanceof ClassAggregateLiteral
  then result = outermostOpsAggregate(cal.getEnclosingElement())
  else result = cal
}

/**
 * Holds if `regSite` registers `target` on `regField` either via a struct
 * aggregate initializer (`ClassAggregateLiteral`, where `regSite` is the
 * enclosing struct initializer instance) or via a dynamic field assignment
 * (`AssignExpr`, such as `shrinker->scan_objects = ...`), excluding
 * asynchronous callback fields already modeled in `async_edges`.
 */
predicate opsFieldRegistration(Field regField, Expr regSite, Function target) {
  regField.getType() instanceof FunctionPointerIshType and
  (
    not asyncCallbackField(opsContainerName(regField), regField.getName(), _)
    or
    opsContainerName(regField) = "netlink_kernel_cfg" and regField.getName() = "input"
  ) and
  (
    exists(ClassAggregateLiteral cal, Expr fieldExpr |
      fieldExpr = cal.getAFieldExpr(regField) and
      resolvesToFunction(fieldExpr, target) and
      regSite = outermostOpsAggregate(cal)
    )
    or
    exists(AssignExpr ae |
      ae.getLValue().(FieldAccess).getTarget() = regField and
      resolvesToFunction(ae.getRValue(), target) and
      regSite = ae
    )
  )
}

/**
 * Holds if `ec` invokes function-pointer `callField` either directly
 * (`ec.getExpr() = callField.getAnAccess()`) or through a same-function local
 * variable / parameter (`stackVarHoldsOpsField`), excluding asynchronous
 * callback fields already modeled in `async_edges`.
 */
predicate opsFieldCall(Field callField, ExprCall ec) {
  callField.getType() instanceof FunctionPointerIshType and
  not asyncCallbackField(opsContainerName(callField), callField.getName(), _) and
  (
    ec.getExpr().getUnconverted() = callField.getAnAccess()
    or
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
  Expr regSite,
  Function target,
  ExprCall ec,
  Function caller,
  BlockStmt targetBody,
  BlockStmt callerBody,
  string parentName
where
  // 1. Ops registration (aggregate initializer or dynamic field assignment)
  opsFieldRegistration(regField, regSite, target) and
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
  locationString(regSite) as definition,
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