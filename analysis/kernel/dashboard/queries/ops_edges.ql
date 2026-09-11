/**
 * @name Indirect ops call targets
 * @description Resolves indirect call sites (ExprCall) invoking function-pointer struct fields
 *              to concrete callback implementations registered in kernel ops initializers.
 * @id cpp/dashboard/ops-edges
 * @kind table
 */

import cpp

string locationString(Locatable l) {
  result = l.getFile().toString() + ":" +
    l.getLocation().getStartLine().toString() + ":" +
    l.getLocation().getStartColumn().toString() + ":" +
    l.getLocation().getEndLine().toString() + ":" +
    l.getLocation().getEndColumn().toString()
}

class OpsAggregateLiteral extends ClassAggregateLiteral {
  Field field;

  OpsAggregateLiteral() {
    exists(this.getAFieldExpr(field)) and
    field.getType() instanceof FunctionPointerIshType
  }

  Field getField() { result = field }
}

from
  OpsAggregateLiteral oal,
  Field field,
  Expr fieldExpr,
  Function target,
  ExprCall ec,
  Function caller,
  BlockStmt targetBody,
  BlockStmt callerBody
where
  // 1. Ops registration
  field = oal.getField() and
  fieldExpr = oal.getAFieldExpr(field) and
  exists(Expr e | e = fieldExpr.getUnconverted() |
    target = e.(FunctionAccess).getTarget() or
    target = e.(AddressOfExpr).getAddressable()
  ) and

  // 2. Indirect call invocation
  ec.getExpr() = field.getAnAccess() and
  caller = ec.getEnclosingFunction() and

  // 3. Body and identifier validity
  target.getBlock() = targetBody and
  caller.getBlock() = callerBody and
  field.getName() != "" and
  target.getName() != "" and
  field.getDeclaringType().getName() != ""
select
  locationString(fieldExpr) as definition,
  field.getDeclaringType().getName() as parent,
  field.getName(),
  target.getName(),
  targetBody.getFile().toString() as target_file,
  targetBody.getLocation().getStartLine() as target_start,
  targetBody.getLocation().getEndLine() as target_end,
  ec.getFile().toString() as exprcall_file,
  ec.getLocation().getStartLine() as exprcall_line,
  callerBody.getLocation().getStartLine() as exprcall_parent_start,
  callerBody.getLocation().getEndLine() as exprcall_parent_end