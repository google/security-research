/**
 * @name Call-Graph & Operations Table Function Resolution Integrity
 * @description Measures intrinsic call-graph and function-pointer resolution rates:
 *              when translation units abort or fail to extract, callers in other files
 *              and ops struct initializers reference function declarations whose
 *              definitions are missing (!hasDefinition()).
 * @kind table
 * @id cpp/kernel-db-test/callgraph-completeness
 */

import cpp

predicate isOpsStructName(string name) {
  name in [
      "file_operations", "proto_ops", "net_device_ops", "inode_operations",
      "seq_operations", "vm_operations_struct", "super_operations"
    ]
}

predicate isNonBuiltinTarget(Function f) {
  not f.getName().matches("__builtin_%") and
  not f.getName().matches("__compiletime_%")
}

from
  int totalCFunctionCalls,
  int resolvedCFunctionCalls,
  int unresolvedCFunctionCalls,
  int fsTotalCalls, int fsResolvedCalls,
  int netTotalCalls, int netResolvedCalls,
  int opsTotalFuncPtrs,
  int opsResolvedFuncPtrs,
  int opsUnresolvedFuncPtrs,
  int totalExprCalls
where
  totalCFunctionCalls = count(FunctionCall fc |
    fc.getFile().getExtension() = "c" and isNonBuiltinTarget(fc.getTarget())
  ) and
  resolvedCFunctionCalls = count(FunctionCall fc |
    fc.getFile().getExtension() = "c" and
    isNonBuiltinTarget(fc.getTarget()) and
    fc.getTarget().hasDefinition()
  ) and
  unresolvedCFunctionCalls = totalCFunctionCalls - resolvedCFunctionCalls and
  fsTotalCalls = count(FunctionCall fc |
    fc.getFile().getExtension() = "c" and
    fc.getFile().getRelativePath().matches("fs/%") and
    isNonBuiltinTarget(fc.getTarget())
  ) and
  fsResolvedCalls = count(FunctionCall fc |
    fc.getFile().getExtension() = "c" and
    fc.getFile().getRelativePath().matches("fs/%") and
    isNonBuiltinTarget(fc.getTarget()) and
    fc.getTarget().hasDefinition()
  ) and
  netTotalCalls = count(FunctionCall fc |
    fc.getFile().getExtension() = "c" and
    fc.getFile().getRelativePath().matches("net/%") and
    isNonBuiltinTarget(fc.getTarget())
  ) and
  netResolvedCalls = count(FunctionCall fc |
    fc.getFile().getExtension() = "c" and
    fc.getFile().getRelativePath().matches("net/%") and
    isNonBuiltinTarget(fc.getTarget()) and
    fc.getTarget().hasDefinition()
  ) and
  opsTotalFuncPtrs = count(FunctionAccess fa |
    exists(ClassAggregateLiteral cal |
      isOpsStructName(cal.getType().getUnspecifiedType().(Struct).getName()) and
      cal.getAChild*() = fa
    )
  ) and
  opsResolvedFuncPtrs = count(FunctionAccess fa |
    exists(ClassAggregateLiteral cal |
      isOpsStructName(cal.getType().getUnspecifiedType().(Struct).getName()) and
      cal.getAChild*() = fa and
      fa.getTarget().hasDefinition()
    )
  ) and
  opsUnresolvedFuncPtrs = opsTotalFuncPtrs - opsResolvedFuncPtrs and
  totalExprCalls = count(ExprCall ec)
select
  totalCFunctionCalls,
  resolvedCFunctionCalls,
  unresolvedCFunctionCalls,
  fsTotalCalls, fsResolvedCalls,
  netTotalCalls, netResolvedCalls,
  opsTotalFuncPtrs,
  opsResolvedFuncPtrs,
  opsUnresolvedFuncPtrs,
  totalExprCalls
