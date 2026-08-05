/**
 * @id callgraph-root-leaf
 * @kind path-problem
 * @severity error
 * codeql database analyze -j$(nproc) --format=sarif-latest --output=dashboard_data/callgraph-direct.sarif ./codeql_db/linux_db_new/ ~/vscode-codeql-starter/ql/cpp/ql/src/Security/dashboard/callgraph_direct.ql --rerun
 */

import cpp
import semmle.code.cpp.ir.dataflow.ResolveCall

predicate badname(Function fun) {
  fun.getName().regexpMatch("__builtin_*|__compiletime_*|fortify_memcpy_chk|cpu_online|_printk")
}

query predicate edges(ControlFlowNode pred, ControlFlowNode succ) {
  (
    pred = succ.(Call).getEnclosingFunction() and not badname(resolveCall(succ))
    or
    //succ = resolveCall(pred) and not badname(succ)
    // or
    pred.(Call).getTarget() = succ and not badname(succ)
  )
}

from ControlFlowNode nodeFrom, ControlFlowNode nodeTo
where
  not edges(nodeTo, _)
  and
  //not edges(_, nodeFrom) and
  edges+(nodeFrom, nodeTo)
select nodeTo, nodeFrom, nodeTo, "callgraph-direct"
