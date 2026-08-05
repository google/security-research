/**
 * @id callgraph-indirect
 * @kind path-problem
 * @severity error
 */

import cpp
import semmle.code.cpp.ir.dataflow.ResolveCall
import semmle.code.cpp.dataflow.new.TaintTracking

module IndirectFlowConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.asConvertedExpr() instanceof FunctionAccess or
    source.asIndirectConvertedExpr() instanceof FunctionAccess
  }

  predicate isSink(DataFlow::Node sink) {
    exists(ExprCall ec |
      sink.asConvertedExpr() = ec.getExpr() or
      sink.asIndirectConvertedExpr() = ec.getExpr()
    )
  }
}

IndirectFlow::PathNode getPathNode(Element e) {
  exists(IndirectFlow::PathNode pn, DataFlow::Node n |
    result = pn and
    pn.getNode() = n and
    n.getLocation() = e.getLocation()
  )
}

module IndirectFlow = TaintTracking::Global<IndirectFlowConfiguration>;

class ExprTargetCallEdge extends AdditionalControlFlowEdge {
  ExprTargetCallEdge() { exists(Function fun | mkElement(this) = fun) }

  override ControlFlowNode getAnEdgeTarget() {
    exists(ExprCall e | e.getEnclosingFunction() = mkElement(this) and result = e.getExpr())
  }
}

cached
class ExprSourceCallEdge extends AdditionalControlFlowEdge {
  cached
  ExprSourceCallEdge() { exists(ExprCall expc | mkElement(this) = expc.getExpr()) }

  cached
  override ControlFlowNode getAnEdgeTarget() {
    exists(IndirectFlow::PathNode target |
      IndirectFlow::flowPath(target, getPathNode(mkElement(this))) and
      target.getNode().asConvertedExpr() = mkElement(result).(Function).getAnAccess()
      or
      target.getNode().asIndirectConvertedExpr() = mkElement(result).(Function).getAnAccess()
    )
  }
}

predicate badname(Function fun) {
  fun.getName().regexpMatch("__builtin_*|__compiletime_*|fortify_memcpy_chk|cpu_online|_printk")
}

query predicate edges(ControlFlowNode pred, ControlFlowNode succ) {
  (
    pred.(ExprTargetCallEdge).(Function) = succ.(Call).getEnclosingFunction() and
    not badname(succ.(Call).getTarget())
    or
    pred.(ExprSourceCallEdge).getAnEdgeTarget() = succ.(ExprTargetCallEdge)
  )
}

from ControlFlowNode nodeFrom, ControlFlowNode nodeTo
where
  not edges(nodeTo, _) and
  not edges(_, nodeFrom) and
  edges+(nodeFrom, nodeTo)
select nodeTo, nodeFrom, nodeTo, "callgraph-indirect"
