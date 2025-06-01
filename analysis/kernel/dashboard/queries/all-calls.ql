/**
 * @name all-calls
 * @id callgraph-all
 * @kind path-problem
 * @severity warning
 */

import cpp
import semmle.code.cpp.pointsto.CallGraph
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


cached predicate exprCallEdge(ExprCall a, Function b) {
  a.getExpr().(TargetPointsToExpr).pointsTo() = b and
  a.getExpr().(TargetPointsToExpr).confidence() >= 0.2 and
  // Get the number of parameters of the function
  exists(int numParams |
    numParams = count(b.getParameter(_)) and
    // Iterate over each parameter
    forall(int i | i in [0 .. numParams - 1] |
      exists(Parameter p | p = b.getParameter(i) |
        // Get the type of the parameter
        exists(Type paramType | paramType = p.getType() |
          // Get the argument at the corresponding index
          exists(Expr arg | arg = a.getArgument(i) |
            // Check if the argument's type is compatible with the parameter's type
            arg.getType().(PointerType).getBaseType() = paramType
            or
            arg.getType() = paramType
          )
        )
      )
    )
  )
}

predicate notInteresting(Function fun) {
  fun.getName().matches("__compiletime_assert_%") or
  fun.getBlock().isEmpty() 
}

query predicate edges(ControlFlowNode a, ControlFlowNode b) {
  // ExprCall to Function
  exprCallEdge(a, b)
  or
  // Function to ExprCall
  a = b.(ExprCall).getEnclosingFunction() and not notInteresting(a)
  or
  // Function to  FunctionCall
  a = b.(FunctionCall).getEnclosingFunction() and not notInteresting(a)
  or
  // FunctionCall to Function
  a.(FunctionCall).getTarget() = b and not notInteresting(b) or

  // Fallback to indirect calls query in case we missed something
  a.(ExprTargetCallEdge).(Function) = b.(Call).getEnclosingFunction()
  or
  a.(ExprSourceCallEdge).getAnEdgeTarget() = b.(ExprTargetCallEdge) or 
  // Maybe it's a more complex call than just function -> call
  b = resolveCall(a)
}

from ControlFlowNode nodeFrom, ControlFlowNode nodeTo
where edges(nodeFrom, nodeTo)
select nodeTo, nodeFrom, nodeTo, "callgraph-all"
