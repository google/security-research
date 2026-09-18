/**
 * @name Syscall-reachable pairs
 * @description Emits (syscall, function, file) for every function reachable from each
 *   __do_sys_* entry over the full call graph (direct + indirect calls). Emitting
 *   the relative file path provides an exact join key (function, file) for location
 *   assembly while avoiding dynamic string concatenation in QL to prevent string-pool
 *   exhaustion.
 * @id cpp/dashboard/syscall-node-pairs
 * @kind table
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
    result = pn and pn.getNode() = n and n.getLocation() = e.getLocation()
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
  cached ExprSourceCallEdge() { exists(ExprCall expc | mkElement(this) = expc.getExpr()) }
  cached override ControlFlowNode getAnEdgeTarget() {
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
  exists(int numParams |
    numParams = count(b.getParameter(_)) and
    forall(int i | i in [0 .. numParams - 1] |
      exists(Parameter p | p = b.getParameter(i) |
        exists(Type paramType | paramType = p.getType() |
          exists(Expr arg | arg = a.getArgument(i) |
            arg.getType().(PointerType).getBaseType() = paramType or
            arg.getType() = paramType
          )
        )
      )
    )
  )
}

predicate notInteresting(Function fun) {
  fun.getName().matches("__compiletime_assert_%") or
  fun.getName().matches("__builtin_%") or
  not exists(fun.getBlock()) or
  fun.getBlock().isEmpty()
}

predicate edges(ControlFlowNode a, ControlFlowNode b) {
  exprCallEdge(a, b) and not notInteresting(b)
  or a = b.(ExprCall).getEnclosingFunction() and not notInteresting(a)
  or a = b.(FunctionCall).getEnclosingFunction() and not notInteresting(a)
  or a.(FunctionCall).getTarget() = b and not notInteresting(b)
  or a.(ExprTargetCallEdge).(Function) = b.(Call).getEnclosingFunction()
  or a.(ExprSourceCallEdge).getAnEdgeTarget() = b.(ExprTargetCallEdge)
  or b = resolveCall(a) and not notInteresting(b)
}

class SyscallEntry extends Function {
  SyscallEntry() { this.getName().regexpMatch("__do_sys_.*") and exists(this.getBlock()) }
}

from SyscallEntry entry, Function reached
where
  edges+(entry, reached) and
  reached != entry and
  not notInteresting(reached)
select
  entry.getName() as syscall,
  reached.getName() as function,
  reached.getFile().getRelativePath() as file
