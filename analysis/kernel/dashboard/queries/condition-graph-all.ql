import cpp
import semmle.code.cpp.ir.dataflow.ResolveCall
import semmle.code.cpp.pointsto.CallGraph
import condition_graph

cached
predicate exprCallEdge(ExprCall a, Function b) {
  a.getExpr().(TargetPointsToExpr).pointsTo() = b and
  a.getExpr().(TargetPointsToExpr).confidence() >= 0.2 and
  exists(int numParams |
    numParams = count(b.getParameter(_)) and
    forall(int i | i in [0 .. numParams - 1] |
      exists(Parameter p | p = b.getParameter(i) |
        exists(Type paramType | paramType = p.getType() |
          exists(Expr arg | arg = a.getArgument(i) |
            arg.getType().(PointerType).getBaseType() = paramType
            or
            arg.getType() = paramType
          )
        )
      )
    )
  )
}

predicate badname(Function f) {
  f.getName().regexpMatch("__builtin_.*|__compile.*") or
  not exists(f.getBlock()) or
  f.getBlock().isEmpty()
}

pragma[nomagic]
predicate funcEdge(Function caller, Function callee) {
  not badname(caller) and
  not badname(callee) and
  exists(Call c |
    c.getEnclosingFunction() = caller and
    callee = resolveCall(c)
  )
}

class ConditionDependentCall extends Call {
  ConditionDependentCall() {
    conditionGuardsCall(_, _, this)
    or
    exists(Function handler |
      genlDeclarativeGateFunction(handler, _, _, _, _) and
      this.getEnclosingFunction() = handler
    )
  }
}

pragma[nomagic]
Function cdcDirectTarget(ConditionDependentCall cdc) {
  result = resolveCall(cdc) and not badname(result)
}

pragma[nomagic]
predicate reachableFunc(Function start, Function last) {
  start = cdcDirectTarget(_) and
  (
    last = start
    or
    exists(Function mid |
      reachableFunc(start, mid) and
      funcEdge(mid, last)
    )
  )
}

from ConditionDependentCall cdc, Function last
where reachableFunc(cdcDirectTarget(cdc), last)
select cdc.toString(), last.getName(), cdc.getLocation().toString(),
  last.getDefinitionLocation().toString()