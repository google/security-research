import cpp
import semmle.code.cpp.pointsto.CallGraph

class ExprCallEdge extends ExprCall {
    ExprCallEdge() {
        any()
    }

    Element getPointsTo() { result = this.getQualifier().(TargetPointsToExpr).pointsTo() }
}

from ExprCallEdge ece
select ece