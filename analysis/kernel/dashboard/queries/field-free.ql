/**
 * @id field-access-free
 * @kind path-problem
 * @severity error
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking

module FieldFreeFlowConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source.asExpr() instanceof FieldAccess }

  predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall fc | fc.getTarget().hasName("kfree") and fc.getArgument(0) = sink.asExpr())
  }
}

module FieldFreeFlow = TaintTracking::Global<FieldFreeFlowConfiguration>;

import FieldFreeFlow::PathGraph

from FieldFreeFlow::PathNode source, FieldFreeFlow::PathNode sink
where FieldFreeFlow::flowPath(source, sink)
select sink, source, sink, "field-access to free"
