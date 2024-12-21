/**
 * @id field-access-leak
 * @kind path-problem
 * @severity error
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking

abstract class LeakNode extends DataFlow::Node {
  LeakNode() { any() }
}

class PrintkArgs extends LeakNode {
  PrintkArgs() {
    exists(FunctionCall fc |
      fc.getAnArgument() = this.asExpr() and fc.getTarget().hasName("printk")
    )
  }
}

class CopyToUserOut extends LeakNode {
  CopyToUserOut() {
    exists(FunctionCall fc |
      fc.getTarget().hasName("copy_to_user") and fc.getArgument(1) = this.asExpr()
    )
  }
}

class PutUser extends LeakNode {
  PutUser() {
    exists(FunctionCall fc |
      fc.getTarget().hasName("put_user") and fc.getArgument(0) = this.asExpr()
    )
  }
}

module LeakFlowConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source.asExpr() instanceof FieldAccess }

  predicate isSink(DataFlow::Node sink) { sink instanceof LeakNode }
}

module LeakFlow = TaintTracking::Global<LeakFlowConfiguration>;

import LeakFlow::PathGraph

from LeakFlow::PathNode source, LeakFlow::PathNode sink
where LeakFlow::flowPath(source, sink)
select sink, source, sink, "field-access to leak"
