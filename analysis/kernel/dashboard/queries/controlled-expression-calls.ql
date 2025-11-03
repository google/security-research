/**
 * @id controlled-exprcall-args
 * @kind path-problem
 * @severity error
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking

abstract class UserControlled extends DataFlow::Node {
  UserControlled() { any() }
}

class CopyFromUser extends UserControlled {
  CopyFromUser() {
    exists(FunctionCall usercopy |
      this.asDefiningArgument() = usercopy.getArgument(0) and
      usercopy.getTarget().hasName("copy_from_user")
    )
  }
}

class SysCallArg extends UserControlled {
  SysCallArg() {
    exists(Function fun |
      fun.getAParameter() = this.asParameter() and
      fun.getName().matches("__do_sys_%")
    )
  }
}

module ExprCallFlowConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof UserControlled }

  predicate isSink(DataFlow::Node sink) { exists(ExprCall ec | sink.asExpr() = ec.getAnArgument()) }
}

module ExprCallFlow = TaintTracking::Global<ExprCallFlowConfiguration>;

import ExprCallFlow::PathGraph

from ExprCallFlow::PathNode source, ExprCallFlow::PathNode sink
where ExprCallFlow::flowPath(source, sink)
select sink, source, sink, "user-controlled to exprcall"
