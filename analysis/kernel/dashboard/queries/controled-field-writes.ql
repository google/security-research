/**
 * @id controlled-field-writes
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

module FieldWriteFlowConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof UserControlled }

  predicate isSink(DataFlow::Node sink) { exists(FieldAccess fa | fa = sink.asExpr()) }
}

module FieldWriteFlow = TaintTracking::Global<FieldWriteFlowConfiguration>;

import FieldWriteFlow::PathGraph

from FieldWriteFlow::PathNode source, FieldWriteFlow::PathNode sink
where FieldWriteFlow::flowPath(source, sink)
select sink, source, sink, "user-controlled to field-write"
