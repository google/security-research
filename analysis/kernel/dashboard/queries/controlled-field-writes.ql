/**
 * @id controlled-field-writes
 * @kind path-problem
 * @severity error
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow

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

class OpsAggregateLiteral extends ClassAggregateLiteral {
  Field field;
  OpsAggregateLiteral() { exists(this.getAFieldExpr(field)) and field.getType() instanceof FunctionPointerIshType }

  Field getField() { result = field} 
}

module FieldWriteFlowConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof UserControlled }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2){
    exists(OpsAggregateLiteral oal, Field field, Function func, ExprCall ec | 
     oal.getField() = field and func = oal.getAFieldExpr(field).(FunctionAccess).getTarget() and ec.getExpr() = field.getAnAccess() and node2.asParameter() = func.getAParameter() and ec.getArgument(node2.asParameter().getIndex()) = node1.asExpr() )

  }

  predicate isSink(DataFlow::Node sink) { exists(Assignment ae, FieldAccess fa | fa = ae.getLValue() and ae.getRValue() = sink.asExpr()) }
}

module FieldWriteFlow = DataFlow::Global<FieldWriteFlowConfiguration>;

import FieldWriteFlow::PathGraph

from FieldWriteFlow::PathNode source, FieldWriteFlow::PathNode sink
where FieldWriteFlow::flowPath(source, sink)
select sink, source, sink, "user-controlled to field-write"
