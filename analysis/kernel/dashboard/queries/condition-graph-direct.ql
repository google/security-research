import cpp
import semmle.code.cpp.controlflow.Guards
import semmle.code.cpp.dataflow.new.TaintTracking

module CapabilityFlowConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof NSCapabilities or
    source.asExpr() instanceof Capabilities
  }


  predicate isSink(DataFlow::Node sink) {
    exists(IfStmt ifst | ifst.getCondition().getAChild() = sink.asExpr())
  }
}

module CapabilityFlow = TaintTracking::Global<CapabilityFlowConfiguration>;

abstract class InterestingConditionCalls extends Element {
  string getInterestingType() { result = ""}
  int interestingArg() { result = 0 }

  abstract Element getInterestingArg();

  IfStmt getCondition() {
      if (this instanceof Capabilities or this instanceof NSCapabilities) then
        CapabilityFlow::flow(DataFlow::exprNode(this), DataFlow::exprNode(result.getCondition().getAChild()))
      else if (this instanceof ModuleParam or this instanceof SysCtl)
      then
        result.getCondition().getAChild() = this.getInterestingArg().(Variable).getAnAccess()
      else none()
  }
}

class NSCapabilities extends InterestingConditionCalls, Call {
  override string getInterestingType() {result = "ns_capable"}
  NSCapabilities() { this.getTarget().hasName("ns_capable") }

  override int interestingArg() { result = 1 }

  override Element getInterestingArg() { result = this.(Call).getArgument(this.interestingArg()) }

}

class Capabilities extends InterestingConditionCalls, Call {
  override string getInterestingType() {result = "capable"}
  Capabilities() { this.getTarget().hasName("capable") }

  override int interestingArg() { result = 0 }

  override Element getInterestingArg() { result = this.(Call).getArgument(this.interestingArg()) }
}

class ModuleParam extends InterestingConditionCalls, MacroInvocation {
  override string getInterestingType() {result = "module_param"}
  ModuleParam() { this.getMacroName() = "module_param" }

  override Element getInterestingArg() {
    result = this.getAnAffectedElement().(VariableAccess).getTarget() and
    not result.(Variable).getName().regexpMatch("param_ops.*|__param_str.*")
  }

}

class SysCtl extends InterestingConditionCalls, ClassAggregateLiteral {
  override string getInterestingType() {result = "sysctl"}
  SysCtl() { this.getType().getName() = "ctl_table" }

  override Element getInterestingArg() {
    exists(Field f |
      f.getName() = "data" and
      result = this.getAFieldExpr(f).(AddressOfExpr).getAddressable()
    )
  }
}

from InterestingConditionCalls ic, ControlFlowNode call, IfStmt condition
where
  condition = ic.getCondition()
   and
  dominates(condition, call) and
  call instanceof Call and
  call != ic
select ic.getInterestingType(), ic.getLocation(), condition.getLocation(), ic.getInterestingArg(), call, call.getLocation()