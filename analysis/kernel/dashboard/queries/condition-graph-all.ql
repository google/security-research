import cpp
import semmle.code.cpp.controlflow.Guards
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.ir.dataflow.ResolveCall
import semmle.code.cpp.pointsto.CallGraph

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

predicate badname(Function f) {
   f.getName().regexpMatch("__builtin_.*|__compile.*") or f.getBlock().isEmpty() 
}

query predicate edges(ControlFlowNode a, ControlFlowNode b) {
    //if a instanceof ExprCall then
    //   exprCallEdge(a, b)
    //else 
    if a instanceof Call then 
        b = resolveCall(a) and not badname(b)
    else if a instanceof Function
    then   
       a = b.(Call).getEnclosingFunction() and not badname(a)
   else
   none()
}


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

class ConditionDependentCall extends Call {
    ConditionDependentCall() {
        exists(InterestingConditionCalls ic, IfStmt condition | condition = ic.getCondition() and dominates(condition, this) and ic != this and condition.getAChild() != this)
    }
}

from ConditionDependentCall cdc, Function last
where
    edges+(cdc, last) and
    last.hasName(["core_siblings_list_read", "bfq_init_rq", "cpumap_read", "cpumap_listread", "ovl_encode_real_fh", "show_mark_fhandle", "dm_array_cursor_end"])
select cdc, last, cdc.getLocation(), last.getLocation()