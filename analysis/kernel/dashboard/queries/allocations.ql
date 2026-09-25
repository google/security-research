/**
 * @name Find interesting objects for kernel heap exploitation
 * @id cpp/kernel-interesting-objects
 * @description Finds interesting objects for kernel heap exploitation
 * @kind problem
 * @precision low
 * @tags security kernel
 * @problem.severity error
 */

import cpp

class FlexibleArrayMember extends Field {
  FlexibleArrayMember() {
    exists(Struct s |
      this = s.getCanonicalMember(max(int j | s.getCanonicalMember(j) instanceof Field | j))
    ) and
    this.getUnspecifiedType() instanceof ArrayType and
    (
      this.getUnspecifiedType().(ArrayType).getArraySize() <= 1 or
      not this.getUnspecifiedType().(ArrayType).hasArraySize()
    )
  }
}

class AllocSizeAttribute extends GnuAttribute {
  AllocSizeAttribute() { this.getName() = "alloc_size" }

  int getSizeParamOneBased() { result = this.getArgument(0).getValueInt() }

  predicate isSingleParamForm() { not exists(this.getArgument(1)) }
}

Stmt enclosingStmtStep(Stmt s) {
  result = s.getParentStmt()
  or
  exists(StmtExpr se | se.getStmt() = s and result = se.getEnclosingStmt())
}

class KmallocCall extends FunctionCall {
  int sizeArgIndex;
  int flagsArgIndex;

  KmallocCall() {
    exists(this.getEnclosingStmt()) and
    not exists(DeclStmt ds, Variable v |
      v = ds.getADeclaration() and
      v.hasName("_res") and
      ds = enclosingStmtStep*(this.getEnclosingStmt()) and
      not this = v.getInitializer().getExpr().getAChild*()
    ) and
    not exists(IfStmt ifs |
      ifs.getCondition().(FunctionCall).getTarget().hasName("mem_alloc_profiling_enabled") and
      ifs.getThen() = enclosingStmtStep*(this.getEnclosingStmt())
    ) and
    exists(AllocSizeAttribute attr |
      attr = this.getTarget().getAnAttribute() and
      attr.isSingleParamForm() and
      sizeArgIndex = attr.getSizeParamOneBased() - 1
    ) and
    exists(Parameter p |
      p = this.getTarget().getParameter(flagsArgIndex) and
      p.getType().hasName("gfp_t")
    )
  }

  Expr getSizeArg() { result = this.getArgument(sizeArgIndex) }

  Expr getFlagsArg() { result = this.getArgument(flagsArgIndex) }

  Expr sizeSubExpr() {
    result = this.getSizeArg().getAChild*()
    or
    result = this.getSizeArg().(VariableAccess).getTarget().getInitializer().getExpr().getAChild*()
  }

  string getFlag() {
    result =
      concat(Expr flag |
        flag = this.getFlagsArg().getAChild*() and flag.getValueText().matches("%GFP%")
      |
        flag.getValueText(), "|"
      )
  }

  string getSize() {
    if this.getSizeArg().isConstant()
    then result = this.getSizeArg().getValue()
    else result = "unknown"
  }

  Type sizeofParam(Expr e) {
    (
      result = e.(SizeofExprOperator).getExprOperand().getFullyConverted().getType()
      or
      result = e.(SizeofTypeOperator).getTypeOperand()
    ) and
    result.getSize() > 0
  }

  StmtExpr innerAllocHooks() {
    result.getStmt() = this.getEnclosingStmt().getParentStmt() or
    result.getStmt() = this.getEnclosingStmt().getParentStmt().getParentStmt() or
    result.getStmt() = this.getEnclosingStmt().getParentStmt().getParentStmt().getParentStmt()
  }

  StmtExpr outerAllocHooks() {
    result.getStmt() = this.innerAllocHooks().getEnclosingStmt().getParentStmt()
  }

  StmtExpr allocObjsWrapper() {
    result.getStmt() = this.outerAllocHooks().getEnclosingStmt().getParentStmt() or
    result.getStmt() = this.outerAllocHooks().getEnclosingStmt().getParentStmt().getParentStmt()
  }

  Expr getWrapperExpr() {
    result = this or
    result = this.innerAllocHooks() or
    result = this.outerAllocHooks() or
    result = this.allocObjsWrapper()
  }

  Struct getStruct() {
    (
      exists(Expr sof |
        this.sizeSubExpr() = sof and
        this.sizeofParam(sof) = result
      )
      or
      not exists(Expr sof |
        this.sizeSubExpr() = sof and exists(this.sizeofParam(sof))
      ) and
      result = this.getWrapperExpr().getFullyConverted().getType().stripType()
    ) and
    result.getSize() > 0 and
    not result.getName().matches("%unnamed%") and
    (this.getSize() = "unknown" or result.getSize() <= this.getSize().toInt())
  }

  predicate sizeViaSafeSizeMacro() {
    exists(MacroInvocation mi |
      mi.getMacro().getName() = ["struct_size", "array_size", "flex_array_size", "struct_size_t"] and
      mi.getExpr() = this.sizeSubExpr()
    )
  }

  string isFlexible(Struct s) {
    s = this.getStruct() and
    (
      (this.getSize() = "unknown" or this.sizeViaSafeSizeMacro()) and
      s.getAField() instanceof FlexibleArrayMember and
      result = "true"
      or
      not (this.getSize() = "unknown" or this.sizeViaSafeSizeMacro()) and
      not s.getAField() instanceof FlexibleArrayMember and
      result = "false"
    )
  }
}

from KmallocCall kfc, Struct s
where s = kfc.getStruct()
select kfc.getLocation(), kfc, s, s.getLocation(), s.getSize(), kfc.getFlag(), kfc.getSize(),
  kfc.getSizeArg(), kfc.isFlexible(s), kfc.getTarget().getName()
