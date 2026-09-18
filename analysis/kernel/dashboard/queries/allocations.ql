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

class KmallocCall extends FunctionCall {
  int sizeArgIndex;
  int flagsArgIndex;

  KmallocCall() {
    not this.getEnclosingStmt().(DeclStmt).getADeclaration().hasName("_res") and
    not exists(IfStmt ifs |
      ifs.getElse() = this.getEnclosingStmt() and
      ifs.getThen() instanceof BlockStmt
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

  StmtExpr innerAllocHooks() {
    result.getStmt() = this.getEnclosingStmt().getParentStmt().getParentStmt().getParentStmt()
  }

  StmtExpr outerAllocHooks() {
    result.getStmt() = this.innerAllocHooks().getEnclosingStmt().getParentStmt()
  }

  Expr getOuterExpr() {
    if exists(this.outerAllocHooks()) then result = this.outerAllocHooks()
    else if exists(this.innerAllocHooks()) then result = this.innerAllocHooks()
    else result = this
  }

  string getCleanTargetName() {
    result = this.getTarget().getName().regexpReplaceAll("_noprof$", "")
  }

  string getCleanCallExpr() {
    result = "call to " + this.getCleanTargetName()
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
    result = e.(SizeofExprOperator).getExprOperand().getFullyConverted().getType()
    or
    result = e.(SizeofTypeOperator).getTypeOperand()
  }

  Struct validSizeofStruct(Expr sof) {
    this.getSizeArg().getAChild*() = sof and
    result = this.sizeofParam(sof) and
    result.getSize() > 0 and
    not result.getName().matches("%unnamed%")
  }

  Struct getStruct() {
    (
      result = this.validSizeofStruct(_)
      or
      not exists(this.validSizeofStruct(_)) and
      (
        result = this.getOuterExpr().getFullyConverted().getType().stripType()
        or
        result = this.getOuterExpr().getParent().(AssignExpr).getLValue().getType().stripType()
        or
        result = this.getOuterExpr().getParent().(Initializer).getDeclaration().(Variable).getType().stripType()
      )
    ) and
    result.getSize() > 0 and
    not result.getName().matches("%unnamed%")
  }

  predicate sizeViaSafeSizeMacro() {
    exists(MacroInvocation mi |
      mi.getMacro().getName() = ["struct_size", "array_size", "flex_array_size", "struct_size_t"] and
      mi.getExpr() = this.getSizeArg().getAChild*()
    )
  }

  string isFlexible() {
    (this.getSize() = "unknown" or this.sizeViaSafeSizeMacro()) and
    this.getStruct().getAField() instanceof FlexibleArrayMember and
    result = "true"
    or
    not (this.getSize() = "unknown" or this.sizeViaSafeSizeMacro()) and
    not this.getStruct().getAField() instanceof FlexibleArrayMember and
    result = "false"
  }
}

from KmallocCall kfc, Struct s
where s = kfc.getStruct()
select kfc.getLocation(), kfc.getCleanCallExpr(), s, s.getLocation(), s.getSize(), kfc.getFlag(),
  kfc.getSize(), kfc.getSizeArg(), kfc.isFlexible(), kfc.getCleanTargetName()

