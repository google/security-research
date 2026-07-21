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

  Struct getStruct() {
    exists(Expr sof |
      this.getSizeArg().getAChild*() = sof and
      this.sizeofParam(sof) = result
    )
    or
    not exists(Expr sof |
      this.getSizeArg().getAChild*() = sof and exists(this.sizeofParam(sof))
    ) and
    result = this.getFullyConverted().getType().stripType()
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
select kfc.getLocation(), kfc, s, s.getLocation(), s.getSize(), kfc.getFlag(), kfc.getSize(),
  kfc.getSizeArg(), kfc.isFlexible(), kfc.getTarget().getName()
