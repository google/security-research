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

class KmallocCall extends FunctionCall {
  KmallocCall() { this.getTarget().hasName(["kmalloc", "kzalloc", "kvmalloc"]) }

  Expr getSizeArg() { result = this.getArgument(0) }

  string getFlag() {
    result =
      concat(Expr flag |
        flag = this.getArgument(1).getAChild*() and flag.getValueText().matches("%GFP%")
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
    ) or
   result = this.getFullyConverted().getType().stripType() 
  }

  string isFlexible() {
    this.getSize() = "unknown" and
    this.getStruct().getAField() instanceof FlexibleArrayMember and
    result = "true"
    or
    not this.getSize() = "unknown" and
    not this.getStruct().getAField() instanceof FlexibleArrayMember and
    result = "false"
  }
}

from KmallocCall kfc, Struct s
where
  s = kfc.getStruct() and
  not kfc.getSizeArg().isAffectedByMacro()
select kfc.getLocation(), kfc, s, s.getLocation(), s.getSize(), kfc.getFlag(), kfc.getSize(),
  kfc.getArgument(0), kfc.isFlexible()
