import cpp
import struct_utils

abstract class InterestingFieldAccesses extends FieldAccess {
  InterestingFieldAccesses() { any() }

  string accessType() { result = "" }
}

class FieldExec extends InterestingFieldAccesses {
  FieldExec() { exists(ExprCall ec | ec.getExpr() = this) }

  override string accessType() { result = "exec" }
}

class FieldWrite extends InterestingFieldAccesses {
  FieldWrite() { this.isModified() }

  override string accessType() { result = "write" }
}

class FieldRead extends InterestingFieldAccesses {
  FieldRead() { this.isRValue() }

  override string accessType() { result = "read" }
}

string enclosingFunctionName(InterestingFieldAccesses ifa) {
  if exists(ifa.getEnclosingFunction())
  then result = ifa.getEnclosingFunction().getName()
  else result = ""
}

from InterestingFieldAccesses ifa, Location loc
where
  loc = ifa.getLocation() and
  not nonRuntimeKernelFile(loc.getFile())
select
  ifa.accessType() as type,
  ifa.getTarget().getName() as field,
  canonicalFieldAccessParent(ifa) as parent,
  loc.toString() as location,
  enclosingFunctionName(ifa) as function_name,
  loc.getFile().getRelativePath() as file_path,
  loc.getStartLine() as line