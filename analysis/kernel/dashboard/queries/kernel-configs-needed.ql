import cpp

class FunctionConfig extends Function {
  FunctionConfig() { not this.getName().matches("__compiletime_assert_%") }

  PreprocessorBranch getAGuard() {
    exists(PreprocessorEndif e, int line |
      result.getEndIf() = e and
      e.getFile() = this.getFile() and
      result.getFile() = this.getFile() and
      line = this.getLocation().getStartLine() and
      result.getLocation().getStartLine() < line and
      line < e.getLocation().getEndLine()
    )
  }
}

from FunctionConfig enc, string guard
where
  guard = enc.getAGuard().getHead() and
  guard.matches("CONFIG%")
select enc, guard
