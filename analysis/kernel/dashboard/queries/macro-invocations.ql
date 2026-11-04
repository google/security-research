import cpp

from MacroInvocation mi, string file, int startLine, int endLine
where
  file = mi.getLocation().getFile().getRelativePath() and
  startLine = mi.getLocation().getStartLine() and
  endLine = mi.getLocation().getEndLine()
select mi.getMacroName(), file, startLine, endLine
