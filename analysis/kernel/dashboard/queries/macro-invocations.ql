import cpp

from MacroInvocation mi, string file, int startLine, int endLine
where
  exists(mi.getLocation().getFile().getRelativePath()) and
  file = mi.getLocation().getFile().toString() and
  startLine = mi.getLocation().getStartLine() and
  endLine = mi.getLocation().getEndLine()
select mi.getMacroName(), file, startLine, endLine
