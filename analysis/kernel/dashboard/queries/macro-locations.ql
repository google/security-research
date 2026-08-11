import cpp

from Macro m, string file, int startLine, int endLine
where
  exists(m.getLocation().getFile().getRelativePath()) and
  file = m.getLocation().getFile().toString() and
  startLine = m.getLocation().getStartLine() and
  endLine = m.getLocation().getEndLine()
select m.getName(), file, startLine, endLine
