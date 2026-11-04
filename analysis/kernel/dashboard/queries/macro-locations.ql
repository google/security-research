import cpp

from Macro m, string file, int startLine, int endLine
where
  file = m.getLocation().getFile().getRelativePath() and
  startLine = m.getLocation().getStartLine() and
  endLine = m.getLocation().getEndLine()
select m.getName(), file, startLine, endLine
