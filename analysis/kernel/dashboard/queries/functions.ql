import cpp

// Used for the dashboard to see which syzkaller repro's trigger this function
from Function fun, string file, BlockStmt block, int startLine, int endLine
where
  not fun.getName().matches("%assert%") and
  fun.getLocation().getFile().toString() = file and
  fun.getBlock() = block and
  block.getLocation().getFile().toString() = file and
  block.getLocation().getStartLine() = startLine and
  block.getLocation().getEndLine() = endLine
select fun.getName(), file, startLine, endLine
