import cpp
import kernel_common

// Used for the dashboard to see which syzkaller repro's trigger this function
from Function fun, File f, string file, int startLine, int endLine
where
  not fun.getName().matches("%assert%") and
  functionSignatureSpan(fun, f, startLine, endLine) and
  fun.getLocation().getFile() = f and
  file = f.toString()
select fun.getName(), file, startLine, endLine
