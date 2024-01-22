import cpp

// Used for the dashboard to see which syzkaller repro's trigger this function
from Function fun
where not fun.getName().matches("%assert%")
select fun.getName(), fun.getLocation().getFile(), fun.getLocation().getStartLine(),
  fun.getBlock().getLocation().getEndLine()
