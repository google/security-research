import cpp

from Function syscall
where syscall.getName().matches("__do_sys_%")
select syscall, syscall.getParameterString()
