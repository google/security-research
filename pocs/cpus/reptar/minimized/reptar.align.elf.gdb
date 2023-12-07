file reptar.align.elf

starti

break '_start.exit' if $rbx == 1
commands
    pipe printf "FAIL(rbx=%x,oneiter)\n", $rbx | cat
    quit 1
end

break '_start.exit' if $rbx > 1
commands
    pipe printf "PASS(rbx=%x,nopsled)\n", $rbx | cat
    quit 0
end

catch signal SIGSEGV
commands
    pipe printf "PASS(rbx=%x,segfault)\n", $rbx | cat
    quit 0
end

continue

pipe printf "FAIL(rbx=%x,unexpected)\n", $rbx | cat
quit 1
