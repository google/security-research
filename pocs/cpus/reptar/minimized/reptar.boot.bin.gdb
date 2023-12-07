target remote | exec qemu-system-x86_64 --enable-kvm -gdb stdio -S -fda reptar.boot.bin

hbreak *0x7E00 if $r15 > 0 && $rbx!=$rdx
commands
    pipe printf "PASS(r15=%d,rbx=%d,rdx=%d)\n", $r15, $rbx, $rdx | cat
    kill
    quit 0
end

hbreak *0x7E00 if $r15 > 0 && $rbx==$rdx
commands
    pipe printf "FAIL(r15=%d,rbx=%d,rdx=%d)\n", $r15, $rbx, $rdx | cat
    kill
    quit 1
end

continue
