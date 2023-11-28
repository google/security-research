# Minimized Reptar Examples

This directory provides a set of examples to reproduce and study the Reptar vulnerability.

You can build them all simply by running `make`.

- **reptar.align.asm**: This is a more reliable reproducer that triggers an error on the first iteration. The `clflush` and the reptar instruction need to be on different 16 byte windows. This could be related to the instruction decoder working on 16 byte instructions at a time.
- **reptar.loop.asm**: This is a more documented reproducer that explains what happens when the bug triggers and which instructions execute and which don't. Running the program on GDB should allow for quick debugging.
- **reptar.loopless.asm**: This is an easier to modify reproducer that will also trigger the bug somewhat reliably but also allows to modify the instructions executed before and after. Note the registers that the program uses at the top.
- **reptar.xlat.asm**: This is similar to `reptar.align.asm` but generates tracing information on the syscalls it executes, so that when the program enters at a different register location, it is possible to observe the consequences. Pause will freeze the process, exit will pass AL as the exit code and yield will simply leave the latest RIP on RCX.
- **reptar.vdsojmp.elf.asm**: This is an experiment where we map ourselves just before the VDSO (you must disable ASLR first and adjust the addresses) and then make the "wrong RIP" point to the VDSO address of the time() function, then we jump to that instruction. As a result, the current time is stored in the address pointed to by RAX. If we had corrupted the uop$ then we would instead expect a crash, so it appears that a long jump to the VDSO doesn't corrupt the uop$.
- **reptar.vdsjpf.elf.asm**: This is a similar experiment to the one above where we do the same except with a pagefault instead of a long jump, with similar consequences.
- **reptar.mce.asm**: Trigger this with `./log_mce.sh` and adjust the cpu 15/7 so they are siblings. This code will trigger an MCE on some affected CPUs and log the details.
