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
