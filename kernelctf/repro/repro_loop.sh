#!/bin/bash
set -e

ITERATIONS=${1:-1000}
SUCCESS=0
FAIL=0

echo "Starting KASLR leak verification loop with $ITERATIONS iterations..."

for i in $(seq 1 $ITERATIONS); do
    echo "[LOOP] Iteration $i / $ITERATIONS"
    
    # Run repro.sh with specific iteration ID
    # We rely on repro.sh adding "kaslr_leak=1" (via metadata.json settings)
    # which causes init.sh to pass the KASLR base to the exploit.
    
    if ./repro.sh $i > /dev/null 2>&1; then
        # We need to check if it ACTUALLY succeeded (flag found).
        # repro.sh checks output for flag and exits 0 if found.
        echo " -> Success"
        SUCCESS=$((SUCCESS+1))
    else
        echo " -> Failure"
        FAIL=$((FAIL+1))
        # Keep logs for failure
        cat qemu.txt
        cp qemu.txt "failure_${i}.log"
    fi
done

echo "============================================"
echo "Results:"
echo "Success: $SUCCESS"
echo "Fail:    $FAIL"
echo "============================================"

if [ $FAIL -gt 0 ]; then
    exit 1
fi
exit 0
