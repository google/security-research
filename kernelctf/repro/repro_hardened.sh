#!/bin/bash
set -e

TRY_ID="$1"
FLAG="kernelCTF{$(uuidgen)}"
echo "$FLAG" > "flag_$TRY_ID"
STOP_MARKER=$(uuidgen)
echo "::stop-commands::$STOP_MARKER"
START_TIME=$(date +%s)

mkdir -p "$RELEASE_ID"
ln -sf ../bzImage "$RELEASE_ID/bzImage"

IBT_ARG=""
if ! grep -q -w 'ibt' /proc/cpuinfo; then
    IBT_ARG="--ignore-ibt"
fi

ROOT_ARG=""
if [ "$AS_ROOT" == "1" ]; then
    ROOT_ARG="--as-root"
fi

SCRIPT_DIR="$(dirname "$(realpath "$0")")"
echo "::EXPLOIT OUTPUT FROM HERE::" > "repro_log_$TRY_ID.txt"
set +e
bash "$SCRIPT_DIR/../server/server/qemu.sh" "$RELEASE_ID" "flag_$TRY_ID" "/cmd_wrapper.sh /exploit" "./exp/exploit" "dmesg_$TRY_ID.txt" $IBT_ARG $ROOT_ARG --timeout=315 | tee -a "repro_log_$TRY_ID.txt"
QEMU_EXIT=${PIPESTATUS[0]}
set -e

if [ -f "dmesg_$TRY_ID.txt" ]; then
    echo -e "\n--- DMESG LOG ---" >> "repro_log_$TRY_ID.txt"
    cat "dmesg_$TRY_ID.txt" >> "repro_log_$TRY_ID.txt"
fi

echo "::$STOP_MARKER::"
RUN_TIME=$(expr $(date +%s) - $START_TIME)
if [ -n "$GITHUB_OUTPUT" ]; then
    echo "RUN_TIME=$RUN_TIME" >> "$GITHUB_OUTPUT"
fi
echo "[REPRO $TRY_ID] Run time: ${RUN_TIME}s"

if grep -q "$FLAG" "repro_log_$TRY_ID.txt"; then
    echo "[REPRO $TRY_ID] Got the flag! Congrats!"
    exit 0
else
    echo "[REPRO $TRY_ID] Failed, did not get the flag."
    exit 1
fi
