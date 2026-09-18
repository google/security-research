#!/bin/bash
set -e

TRY_ID="$1"
STDOUT_TIMEOUT=1800  # 30 minutes (matches Linux)
CUTTLEFISH_TXT=cuttlefish_$TRY_ID.txt

FLAG="kernelCTF{$(uuidgen)}"
echo $FLAG > flag_$TRY_ID

STOP_MARKER=$(uuidgen)
echo "::stop-commands::$STOP_MARKER"

touch $CUTTLEFISH_TXT
START_TIME=$(date +%s)

# Cleanup function for Android
cleanup_cuttlefish() {
    local phase="$1"
    local release_path="$2"

    echo "[REPRO $TRY_ID] ${phase^}-cleanup: Starting cleanup..."

    # Kill processes - include stop_cvd only in pre-cleanup
    local processes="launch_cvd run_cvd crosvm"
    if [ "$phase" = "pre" ]; then
        processes="launch_cvd run_cvd stop_cvd crosvm"
    fi

    for process in $processes; do
        pids=$(pgrep -f "$process" 2>/dev/null || true)
        if [ -n "$pids" ]; then
            echo "[REPRO $TRY_ID] Killing leftover $process processes..."
            echo "$pids" | xargs -r kill -9 2>/dev/null || true
        fi
    done

    # Try graceful stop first (only in pre-cleanup)
    if [ "$phase" = "pre" ] && [ -f "$release_path/bin/stop_cvd" ]; then
        HOME="$release_path" "$release_path/bin/stop_cvd" --clear_instance_dirs 2>/dev/null || true
        sleep 1
    fi

    # Remove all instance data
    rm -rf "$release_path"/cuttlefish/instances/* 2>/dev/null || true
    rm -rf "$release_path"/cuttlefish_runtime* 2>/dev/null || true

    # Remove all converted images (safe in CI since we're not running parallel)
    rm -f "$release_path"/*.img.raw 2>/dev/null || true

    # Remove overlay/composite images
    find "$release_path/cuttlefish" -name "*overlay*.img" -delete 2>/dev/null || true
    find "$release_path/cuttlefish" -name "*composite*.img" -delete 2>/dev/null || true

    # Remove all locks
    rm -rf "$release_path/../locks/lock-inst-"* 2>/dev/null || true

    # Clean up temp files
    for pattern in "cf_avd_*" "cf_env_*" "cvd-*" "launch_cvd_*"; do
        rm -rf /tmp/$pattern 2>/dev/null || true
    done

    # Clean up shared memory
    rm -rf /dev/shm/cvd_* /dev/shm/cuttlefish_* /dev/shm/cf_avd_* 2>/dev/null || true

    # Clean up stale named pipes (only in pre-cleanup)
    if [ "$phase" = "pre" ]; then
        find /tmp -maxdepth 1 -type p -name "tmp.*" -mmin +5 -delete 2>/dev/null || true
    fi

    # Force sync
    sync

    echo "[REPRO $TRY_ID] ${phase^}-cleanup done"
}

echo "[REPRO $TRY_ID] Starting Cuttlefish with exploit..."
echo "[REPRO $TRY_ID] Release path: $ANDROID_RELEASE_PATH"
echo "[REPRO $TRY_ID] Exploit path: $(realpath ./exp/exploit)"
echo "[REPRO $TRY_ID] APK path: $APK_PATH"
echo "[REPRO $TRY_ID] Flag file: flag_$TRY_ID"

# Determine the path to cuttlefish.sh
CUTTLEFISH_SCRIPT="./cuttlefish.sh"
if [ ! -f "$CUTTLEFISH_SCRIPT" ]; then
    CUTTLEFISH_SCRIPT="../../kernelctf/server/cuttlefish.sh"
fi

if [ ! -f "$CUTTLEFISH_SCRIPT" ]; then
    echo "[ERROR] Could not find cuttlefish.sh"
    exit 1
fi

echo "[REPRO $TRY_ID] Using cuttlefish script: $CUTTLEFISH_SCRIPT"

# Pre-cleanup
cleanup_cuttlefish "pre" "$ANDROID_RELEASE_PATH"

# Use sudo --user to activate group memberships (kvm, cvdnetwork, render)
sudo --user "$USER" --preserve-env --preserve-env=PATH -- env -- \
    timeout ${STDOUT_TIMEOUT}s bash "$CUTTLEFISH_SCRIPT" \
        --release_path="$ANDROID_RELEASE_PATH" \
        --bin_path="$(realpath ./exp/exploit)" \
        --flag_path=flag_$TRY_ID \
        --apk_path="$APK_PATH" \
        > "$CUTTLEFISH_TXT" 2>&1 &

CUTTLEFISH_PID="$!"

echo "[REPRO $TRY_ID] Cuttlefish PID: $CUTTLEFISH_PID"

# Tail the log file in real-time
tail -f "$CUTTLEFISH_TXT" &
TAIL_PID=$!

# Wait for Cuttlefish to complete or timeout
wait $CUTTLEFISH_PID
CUTTLEFISH_EXIT=$?

# Stop tailing
kill $TAIL_PID 2>/dev/null || true

echo "[REPRO $TRY_ID] Cuttlefish exited with code: $CUTTLEFISH_EXIT"

echo "::$STOP_MARKER::"

# Post-cleanup
cleanup_cuttlefish "post" "$ANDROID_RELEASE_PATH"

# Copy log to repro_log file
cp $CUTTLEFISH_TXT repro_log_$TRY_ID.txt

# Calculate run time
RUN_TIME=$(expr $(date +%s) - $START_TIME)
if [ -n "$GITHUB_OUTPUT" ]; then
    echo "RUN_TIME=$RUN_TIME" >> "$GITHUB_OUTPUT"
fi
echo "[REPRO $TRY_ID] Run time: ${RUN_TIME}s"

# Check if we got the flag
if grep -q "$FLAG" $CUTTLEFISH_TXT; then
    echo "[REPRO $TRY_ID] Got the flag! Congrats!"
    exit 0
else
    echo "[REPRO $TRY_ID] Failed, did not get the flag."

    # Provide some debugging info
    if [ $CUTTLEFISH_EXIT -eq 124 ]; then
        echo "[REPRO $TRY_ID] Timeout: Cuttlefish did not complete within ${STDOUT_TIMEOUT}s"
    elif [ $CUTTLEFISH_EXIT -ne 0 ]; then
        echo "[REPRO $TRY_ID] Cuttlefish failed with exit code: $CUTTLEFISH_EXIT"
    fi

    exit 1
fi
