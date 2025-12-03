#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RELEASE_PATH=""
TEST_MODE=0
CLEANUP_RUNNING=false

cleanup_function() {
    # Prevent recursive calls
    if [ "$CLEANUP_RUNNING" = true ]; then
        return 0
    fi
    CLEANUP_RUNNING=true
    
    # Disable exit-on-error for cleanup
    set +e
    
    echo "[CLEANUP] Shutting down instance $instance_num" 1>&2
    
    # Kill logcat monitoring if running
    if [ -n "$LOGCAT_PID" ] && kill -0 "$LOGCAT_PID" 2>/dev/null; then
        kill "$LOGCAT_PID" 2>/dev/null || true
        sleep 0.2
        kill -9 "$LOGCAT_PID" 2>/dev/null || true
    fi
    
    # Remove logcat temp file
    if [ -n "$LOGCAT_FILE" ] && [ -f "$LOGCAT_FILE" ]; then
        rm -f "$LOGCAT_FILE" 2>/dev/null || true
    fi
    
    # Stop cuttlefish (protect against failures)
    if [ -n "$RELEASE_PATH" ] && [ -d "$RELEASE_PATH" ]; then
        CUTTLEFISH_RUNTIME_LINK=$RELEASE_PATH/cuttlefish_runtime
        CUTTLEFISH_CURRENT_INSTANCE=$RELEASE_PATH/cuttlefish/instances/cvd-$instance_num
        
        if [ -d "$CUTTLEFISH_CURRENT_INSTANCE" ]; then
            # Try graceful stop
            (
                ln -sf $CUTTLEFISH_CURRENT_INSTANCE $CUTTLEFISH_RUNTIME_LINK 2>/dev/null
                HOME=$RELEASE_PATH timeout 10s $RELEASE_PATH/bin/stop_cvd 2>/dev/null
            ) || true
            
            # Give it time
            sleep 1
            
            # Force kill any remaining processes for this instance
            pgrep -f "cvd-$instance_num" | xargs -r kill -9 2>/dev/null || true
        fi
        
        # Clean up instance-specific data (multiple attempts)
        for i in {1..3}; do
            rm -rf "$RELEASE_PATH/cuttlefish_runtime.$instance_num" 2>/dev/null && break
            sleep 0.5
        done
        
        for i in {1..3}; do
            rm -rf "$CUTTLEFISH_CURRENT_INSTANCE" 2>/dev/null && break
            sleep 0.5
        done
        
        # Clean overlays for this instance only
        find "$RELEASE_PATH/cuttlefish/instances/cvd-$instance_num" -name "*overlay*.img" -delete 2>/dev/null || true
        find "$RELEASE_PATH/cuttlefish/instances/cvd-$instance_num" -name "*composite*.img" -delete 2>/dev/null || true
        
        # Clean up converted raw images if last instance
        local active_instances=$(find "$RELEASE_PATH/../locks" -name "lock-inst-*" -type d ! -name "lock-inst-$instance_num" 2>/dev/null | wc -l)
        if [ "$active_instances" -eq 0 ]; then
            echo "[CLEANUP] Last instance, cleaning up shared .raw images" 1>&2
            rm -f "$RELEASE_PATH"/*.img.raw 2>/dev/null || true
        fi
        
        # Clean up temp files
        rm -rf /tmp/cf_avd_${instance_num}* 2>/dev/null || true
        rm -rf /tmp/cf_env_${instance_num}* 2>/dev/null || true
        rm -rf /tmp/cvd-${instance_num}* 2>/dev/null || true
        rm -rf /tmp/launch_cvd_${instance_num}* 2>/dev/null || true
    fi
    
    # Release instance lock (critical - try multiple times)
    if [ -n "$folder" ] && [ -d "$folder" ]; then
        for i in {1..5}; do
            rm -rf "$folder" 2>/dev/null && break
            sleep 0.2
        done
    fi
    
    if [ -n "$instance_num" ]; then
        for i in {1..5}; do
            rm -rf "$RELEASE_PATH/../locks/lock-inst-$instance_num" 2>/dev/null && break
            sleep 0.2
        done
    fi
    
    # Force sync (ignore errors)
    sync 2>/dev/null || true
    
    echo "[CLEANUP] Cleanup done" 1>&2
    
    # Don't call exit here to avoid recursion
    return 0
}

cleanup_wrapper() {
    cleanup_function 1>&2
}

# Trap multiple signals to ensure cleanup always runs
trap 'cleanup_wrapper' EXIT
trap 'cleanup_wrapper; exit 130' INT   # Ctrl+C
trap 'cleanup_wrapper; exit 143' TERM  # kill

usage() {
    echo "Usage: $0 --release_path=<release_path> --flag_path=<flag_fn> [--bin_path=<bin_path>] [--apk_path=<apk_path>] [--test-mode]"
    exit 1;
}

# Function to check required groups
check_groups() {
    local current_groups=$(groups)
    local missing_groups=()
    
    # Check for required groups
    for group in kvm cvdnetwork render; do
        if ! echo "$current_groups" | grep -qw "$group"; then
            missing_groups+=("$group")
        fi
    done
    
    if [ ${#missing_groups[@]} -gt 0 ]; then
        echo "=========================================="
        echo "ERROR: Missing required group memberships"
        echo "=========================================="
        echo ""
        echo "Current groups: $current_groups"
        echo "Missing groups: ${missing_groups[*]}"
        echo ""
        echo "To fix this issue:"
        echo "  1. Run: sudo usermod -aG kvm,cvdnetwork,render \$USER"
        echo "  2. Logout and login again (or reboot)"
        echo ""
        echo "Alternatively, if you just ran install_dependencies.sh,"
        echo "run this script with: sudo su - \$USER -c \"cd \$PWD && ./cuttlefish.sh ...\""
        echo ""
        return 1
    fi
    
    return 0
}

# Function to check kernel modules
check_kernel_modules() {
    local missing_modules=()
    local optional_modules=()
    
    # Check for required modules
    if ! lsmod | grep -q "^kvm"; then
        missing_modules+=("kvm")
    fi
    
    # Check for optional but recommended modules
    if ! lsmod | grep -q "^vhost_net"; then
        optional_modules+=("vhost_net")
    fi
    
    if ! lsmod | grep -q "^vhost_vsock"; then
        optional_modules+=("vhost_vsock")
    fi
    
    if [ ${#missing_modules[@]} -gt 0 ]; then
        echo "=========================================="
        echo "ERROR: Missing required kernel modules"
        echo "=========================================="
        echo ""
        echo "Missing modules: ${missing_modules[*]}"
        echo ""
        echo "To fix this issue:"
        echo "  sudo modprobe kvm"
        echo "  sudo modprobe kvm_intel  # or kvm_amd for AMD CPUs"
        echo ""
        return 1
    fi
    
    if [ ${#optional_modules[@]} -gt 0 ]; then
        echo "[WARNING] Optional modules not loaded: ${optional_modules[*]}"
        echo "  Cuttlefish may work but with reduced performance."
        echo "  To load them: sudo modprobe vhost_net vhost_vsock"
        echo ""
    fi
    
    return 0
}

# Function to check device permissions
check_device_permissions() {
    local permission_errors=()
    
    # Check /dev/kvm
    if [ ! -e /dev/kvm ]; then
        permission_errors+=("/dev/kvm does not exist")
    elif [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
        permission_errors+=("/dev/kvm is not readable/writable")
    fi
    
    # Check /dev/net/tun
    if [ ! -e /dev/net/tun ]; then
        permission_errors+=("/dev/net/tun does not exist")
    elif [ ! -r /dev/net/tun ] || [ ! -w /dev/net/tun ]; then
        permission_errors+=("/dev/net/tun is not readable/writable")
    fi
    
    if [ ${#permission_errors[@]} -gt 0 ]; then
        echo "=========================================="
        echo "ERROR: Device permission issues"
        echo "=========================================="
        echo ""
        for error in "${permission_errors[@]}"; do
            echo "  - $error"
        done
        echo ""
        echo "Current permissions:"
        [ -e /dev/kvm ] && ls -la /dev/kvm || echo "  /dev/kvm: Not found"
        [ -e /dev/net/tun ] && ls -la /dev/net/tun || echo "  /dev/net/tun: Not found"
        echo ""
        echo "These issues are usually resolved by:"
        echo "  1. Being in the kvm and cvdnetwork groups"
        echo "  2. Logging out and back in"
        echo "  3. Running: sudo udevadm control --reload-rules && sudo udevadm trigger"
        echo ""
        return 1
    fi
    
    return 0
}

# Function to run all pre-flight checks
run_preflight_checks() {
    local checks_failed=0
    
    # Run all checks silently, only show errors
    check_groups || checks_failed=1
    check_kernel_modules || checks_failed=1
    check_device_permissions || checks_failed=1
    
    if [ $checks_failed -ne 0 ]; then
        echo "=========================================="
        echo "[FAILED] Pre-flight checks FAILED"
        echo "=========================================="
        echo ""
        echo "Please fix the issues above before running Cuttlefish."
        echo ""
        exit 1
    fi
    
    return 0
}

ARGS=()
while [[ $# -gt 0 ]]; do
  case $1 in
    --release_path=*) RELEASE_PATH="${1#*=}"; shift;;
    --bin_path=*) BIN_PATH="${1#*=}"; shift;;
    --flag_path=*) FLAG_FN="${1#*=}"; shift;;
    --apk_path=*) APK_PATH="${1#*=}"; shift;;
    --test-mode) TEST_MODE=1; shift;;
    --skip-checks) SKIP_CHECKS=1; shift;;
    --) # stop processing special arguments after "--"
        shift
        while [[ $# -gt 0 ]]; do ARGS+=("$1"); shift; done
        break
        ;;
    -*|--*) echo "[ERROR] Unknown option $1"; usage;;
    *) ARGS+=("$1"); shift;;
  esac
done
set -- "${ARGS[@]}"

# Validate required parameters
if [ -z "$RELEASE_PATH" ]; then
    echo "[ERROR] --release_path is required"
    usage
fi

if [ -z "$FLAG_FN" ]; then
    echo "[ERROR] --flag_path is required"
    usage
fi

# Set default APK path if not provided
if [ -z "$APK_PATH" ]; then
    APK_PATH="$SCRIPT_DIR/android_shellserver/app/build/outputs/apk/release/app-release.apk"
fi

# Validate that APK file exists
if [ ! -f "$APK_PATH" ]; then
    echo "[ERROR] APK file not found at $APK_PATH"
    exit 1
fi

echo "[OK] APK file found: $APK_PATH"

if [ "$TEST_MODE" -eq 1 ]; then
    echo "[TEST MODE] Running in test mode - flag will be readable by exploit user"
fi

# Run pre-flight checks (unless --skip-checks is specified)
if [ -z "$SKIP_CHECKS" ]; then
    run_preflight_checks
else
    echo "[WARNING] Skipping pre-flight checks (--skip-checks specified)"
    echo ""
fi

# Validate that RELEASE_PATH exists and is a directory
if [ ! -d "$RELEASE_PATH" ]; then
    echo "[ERROR] Release path '$RELEASE_PATH' does not exist or is not a directory"
    exit 1
fi

# Check that RELEASE_PATH contains required Cuttlefish files
if [ ! -f "$RELEASE_PATH/bin/launch_cvd" ]; then
    echo "[ERROR] '$RELEASE_PATH' does not appear to be a valid Cuttlefish release"
    echo "[ERROR] Missing: $RELEASE_PATH/bin/launch_cvd"
    exit 1
fi

# Convert RELEASE_PATH to absolute path
RELEASE_PATH=$(cd "$RELEASE_PATH" && pwd)

tmp="$RELEASE_PATH"
while [[ "$tmp" == *\"* ]]; do
  tmp="${tmp//\"}"
done
RELEASE_PATH="$tmp"

if [ ! -d "$RELEASE_PATH/../locks" ]; then
    mkdir -p "$RELEASE_PATH/../locks"
fi

# Check for the first free instance
for i in $(seq 1 32); do
    folder="$RELEASE_PATH/../locks/lock-inst-${i}"
    if mkdir "$folder" 2>/dev/null; then
        instance_num=$i
        # Record ownership
        echo $$ > "$folder/pid"
        echo "$(date +%s)" > "$folder/timestamp"
        echo "[OK] Acquired instance slot $instance_num"
        break
    fi
done

if [ -z "$instance_num" ]; then
    echo "[ERROR] All instances are busy, exiting..."
    exit 1
fi

# Calculate the ADB port for this instance
ADB_PORT=$((6520 + instance_num - 1))

# Create and boot virtual device with android kernel at RELEASE_PATH.
# The path to launch_cvd needs to be 108 characters or less
echo "[STARTING] Starting Cuttlefish instance..."

# Build base launch flags
LAUNCH_FLAGS="--daemon --console=true --resume=false --verbosity=ERROR --system_image_dir=\"$RELEASE_PATH\" --base_instance_num=$instance_num -report_anonymous_usage_stats=n"

# Auto-detect if we need --enable_tap_devices=false (Android 16+)
# Check kernel version string in boot.img
if [ -f "$RELEASE_PATH/boot.img" ]; then
    # Extract kernel version string and check for android16 or kernel 6.12+
    kernel_version=$(strings "$RELEASE_PATH/boot.img" 2>/dev/null | grep -m1 "android" | head -1)
    
    if echo "$kernel_version" | grep -q "android16\|android1[7-9]\|android[2-9]"; then
        LAUNCH_FLAGS="$LAUNCH_FLAGS --enable_tap_devices=false"
    elif echo "$kernel_version" | grep -Eq "^6\.1[2-9]\.|^6\.[2-9][0-9]\.|^[7-9]\."; then
        LAUNCH_FLAGS="$LAUNCH_FLAGS --enable_tap_devices=false"
    fi
fi

echo "[DEBUG] Launching with flags: $LAUNCH_FLAGS"
bash -c "HOME=$RELEASE_PATH $RELEASE_PATH/bin/launch_cvd $LAUNCH_FLAGS" 2>&1 | sed '/^===/,/^===/d'
LAUNCH_EXIT=${PIPESTATUS[0]}

if [ $LAUNCH_EXIT -ne 0 ]; then
    echo "[ERROR] Failed to launch Cuttlefish instance (exit code: $LAUNCH_EXIT)"
    exit 1
fi

# Wait for the instance to fully start and become ready
echo -n "[WAITING] Waiting for instance to start"
max_wait=120
waited=0
while [ $waited -lt $max_wait ]; do
    if [ -f "$RELEASE_PATH/cuttlefish_runtime.$instance_num/cuttlefish_config.json" ]; then
        echo " done"
        echo "[OK] Instance started successfully"
        break
    fi
    echo -n "."
    sleep 1
    waited=$((waited + 1))
done
if [ $waited -ge $max_wait ]; then
    echo " timeout"
    echo "[ERROR] Instance failed to start within ${max_wait} seconds"
    exit 1
fi

# Wait for ADB to connect and device to be ready
# FIX: Accept both 0.0.0.0 and 127.0.0.1 formats since Cuttlefish may report either
echo -n "[WAITING] Waiting for ADB to connect"
timeout=60
elapsed=0
device_found=0
while [ $elapsed -lt $timeout ]; do
    # Check for device on the expected port (works with both 0.0.0.0 and 127.0.0.1)
    if $RELEASE_PATH/bin/adb devices 2>/dev/null | grep -E "(0\.0\.0\.0|127\.0\.0\.1):${ADB_PORT}[[:space:]]+device" > /dev/null; then
        device_found=1
        echo " done"
        # Detect which format the device is using
        if $RELEASE_PATH/bin/adb devices 2>/dev/null | grep -q "0\.0\.0\.0:${ADB_PORT}"; then
            DEVICE_ADDRESS="0.0.0.0:${ADB_PORT}"
            echo "[INFO] Device connected as 0.0.0.0:${ADB_PORT}"
        else
            DEVICE_ADDRESS="127.0.0.1:${ADB_PORT}"
            echo "[INFO] Device connected as 127.0.0.1:${ADB_PORT}"
        fi
        echo "[OK] ADB connected"
        break
    fi
    echo -n "."
    sleep 2
    elapsed=$((elapsed + 2))
done

if [ $device_found -eq 0 ]; then
    echo " timeout"
    echo "[ERROR] ADB connection timeout after ${timeout}s"
    echo "[DEBUG] Current ADB devices:"
    $RELEASE_PATH/bin/adb devices
    exit 1
fi

# Define helper functions for ADB operations using the detected device address
as_root="$RELEASE_PATH/bin/adb -s $DEVICE_ADDRESS shell su root"
on_guest="$RELEASE_PATH/bin/adb -s $DEVICE_ADDRESS"

# Additional wait for device to be fully ready
echo -n "[WAITING] Waiting for device to be fully booted"
$on_guest wait-for-device
echo " done"
sleep 5

if [ ! -f "$FLAG_FN" ]; then
    echo "[ERROR] Flag file not found at $FLAG_FN"
    exit 1
fi

# Verify root access
echo "[CHECK] Verifying root access..."

# FIX: Use proper timeout and error handling for root check
if ! timeout 10 bash -c "$as_root id" 2>/dev/null | grep -q "uid=0"; then
    echo "[ERROR] Cannot execute commands as root"
    echo "[DEBUG] Attempting to diagnose root access issue..."
    
    # Try to get more information
    echo "[DEBUG] Testing basic shell access:"
    $on_guest shell id 2>&1 | head -3
    
    echo "[DEBUG] Testing su availability:"
    $on_guest shell "which su" 2>&1
    
    echo "[DEBUG] Build type:"
    $on_guest shell getprop ro.build.type 2>&1
    
    echo "[DEBUG] Debuggable:"
    $on_guest shell getprop ro.debuggable 2>&1
    
    exit 1
fi

echo "[OK] Root access verified"

# Setup flag file
FLAG=$(<$FLAG_FN)
$on_guest push $FLAG_FN /data/local/tmp/flag

if [ "$TEST_MODE" -eq 1 ]; then
    # Test mode: make flag readable by the exploit user
    $as_root "chmod 0644 /data/local/tmp/flag"
    $as_root "chown 10108:10108 /data/local/tmp/flag"
    echo "[TEST MODE] Flag is readable by exploit user"
else
    # Production mode: flag requires root
    $as_root "chmod 0000 /data/local/tmp/flag"
    $as_root "chown root:root /data/local/tmp/flag"
fi

PORT_TO_USE=$(expr $instance_num + 7000)

echo "[CHECK] Checking if port $PORT_TO_USE is available..."
if lsof -Pi :$PORT_TO_USE -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo "[ERROR] Port $PORT_TO_USE is already in use"
    exit 1
fi

# Install APK
echo "[INSTALLING] Installing APK..."
if ! $on_guest install -g $APK_PATH 2>&1 | tee /tmp/apk_install_$instance_num.log; then
    echo "[ERROR] APK installation failed"
    cat /tmp/apk_install_$instance_num.log
    exit 1
fi

# Verify the package is installed
echo "[VERIFYING] Checking package installation..."
if ! $on_guest shell pm list packages 2>/dev/null | grep -q "com.google.android.kernelctf.shellserver"; then
    echo "[ERROR] APK package not found after installation"
    exit 1
fi

echo "[OK] APK installed and verified successfully"
rm -f /tmp/apk_install_$instance_num.log

# Determine which binary path to pass to MainActivity
BINARY_PATH=""
if [ -f "$BIN_PATH" ]; then
    BIN_NAME=$(basename $BIN_PATH)
    BINARY_PATH="--es binary_path /data/local/tmp/$BIN_NAME"

    $on_guest push $BIN_PATH /data/local/tmp

    $as_root "chmod +x /data/local/tmp/$BIN_NAME"
    $as_root "chown 10108:10108 /data/local/tmp/$BIN_NAME"
    $as_root "chcon u:object_r:apk_data_file:s0 /data/local/tmp/$BIN_NAME"
fi

$as_root "am start -n com.google.android.kernelctf.shellserver/.MainActivity --es server_port $PORT_TO_USE $BINARY_PATH"
$on_guest forward tcp:$PORT_TO_USE tcp:$PORT_TO_USE

# Start single logcat monitor for both startup detection and crash monitoring
LOGCAT_FILE=$(mktemp)
($on_guest logcat 2>/dev/null > "$LOGCAT_FILE") &
LOGCAT_PID=$!

# Wait for android device to be ready by monitoring logcat
echo -n "[WAITING] Waiting for VM to be ready"
READY_TIMEOUT=30
READY_ELAPSED=0
VM_READY=0
while [ $READY_ELAPSED -lt $READY_TIMEOUT ]; do
    if grep -q "timeout 1800s socat -u tcp:127.0.0.1:$PORT_TO_USE - 2>&1 | tee "$OUTPUT_FILE" &" "$LOGCAT_FILE" 2>/dev/null; then
        VM_READY=1
        echo " done"
        echo "[OK] VM ready for connection"
        break
    fi
    echo -n "."
    sleep 1
    READY_ELAPSED=$((READY_ELAPSED + 1))
done

if [ $VM_READY -eq 0 ]; then
    echo " timeout"
    echo "[ERROR] VM setup failed - kernelCTF_READY not detected within ${READY_TIMEOUT}s"
    exit 1
fi

# After "VM ready for connection" and before spawning shell
echo "[DEBUG] Testing if port $PORT_TO_USE is listening..."
if nc -z 127.0.0.1 $PORT_TO_USE 2>/dev/null; then
    echo "[DEBUG] Port $PORT_TO_USE is listening"
else
    echo "[ERROR] Port $PORT_TO_USE is not listening!"
    exit 1
fi

echo "[DEBUG] Checking what's listening on port $PORT_TO_USE..."
lsof -i :$PORT_TO_USE 2>/dev/null || echo "[DEBUG] lsof found nothing"

echo "[INFO] Connecting to exploit"
if [ -n "$CI" ] || [ -n "$GITHUB_ACTIONS" ]; then
    echo "[DEBUG] CI mode: 30 min hard timeout, 60s no-output timeout, flag detection enabled"
fi
set +e

# In CI environments, we need to handle non-interactive connections
if [ -n "$CI" ] || [ -n "$GITHUB_ACTIONS" ]; then
    echo "[DEBUG] Connecting to port $PORT_TO_USE in CI mode..."
    
    # Create temporary file for output monitoring (CI only)
    OUTPUT_FILE=$(mktemp)
    CRASH_DETECTED=0
    
    # Run socat with 30-minute timeout and capture output
    timeout 1800s socat -u tcp:127.0.0.1:$PORT_TO_USE - 2>&1 | tee "$OUTPUT_FILE" &
    SOCAT_PID=$!
    
    # Monitor for flag in real-time (background process)
    (
        # Read the flag we're looking for
        FLAG_CONTENT=$(cat "$FLAG_FN" 2>/dev/null || echo "")
        if [ -z "$FLAG_CONTENT" ]; then
            echo "[WARNING] Could not read flag file, won't detect early completion" 1>&2
            exit 0
        fi
        
        # Watch the output file for the flag
        tail -f "$OUTPUT_FILE" 2>/dev/null | while read -r line; do
            if echo "$line" | grep -q "$FLAG_CONTENT"; then
                echo "[SUCCESS] Flag detected! Exploit completed successfully." 1>&2
                # Kill the socat process to exit early
                kill $SOCAT_PID 2>/dev/null || true
                break
            fi
        done
    ) &
    MONITOR_PID=$!
    
    # Activity monitor - kill if no output for 60 seconds (background process)
    (
        NO_OUTPUT_TIMEOUT=60
        LAST_SIZE=0
        STALE_COUNT=0
        
        # Wait for connection to establish
        sleep 5
        
        while kill -0 $SOCAT_PID 2>/dev/null; do
            if [ -f "$OUTPUT_FILE" ]; then
                CURRENT_SIZE=$(stat -f%z "$OUTPUT_FILE" 2>/dev/null || stat -c%s "$OUTPUT_FILE" 2>/dev/null || echo "0")
                
                if [ "$CURRENT_SIZE" -eq "$LAST_SIZE" ]; then
                    STALE_COUNT=$((STALE_COUNT + 1))
                    
                    if [ $STALE_COUNT -ge 60 ]; then
                        echo "[TIMEOUT] No output for ${NO_OUTPUT_TIMEOUT}s, killing exploit" 1>&2
                        kill $SOCAT_PID 2>/dev/null || true
                        break
                    fi
                else
                    STALE_COUNT=0
                    LAST_SIZE=$CURRENT_SIZE
                fi
            fi
            
            sleep 1
        done
    ) &
    ACTIVITY_MONITOR_PID=$!
    
    # Wait for socat to complete (either naturally, timeout, killed by monitor, or crashed)
    wait $SOCAT_PID
    socat_exit=$?
    
    # Clean up monitor processes
    kill $MONITOR_PID 2>/dev/null || true
    wait $MONITOR_PID 2>/dev/null || true
    kill $ACTIVITY_MONITOR_PID 2>/dev/null || true
    wait $ACTIVITY_MONITOR_PID 2>/dev/null || true
    
    # Analyze exit code
    echo "[DEBUG] socat exited with code: $socat_exit"
    
    # Check if VM died (connection lost)
    if [ $socat_exit -ne 0 ] && [ $socat_exit -ne 124 ] && [ $socat_exit -ne 143 ] && [ $socat_exit -ne 137 ]; then
        if ! timeout 5s $on_guest shell "echo test" >/dev/null 2>&1; then
            echo "[CRASH] VM appears to be unresponsive or crashed"
            CRASH_DETECTED=1
        fi
    fi
    
    # Save output for inspection
    if [ -f "$OUTPUT_FILE" ]; then
        echo "[DEBUG] Last 50 lines of exploit output:" 1>&2
        tail -50 "$OUTPUT_FILE" 1>&2
    fi
    
    # Clean up logcat monitoring
    if [ -n "$LOGCAT_PID" ]; then
        kill $LOGCAT_PID 2>/dev/null || true
        wait $LOGCAT_PID 2>/dev/null || true
    fi
    rm -f "$LOGCAT_FILE"
    
    # Clean up output file
    rm -f "$OUTPUT_FILE"
else
    # Interactive mode for local testing
    # Researcher can see crash output directly in terminal
    # No timeout - researcher controls with Ctrl+C
    echo "[DEBUG] Connecting to port $PORT_TO_USE in interactive mode (Ctrl+C to exit)..."
    socat - tcp:127.0.0.1:$PORT_TO_USE
    socat_exit=$?
    
    # Clean up logcat monitor
    if [ -n "$LOGCAT_PID" ]; then
        kill $LOGCAT_PID 2>/dev/null || true
        wait $LOGCAT_PID 2>/dev/null || true
    fi
    rm -f "$LOGCAT_FILE"
fi

set -e
if [ $socat_exit -eq 124 ]; then
    echo "[INFO] Connection timeout after 30 minutes (hard limit)" 1>&2
elif [ $socat_exit -eq 143 ] || [ $socat_exit -eq 137 ]; then
    echo "[INFO] Connection terminated (likely flag detected or activity timeout)" 1>&2
elif [ "${CRASH_DETECTED:-0}" -eq 1 ]; then
    echo "[INFO] Exploit execution ended - crash detected (post-mortem analysis)" 1>&2
elif [ $socat_exit -ne 0 ]; then
    echo "[INFO] Connection closed with exit code: $socat_exit" 1>&2
else
    echo "[INFO] Connection closed cleanly" 1>&2
fi
