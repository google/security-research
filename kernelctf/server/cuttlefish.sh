#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APK_PATH="$SCRIPT_DIR/android_shellserver/app/build/outputs/apk/release/app-release.apk"
RELEASE_PATH=""

cleanup_function() {
    set +e
    echo "[CLEANUP] Shutting down instance $instance_num" 1>&2
    
    # Kill background processes
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null
    fi
    
    # Remove named pipe
    if [ -n "$pipe_name" ] && [ -p "$pipe_name" ]; then
        rm -f "$pipe_name"
    fi
    
    # Stop cuttlefish
    if [ -n "$RELEASE_PATH" ] && [ -d "$RELEASE_PATH" ]; then
        CUTTLEFISH_RUNTIME_LINK=$RELEASE_PATH/cuttlefish_runtime
        CUTTLEFISH_CURRENT_INSTANCE=$RELEASE_PATH/cuttlefish/instances/cvd-$instance_num
        
        if [ -d "$CUTTLEFISH_CURRENT_INSTANCE" ]; then
            ln -sf $CUTTLEFISH_CURRENT_INSTANCE $CUTTLEFISH_RUNTIME_LINK 2>/dev/null
            HOME=$RELEASE_PATH $RELEASE_PATH/bin/stop_cvd 2>/dev/null || true
        fi
        
        # Clean up instance data
        rm -rf "$RELEASE_PATH/cuttlefish_runtime.$instance_num" 2>/dev/null
        rm -rf "$CUTTLEFISH_CURRENT_INSTANCE" 2>/dev/null
    fi
    
    # Release instance lock
    if [ -n "$folder" ] && [ -d "$folder" ]; then
        rm -rf "$folder" 2>/dev/null
    fi
    
    if [ -n "$instance_num" ]; then
        rm -rf "$RELEASE_PATH/../locks/lock-inst-$instance_num" 2>/dev/null
    fi
    
    echo "[CLEANUP] Cleanup done" 1>&2
    exit 0
}

cleanup_wrapper() {
    cleanup_function 1>&2
}

trap 'cleanup_wrapper' EXIT

usage() {
    echo "Usage: $0 --release_path=<release_path> --flag_path=<flag_fn> [--bin_path=<bin_path>]"
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

# Check if enable_tap_devices flag is supported (Android 16+)
# Android 16+ defaults to TAP networking which requires CAP_NET_ADMIN capability
# Disabling tap devices allows running without sudo and provides same functionality as Android 14
if $RELEASE_PATH/bin/launch_cvd --help 2>&1 | grep -q "enable_tap_devices"; then
    # Detected Android 16+, disabling tap devices (avoids sudo requirement)
    LAUNCH_FLAGS="$LAUNCH_FLAGS --enable_tap_devices=false"
fi

bash -c "HOME=$RELEASE_PATH $RELEASE_PATH/bin/launch_cvd $LAUNCH_FLAGS" 2>/dev/null | sed '/^===/,/^===/d'

if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to launch Cuttlefish instance"
    exit 1
fi

# Wait for the instance to fully start and become ready
echo -n "[WAITING] Waiting for instance to start"
max_wait=30
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
$on_guest push $FLAG_FN /data/local/tmp
$as_root "chmod 0000 /data/local/tmp/flag"
$as_root "chown root:root /data/local/tmp/flag"

PORT_TO_USE=$(expr $instance_num + 7000)

echo "[CHECK] Checking if port $PORT_TO_USE is available..."
if lsof -Pi :$PORT_TO_USE -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo "[ERROR] Port $PORT_TO_USE is already in use"
    exit 1
fi

# Create a named pipe
pipe_name=$(mktemp -u)
mkfifo "$pipe_name"

# Install APK
if [ ! -f "$APK_PATH" ]; then
    echo "[ERROR] APK file not found at $APK_PATH"
    exit 1
fi

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

# background process to redirect VM's logcat output to a named pipe
(($on_guest logcat -s ShellServer:I *:S) 2>/dev/null > "$pipe_name") &
pid=$!

# Wait for android device to be ready
if timeout 5s grep -q kernelCTF_READY $pipe_name; then
    echo "[OK] VM ready for connection"
else
    echo "[ERROR] VM setup failed. Exiting"
    kill "$pid"
    exit
fi
kill $pid

echo "[INFO] Spawning interactive shell (Type \"exit\" to exit)"
set +e
socat - tcp:127.0.0.1:$PORT_TO_USE
socat_exit=$?
set -e

if [ $socat_exit -ne 0 ]; then
    echo "[INFO] Connection closed" 1>&2
fi
