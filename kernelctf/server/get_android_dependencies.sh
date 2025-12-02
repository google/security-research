#!/bin/bash
set -e

# Unset conflicting Android SDK environment variable if it exists
unset ANDROID_SDK_ROOT

# Check if running in exploit-build-only mode
EXPLOIT_BUILD_ONLY=false
if [ "$1" == "--exploit-build-only" ]; then
    EXPLOIT_BUILD_ONLY=true
fi

ANDROID_COMPILE_SDK="android-34"
ANDROID_BUILD_TOOLS="35.0.0"

log() {
    echo "[SETUP] $1"
}

error() {
    echo "[ERROR] $1"
}

warn() {
    echo "[WARN] $1"
}

install_if_missing() {
    local package=$1
    local display_name=${2:-$package}
    
    if ! dpkg-query -W -f'${Status}' "$package" 2>/dev/null | grep -q 'ok installed'; then
        log "Installing $display_name..."
        sudo apt install -y "$package"
    else
        echo "$display_name is already installed"
    fi
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANDROID_SHELLSERVER_DIR="$SCRIPT_DIR/android_shellserver"

# Skip KVM check in exploit-build-only mode
if [ "$EXPLOIT_BUILD_ONLY" = false ]; then
    if [ "$(grep -c -w 'vmx\|svm' /proc/cpuinfo)" == 0 ]; then
        error "Virtualization with KVM is not available."
        exit 1;
    fi
fi

# System & Runtime Dependencies
log "Updating package lists..."
sudo apt-get update

log "Installing system dependencies..."
install_if_missing "git" "Git"
install_if_missing "curl" "Curl"
install_if_missing "wget" "Wget"
install_if_missing "unzip" "Unzip"
install_if_missing "build-essential" "Build Essential"

# Only install runtime dependencies if not in exploit-build-only mode
if [ "$EXPLOIT_BUILD_ONLY" = false ]; then
    install_if_missing "socat" "Socat"
    
    # Python dependencies
    install_if_missing "python3-gmpy2" "python3-gmpy2" 
    install_if_missing "python-gmpy2-common" "python-gmpy2-common" 
    install_if_missing "python3-ecdsa" "python3-ecdsa" 
fi

# Cuttlefish Installation - skip in exploit-build-only mode
if [ "$EXPLOIT_BUILD_ONLY" = false ]; then
    log "Checking Cuttlefish installation..."

    # Ensure repository is configured
    if [ ! -f "/etc/apt/sources.list.d/artifact-registry.list" ]; then
        log "Adding Artifact Registry GPG key..."
        sudo curl -fsSL https://us-apt.pkg.dev/doc/repo-signing-key.gpg \
            -o /etc/apt/trusted.gpg.d/artifact-registry.asc
        sudo chmod a+r /etc/apt/trusted.gpg.d/artifact-registry.asc
        
        log "Adding Cuttlefish repository..."
        echo "deb https://us-apt.pkg.dev/projects/android-cuttlefish-artifacts android-cuttlefish main" \
            | sudo tee /etc/apt/sources.list.d/artifact-registry.list > /dev/null
        
        log "Updating package lists..."
        sudo apt-get update
    fi

    # Check if Cuttlefish is installed
    if dpkg-query -W -f'${Status}' 'cuttlefish-base' 2>/dev/null | grep -q 'ok installed'; then
        log "Cuttlefish is installed. Checking for updates..."
        
        # Refresh package information
        sudo apt-get update -qq
        
        # Get installed and available versions
        INSTALLED_VERSION=$(dpkg-query -W -f='${Version}' cuttlefish-base 2>/dev/null)
        AVAILABLE_VERSION=$(apt-cache policy cuttlefish-base | grep Candidate | awk '{print $2}')
        
        echo "  Installed version: $INSTALLED_VERSION"
        echo "  Available version: $AVAILABLE_VERSION"
        
        # Compare versions using dpkg --compare-versions
        if dpkg --compare-versions "$INSTALLED_VERSION" lt "$AVAILABLE_VERSION"; then
            log "Newer version available. Upgrading Cuttlefish..."
            sudo apt-get install -y --only-upgrade cuttlefish-base cuttlefish-user
            log "Cuttlefish upgrade complete"
        else
            log "Cuttlefish is already up to date."
        fi
    else
        log "Cuttlefish not found. Installing from Artifact Registry..."
        
        # Make sure we have the latest package lists
        sudo apt-get update -qq
        
        log "Installing Cuttlefish packages..."
        sudo apt-get install -y cuttlefish-base cuttlefish-user
        
        log "Cuttlefish installation complete"
    fi

    # Cuttlefish Configuration & Verification
    log "Verifying Cuttlefish environment configuration..."

    echo "Updating user groups..."
    sudo usermod -aG kvm,cvdnetwork,render $USER

    echo "Verifying permissions..."

    if [ -e /dev/kvm ]; then
        ls -la /dev/kvm
    else
        warn "/dev/kvm not found. KVM support may not be available."
    fi

    if [ -e /dev/net/tun ]; then
        ls -la /dev/net/tun
    else
        warn "/dev/net/tun not found."
    fi

    # Group Membership Check
    NEEDS_RELOAD=false

    if ! groups | grep -q cvdnetwork; then NEEDS_RELOAD=true; fi
    if ! groups | grep -q kvm; then NEEDS_RELOAD=true; fi
    if ! groups | grep -q render; then NEEDS_RELOAD=true; fi

    if [ "$NEEDS_RELOAD" = true ]; then
        warn "Group membership updated."
        warn "You need to log out and log back in for these changes to persist."
        warn "A temporary shell with new permissions will be spawned at the end of this script."
    else
        log "Group membership verified."
    fi
fi

# Android SDK & Build Tools
install_if_missing "android-sdk" "Android SDK"

# Detect ANDROID_HOME location after apt installation (universal detection)
if [ -d "/usr/lib/android-sdk" ]; then
    export ANDROID_HOME=/usr/lib/android-sdk
elif [ -d "/usr/local/lib/android/sdk" ]; then
    export ANDROID_HOME=/usr/local/lib/android/sdk
elif [ -n "$ANDROID_HOME" ] && [ -d "$ANDROID_HOME" ]; then
    # Use existing ANDROID_HOME if set and valid
    log "Using existing ANDROID_HOME: $ANDROID_HOME"
else
    # Try to find it using dpkg
    ANDROID_HOME=$(dpkg -L android-sdk 2>/dev/null | grep -m1 "bin/sdkmanager$" | xargs dirname | xargs dirname || echo "")
    if [ -z "$ANDROID_HOME" ] || [ ! -d "$ANDROID_HOME" ]; then
        error "Could not detect ANDROID_HOME after installing android-sdk package"
        error "Please set ANDROID_HOME manually"
        exit 1
    fi
fi

log "ANDROID_HOME set to: $ANDROID_HOME"

if [ ! -d "$ANDROID_HOME" ]; then
    error "ANDROID_HOME directory ($ANDROID_HOME) does not exist."
    error "The 'android-sdk' package might not have installed correctly."
    exit 1
fi

if [ ! -d "$ANDROID_HOME/cmdline-tools/latest" ]; then
    # Get latest cmdline-tools version from Android SDK repository
    log "Detecting latest command-line tools version..."
    LATEST_CMDLINE_VERSION=$(curl -s https://dl.google.com/android/repository/repository2-3.xml | \
        grep -oP 'commandlinetools-linux-\K[0-9]+' | \
        sort -n | \
        tail -1)

    if [ -n "$LATEST_CMDLINE_VERSION" ]; then
        CMDLINE_TOOLS_URL="https://dl.google.com/android/repository/commandlinetools-linux-${LATEST_CMDLINE_VERSION}_latest.zip"
        log "Using latest command-line tools version: $LATEST_CMDLINE_VERSION"
    else
        warn "Could not detect latest version, using default"
        CMDLINE_TOOLS_URL="https://dl.google.com/android/repository/commandlinetools-linux-13114758_latest.zip"
    fi
    
    log "Downloading command line tools..."
    wget -q --show-progress "$CMDLINE_TOOLS_URL" -O cmdline_tools.zip
    unzip -q cmdline_tools.zip -d cmdline-tools
    
    # Attempting to install cmdline-tools. 
    # WARNING: If ANDROID_HOME is not writable by the current user, this step will fail.
    if [ ! -w "$ANDROID_HOME" ]; then
        warn "$ANDROID_HOME is not writable. Trying with sudo..."
        sudo mkdir -p "$ANDROID_HOME/cmdline-tools/latest"
        sudo mv cmdline-tools/cmdline-tools/* "$ANDROID_HOME/cmdline-tools/latest/"
    else
        mkdir -p "$ANDROID_HOME/cmdline-tools/latest"
        mv cmdline-tools/cmdline-tools/* "$ANDROID_HOME/cmdline-tools/latest/"
    fi
    
    rm -rf cmdline-tools cmdline_tools.zip
    
    export PATH=$ANDROID_HOME/cmdline-tools/latest/bin:$PATH
else
    echo "Cmdline-tools is already installed"
fi

SDKMANAGER="$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager"

if [ -f "$SDKMANAGER" ]; then
    log "Accepting licenses via SDKManager..."
    
    # If not writable, we must use sudo to accept licenses/install
    if [ ! -w "$ANDROID_HOME" ]; then
        log "Using sudo for sdkmanager (system directory detected)..."
        yes | sudo $SDKMANAGER --licenses >/dev/null 2>&1
        
        log "Installing Android platform and build tools..."
        sudo $SDKMANAGER --install "platforms;${ANDROID_COMPILE_SDK}"
        sudo $SDKMANAGER --install "build-tools;${ANDROID_BUILD_TOOLS}"
    else
        yes | $SDKMANAGER --licenses >/dev/null 2>&1
        $SDKMANAGER --install "platforms;${ANDROID_COMPILE_SDK}"
        $SDKMANAGER --install "build-tools;${ANDROID_BUILD_TOOLS}"
    fi
    log "Platform and build tools installation complete"
else
    error "sdkmanager not found at $SDKMANAGER"
    exit 1
fi

# Android NDK Installation
log "Checking Android NDK installation..."

# Get the latest available NDK version from sdkmanager
NDK_VERSION=$($SDKMANAGER --list 2>/dev/null | grep "ndk;" | grep -v "ndk-bundle" | tail -1 | awk '{print $1}' | cut -d';' -f2)

if [ -z "$NDK_VERSION" ]; then
    error "Could not detect latest NDK version from sdkmanager"
    exit 1
fi

# Check if NDK is already installed
if [ -d "$ANDROID_HOME/ndk/$NDK_VERSION" ]; then
    log "NDK $NDK_VERSION is already installed"
else
    log "Installing Android NDK version: $NDK_VERSION"
    
    if [ ! -w "$ANDROID_HOME" ]; then
        sudo $SDKMANAGER "ndk;${NDK_VERSION}"
    else
        $SDKMANAGER "ndk;${NDK_VERSION}"
    fi
    
    log "NDK installation complete"
fi

# Set NDK environment variables
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/$NDK_VERSION"
NDK_TOOLCHAIN_PATH="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"

# Add NDK to PATH
export PATH="$NDK_TOOLCHAIN_PATH:$PATH"

log "ANDROID_NDK_HOME set to: $ANDROID_NDK_HOME"
log "NDK toolchain added to PATH"

# Check and fix AppArmor namespace restrictions (only when Cuttlefish will be used)
if [ "$EXPLOIT_BUILD_ONLY" = false ]; then
    log "Checking AppArmor namespace restrictions..."
    
    CURRENT_USERNS_RESTRICTION=$(sudo sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || echo "not_found")
    
    if [ "$CURRENT_USERNS_RESTRICTION" = "not_found" ]; then
        log "AppArmor userns restriction not present on this system (likely not Ubuntu 24.04+)"
    elif [ "$CURRENT_USERNS_RESTRICTION" = "1" ]; then
        warn "AppArmor is restricting unprivileged user namespaces"
        warn "This will cause Cuttlefish to fail with 'unshare(CLONE_NEWNS) failed: Operation not permitted'"
        echo ""
        
        if [ -n "$CI" ] || [ -n "$GITHUB_ACTIONS" ]; then
            log "CI environment detected - applying fix automatically..."
            sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
            log "AppArmor restriction disabled (temporary)"
        else
            echo "To fix this, you have two options:"
            echo ""
            echo "Option 1 (Temporary - until reboot):"
            echo "  sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0"
            echo ""
            echo "Option 2 (Permanent):"
            echo "  echo 'kernel.apparmor_restrict_unprivileged_userns = 0' | sudo tee /etc/sysctl.d/99-cuttlefish-userns.conf"
            echo "  sudo sysctl -p /etc/sysctl.d/99-cuttlefish-userns.conf"
            echo ""
            read -p "Would you like to apply the temporary fix now? (y/N): " -r REPLY
            echo ""
            
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                log "Applying temporary fix..."
                sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
                log "AppArmor restriction disabled (temporary - until reboot)"
                echo ""
                warn "To make this permanent, run:"
                warn "  echo 'kernel.apparmor_restrict_unprivileged_userns = 0' | sudo tee /etc/sysctl.d/99-cuttlefish-userns.conf"
                warn "  sudo sysctl -p /etc/sysctl.d/99-cuttlefish-userns.conf"
            else
                warn "Skipping AppArmor fix - Cuttlefish may fail to launch"
                warn "You can apply the fix manually later if needed"
            fi
        fi
    else
        log "AppArmor userns restriction is already disabled (value: $CURRENT_USERNS_RESTRICTION)"
    fi
    
    echo ""
fi

# Build android_shellserver APK (only when not in exploit-build-only mode)
if [ "$EXPLOIT_BUILD_ONLY" = false ]; then
    if [ ! -d "$ANDROID_SHELLSERVER_DIR" ]; then
        error "Directory not found: $ANDROID_SHELLSERVER_DIR"
        exit 1
    fi

    cd "$ANDROID_SHELLSERVER_DIR"

    if [ ! -f "gradlew" ]; then
        error "gradlew not found. Not a valid Gradle project?"
        exit 1
    fi

    NUM_CORES=$(nproc)
    log "Detected $NUM_CORES CPU cores"

    log "Configuring Gradle..."

    if [ -f "gradle.properties" ]; then
        warn "gradle.properties exists. Backing up to gradle.properties.bak"
        cp gradle.properties gradle.properties.bak
    fi

    cat > gradle.properties << EOF
# AndroidX Support
android.useAndroidX=true
android.enableJetifier=true

# Performance optimizations
org.gradle.parallel=true
org.gradle.caching=true
org.gradle.configureondemand=true
org.gradle.workers.max=$NUM_CORES
org.gradle.jvmargs=-Xmx4g -XX:MaxMetaspaceSize=512m -XX:+HeapDumpOnOutOfMemoryError --enable-native-access=ALL-UNNAMED
org.gradle.daemon=true
org.gradle.build-cache=true
EOF

    log "Checking Gradle version..."
    ./gradlew --version --quiet 2>&1 | grep "Gradle "

    ./gradlew --stop > /dev/null 2>&1 || true

    log "Cleaning build directories..."
    rm -rf app/build build .gradle

    export GRADLE_USER_HOME="$ANDROID_SHELLSERVER_DIR/.gradle"

    if [ -n "$CI" ] || [ -n "$GITHUB_ACTIONS" ]; then
        log "Running in CI environment - optimized for CI/CD"
        GRADLE_OPTS="--parallel --build-cache --no-daemon"
    else
        log "Running locally - using daemon for faster subsequent builds"
        GRADLE_OPTS="--parallel --build-cache"
    fi

    log "Generating keystore..."
    ./gradlew generateKeystore $GRADLE_OPTS --quiet

    log "Building release APK (parallel mode with $NUM_CORES workers)..."
    ./gradlew --refresh-dependencies assembleRelease $GRADLE_OPTS --quiet

    APK_PATH="app/build/outputs/apk/release/app-release.apk"
    if [ -f "$APK_PATH" ]; then
        log "Build successful!"
        echo "APK: $(realpath "$APK_PATH")"
        ls -lh "$APK_PATH"
    else
        error "Build failed: APK not found"
        exit 1
    fi

    cd $SCRIPT_DIR
fi

# Export environment variables
if [ -n "$CI" ] || [ -n "$GITHUB_ACTIONS" ]; then
    # CI/CD environment (GitHub Actions, etc.)
    if [ -n "$GITHUB_ENV" ] && [ -n "$GITHUB_PATH" ]; then
        log "Exporting environment variables for GitHub Actions..."
        echo "ANDROID_HOME=$ANDROID_HOME" >> $GITHUB_ENV
        echo "ANDROID_NDK_HOME=$ANDROID_NDK_HOME" >> $GITHUB_ENV
        echo "$NDK_TOOLCHAIN_PATH" >> $GITHUB_PATH
        
        log "Environment variables exported to GitHub Actions:"
        log "  ANDROID_HOME=$ANDROID_HOME"
        log "  ANDROID_NDK_HOME=$ANDROID_NDK_HOME"
        log "  NDK in PATH: $NDK_TOOLCHAIN_PATH"
    fi
else
    # Local development environment
    ENV_FILE="$SCRIPT_DIR/android_env.sh"
    log "Creating environment file: $ENV_FILE"
    
    cat > "$ENV_FILE" << EOF
# Android development environment
# Source this file to set up your environment:
#   source $ENV_FILE

export ANDROID_HOME="$ANDROID_HOME"
export ANDROID_NDK_HOME="$ANDROID_NDK_HOME"
export PATH="$NDK_TOOLCHAIN_PATH:\$PATH"

echo "Android development environment loaded:"
echo "  ANDROID_HOME=\$ANDROID_HOME"
echo "  ANDROID_NDK_HOME=\$ANDROID_NDK_HOME"
echo "  NDK toolchain added to PATH"
EOF
    
    chmod +x "$ENV_FILE"
    
    echo ""
    warn "==============================================="
    warn "Environment variables have been saved to:"
    warn "  $ENV_FILE"
    warn ""
    warn "To use them in your current shell, run:"
    warn "  source $ENV_FILE"
    warn "==============================================="
    echo ""
fi

log "... The End ..."

if [ "$EXPLOIT_BUILD_ONLY" = false ] && [ "$NEEDS_RELOAD" = true ]; then
    echo ""
    if [ -n "$CI" ] || [ -n "$GITHUB_ACTIONS" ]; then
        warn "Running in CI environment - group changes detected"
        warn "Groups will be activated using 'sg' command when running Cuttlefish"
    else
        warn "Spawning new shell with updated group permissions..."
        exec sudo su - $USER
    fi
fi
