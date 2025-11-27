#!/bin/bash
set -e

ANDROID_COMPILE_SDK="android-34"
ANDROID_BUILD_TOOLS="35.0.0"
CMDLINE_TOOLS_URL="https://dl.google.com/android/repository/commandlinetools-linux-13114758_latest.zip"
CMDLINE_TOOLS_VER="13.0" 

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

if [ "$(grep -c -w 'vmx\|svm' /proc/cpuinfo)" == 0 ]; then
    error "Virtualization with KVM is not available."
    exit 1;
fi

# System & Runtime Dependencies
log "Updating package lists..."
sudo apt-get update

log "Installing system dependencies..."
install_if_missing "git" "Git"
install_if_missing "curl" "Curl"
install_if_missing "wget" "Wget"
install_if_missing "unzip" "Unzip"
install_if_missing "socat" "Socat"
install_if_missing "build-essential" "Build Essential"

# Python dependencies
install_if_missing "python3-gmpy2" "python3-gmpy2" 
install_if_missing "python-gmpy2-common" "python-gmpy2-common" 
install_if_missing "python3-ecdsa" "python3-ecdsa" 

# Cuttlefish Installation via Artifact Registry
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

# Android SDK & Build Tools
install_if_missing "android-sdk" "Android SDK"

export ANDROID_HOME=/usr/lib/android-sdk
log "ANDROID_HOME set to: $ANDROID_HOME"

if [ ! -d "$ANDROID_HOME" ]; then
    error "ANDROID_HOME directory ($ANDROID_HOME) does not exist."
    error "The 'android-sdk' package might not have installed correctly."
    exit 1
fi

if [ ! -d "$ANDROID_HOME/cmdline-tools/latest" ]; then
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

log "... The End ..."

if [ "$NEEDS_RELOAD" = true ]; then
    echo ""
    warn "Spawning new shell with updated group permissions..."
    exec sudo su - $USER
fi
