#!/bin/bash
set -e

# This script is expected to be run from kernelctf/repro directory
# Required environment variables: RELEASE_ID

if [ -z "$RELEASE_ID" ]; then
    echo "ERROR: RELEASE_ID environment variable is not set."
    exit 1
fi

# Start Android dependencies installation in background
(
  bash ../../kernelctf/server/get_android_dependencies.sh > android_deps_install.log 2>&1
  DEPS_EXIT=$?
  
  if [ $DEPS_EXIT -eq 0 ]; then
    echo "Dependencies installation completed"
    
    # Clean up apt cache immediately after installation to free space
    echo "Cleaning up apt cache..."
    sudo apt-get clean
    sudo rm -rf /var/lib/apt/lists/*
  fi
  
  exit $DEPS_EXIT
) &
DEPS_PID=$!

# Start system images download in background
(
  mkdir -p android_release
  cd android_release
  
  # Extract build number from RELEASE_ID
  BUILD_NUMBER=$(echo "$RELEASE_ID" | grep -oP '\d+$')
  
  echo "Downloading and extracting Android system images for $RELEASE_ID (build: $BUILD_NUMBER)..."
  
  # Download, extract, and delete phone image immediately
  wget --progress=dot:giga https://storage.googleapis.com/kernelctf-build/releases/$RELEASE_ID/aosp_cf_x86_64_only_phone-img-${BUILD_NUMBER}.zip 2>&1 | tail -n 1
  echo "Extracting phone image..."
  unzip -q aosp_cf_x86_64_only_phone-img-${BUILD_NUMBER}.zip
  echo "Removing phone image archive to save space..."
  rm -f aosp_cf_x86_64_only_phone-img-${BUILD_NUMBER}.zip
  
  # Download, extract, and delete host package immediately
  wget --progress=dot:giga https://storage.googleapis.com/kernelctf-build/releases/$RELEASE_ID/cvd-host_package.tar.gz 2>&1 | tail -n 1
  echo "Extracting host package..."
  tar -xzf cvd-host_package.tar.gz
  echo "Removing host package archive to save space..."
  rm -f cvd-host_package.tar.gz
  
  echo "System images ready"
) &
DOWNLOAD_PID=$!

# Wait for both to complete
echo "Running in parallel: dependencies installation (PID: $DEPS_PID) and image download (PID: $DOWNLOAD_PID)..."
wait $DEPS_PID
DEPS_EXIT=$?
wait $DOWNLOAD_PID
DOWNLOAD_EXIT=$?

# Check if either failed
if [ $DEPS_EXIT -ne 0 ]; then
  echo "ERROR: Dependencies installation failed with exit code $DEPS_EXIT"
  echo "Last 50 lines of android_deps_install.log:"
  tail -n 50 android_deps_install.log || true
  exit $DEPS_EXIT
fi

if [ $DOWNLOAD_EXIT -ne 0 ]; then
  echo "ERROR: Image download failed with exit code $DOWNLOAD_EXIT"
  exit $DOWNLOAD_EXIT
fi

echo "Both tasks completed successfully"

APK_SOURCE="../../kernelctf/server/android_shellserver/app/build/outputs/apk/release/app-release.apk"

if [ -f "$APK_SOURCE" ]; then
  # Show space before cleanup
  echo "Disk space before cleanup:"
  df -h / | grep -E "Filesystem|/$"
  
  # Copy APK to a known location
  mkdir -p ./apk
  cp "$APK_SOURCE" ./apk/app-release.apk
  echo "APK saved to: $(pwd)/apk/app-release.apk"
  
  # Remove android_shellserver directory (source + build artifacts ~200MB)
  echo "Removing android_shellserver directory..."
  rm -rf ../../kernelctf/server/android_shellserver
  
  # Clean Gradle cache (~500MB)
  if [ -d "$HOME/.gradle" ]; then
    echo "Cleaning Gradle cache..."
    rm -rf $HOME/.gradle/caches
    rm -rf $HOME/.gradle/wrapper/dists
    rm -rf $HOME/.gradle/daemon
  fi
else
  echo "ERROR: APK not found at $APK_SOURCE"
  exit 1
fi
