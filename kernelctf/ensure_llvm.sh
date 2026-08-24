#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR"

LLVM_SRC_DIR="$BUILD_DIR/llvm-22"
LLVM_BUILD_DIR="$LLVM_SRC_DIR/build"
LLVM_BIN_DIR="$LLVM_BUILD_DIR/bin"
LLVM_REPO_URL="https://github.com/llvm/llvm-project.git"
LLVM_BRANCH="release/22.x"

get_clang_major_version() {
    local clang_bin="$1"
    "$clang_bin" --version 2>/dev/null | grep -oP 'clang version \K[0-9]+' | head -n1 || true
}

# 1. Check if system clang in PATH is >= 22
SYSTEM_CLANG="$(which clang 2>/dev/null || true)"
if [ -n "$SYSTEM_CLANG" ]; then
    SYS_MAJOR="$(get_clang_major_version "$SYSTEM_CLANG")"
    if [ -n "$SYS_MAJOR" ] && [ "$SYS_MAJOR" -ge 22 ]; then
        echo "--> [LLVM] System clang ($SYSTEM_CLANG) version $SYS_MAJOR is >= 22. Skipping LLVM build."
        "$SYSTEM_CLANG" --version
        export PATH="$(dirname "$SYSTEM_CLANG"):$PATH"
        return 0 2>/dev/null || exit 0
    fi
fi

# 2. Check if cached local LLVM 22 build exists
if [ -x "$LLVM_BIN_DIR/clang" ]; then
    LOCAL_MAJOR="$(get_clang_major_version "$LLVM_BIN_DIR/clang")"
    if [ -n "$LOCAL_MAJOR" ] && [ "$LOCAL_MAJOR" -ge 22 ]; then
        echo "--> [LLVM] LLVM 22 already built at $LLVM_BIN_DIR. Reusing cached build."
        export PATH="$LLVM_BIN_DIR:$PATH"
        "$LLVM_BIN_DIR/clang" --version
        return 0 2>/dev/null || exit 0
    fi
fi

# 3. Download and build LLVM 22
echo "--> [LLVM] LLVM >= 22 not found on system or cache. Building LLVM 22..."

if [ ! -d "$LLVM_SRC_DIR/.git" ]; then
    echo "--> [LLVM] Downloading LLVM 22 (shallow clone)..."
    git clone --depth 1 --branch "$LLVM_BRANCH" "$LLVM_REPO_URL" "$LLVM_SRC_DIR"
fi

mkdir -p "$LLVM_BUILD_DIR"

if [ ! -f "$LLVM_BUILD_DIR/build.ninja" ]; then
    echo "--> [LLVM] Configuring CMake..."
    cmake -G Ninja -S "$LLVM_SRC_DIR/llvm" -B "$LLVM_BUILD_DIR" \
        -DCMAKE_BUILD_TYPE=Release \
        -DLLVM_ENABLE_PROJECTS="clang;lld" \
        -DLLVM_TARGETS_TO_BUILD="X86" \
        -DLLVM_ENABLE_ASSERTIONS=OFF \
        -DLLVM_ENABLE_BINDINGS=OFF \
        -DLLVM_INCLUDE_TESTS=OFF \
        -DLLVM_INCLUDE_EXAMPLES=OFF \
        -DLLVM_INCLUDE_BENCHMARKS=OFF \
        -DLLVM_INCLUDE_DOCS=OFF
fi

echo "--> [LLVM] Compiling clang, lld, and llvm tools with Ninja..."
ninja -C "$LLVM_BUILD_DIR" clang lld llvm-ar llvm-nm llvm-objcopy llvm-objdump llvm-readelf llvm-strip

export PATH="$LLVM_BIN_DIR:$PATH"
echo "--> [LLVM] LLVM 22 build complete."
"$LLVM_BIN_DIR/clang" --version
