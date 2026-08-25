#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

get_clang_major_version() {
    local clang_bin="$1"
    "$clang_bin" --version 2>/dev/null | grep -oP 'clang version \K[0-9]+' | head -n1 || true
}

ensure_llvm22() {
    local sudo_cmd=""
    if [ "$(id -u)" -ne 0 ]; then
        if command -v sudo >/dev/null 2>&1; then
            sudo_cmd="sudo"
        else
            echo "--> [LLVM] Warning: not running as root and sudo not found."
        fi
    fi

    # 1. Check if system clang in PATH is >= 22
    local system_clang
    system_clang="$(command -v clang 2>/dev/null || true)"
    if [ -n "$system_clang" ]; then
        local sys_major
        sys_major="$(get_clang_major_version "$system_clang")"
        if [ -n "$sys_major" ] && [ "$sys_major" -ge 22 ]; then
            echo "--> [LLVM] System clang ($system_clang) version $sys_major is >= 22. Skipping LLVM installation."
            "$system_clang" --version
            return 0
        fi
    fi

    # 2. Check if clang-22 is already installed
    if ! command -v clang-22 >/dev/null 2>&1 && [ ! -x "/usr/bin/clang-22" ] && [ ! -x "/usr/lib/llvm-22/bin/clang" ]; then
        echo "--> [LLVM] LLVM >= 22 not found on system. Installing LLVM 22 from PPA (apt.llvm.org)..."

        # Ensure prerequisites for repository setup
        $sudo_cmd apt-get update
        $sudo_cmd apt-get install -yq --no-install-recommends \
            wget curl gnupg lsb-release software-properties-common ca-certificates

        # Try installing via apt.llvm.org setup script
        local llvm_script="/tmp/llvm.sh"
        local installed=0
        if wget -qO "$llvm_script" https://apt.llvm.org/llvm.sh || curl -sSf -o "$llvm_script" https://apt.llvm.org/llvm.sh; then
            chmod +x "$llvm_script"
            if $sudo_cmd "$llvm_script" 22; then
                installed=1
            fi
            rm -f "$llvm_script"
        fi

        # Fallback if script failed
        if [ "$installed" -eq 0 ]; then
            echo "--> [LLVM] llvm.sh script failed, attempting manual repository configuration..."
            local codename
            codename="$(lsb_release -cs 2>/dev/null || (. /etc/os-release && echo "$VERSION_CODENAME"))"
            wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | $sudo_cmd tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc > /dev/null
            $sudo_cmd add-apt-repository -y "deb http://apt.llvm.org/${codename}/ llvm-toolchain-${codename}-22 main"
            $sudo_cmd apt-get update
            $sudo_cmd apt-get install -yq clang-22 lld-22 llvm-22
        fi

        # Ensure tools like llvm-ar, llvm-nm, llvm-objcopy, etc. are installed
        $sudo_cmd apt-get install -yq clang-22 lld-22 llvm-22 llvm-22-tools || true
    fi

    # 3. Configure alternatives / symlinks for LLVM 22 tools
    echo "--> [LLVM] Configuring LLVM 22 alternatives and links..."
    local llvm_version=22
    local llvm_tools=(clang clang++ lld ld.lld llvm-ar llvm-nm llvm-objcopy llvm-objdump llvm-readelf llvm-strip)
    local tool
    for tool in "${llvm_tools[@]}"; do
        local tool_bin=""
        if [ -x "/usr/bin/${tool}-${llvm_version}" ]; then
            tool_bin="/usr/bin/${tool}-${llvm_version}"
        elif [ -x "/usr/lib/llvm-${llvm_version}/bin/${tool}" ]; then
            tool_bin="/usr/lib/llvm-${llvm_version}/bin/${tool}"
        elif command -v "${tool}-${llvm_version}" >/dev/null 2>&1; then
            tool_bin="$(command -v "${tool}-${llvm_version}")"
        fi

        if [ -n "$tool_bin" ]; then
            $sudo_cmd update-alternatives --install "/usr/bin/${tool}" "${tool}" "$tool_bin" 100 2>/dev/null || true
            $sudo_cmd update-alternatives --set "${tool}" "$tool_bin" 2>/dev/null || true
            if ! command -v "${tool}" >/dev/null 2>&1 || [ "$(command -v "${tool}")" != "/usr/bin/${tool}" ]; then
                $sudo_cmd ln -sf "$tool_bin" "/usr/bin/${tool}" 2>/dev/null || true
            fi
        fi
    done

    # Handle ld.lld if not present but lld-22 is present
    if ! command -v ld.lld >/dev/null 2>&1; then
        if [ -x "/usr/bin/lld-${llvm_version}" ]; then
            $sudo_cmd ln -sf "/usr/bin/lld-${llvm_version}" "/usr/bin/ld.lld" 2>/dev/null || true
        elif [ -x "/usr/bin/lld" ]; then
            $sudo_cmd ln -sf "/usr/bin/lld" "/usr/bin/ld.lld" 2>/dev/null || true
        fi
    fi

    if [ -d "/usr/lib/llvm-${llvm_version}/bin" ]; then
        export PATH="/usr/lib/llvm-${llvm_version}/bin:$PATH"
    fi

    if command -v clang >/dev/null 2>&1; then
        echo "--> [LLVM] LLVM 22 setup complete."
        clang --version
    else
        echo "--> [LLVM] Error: clang not found after setup."
        return 1
    fi
}

ensure_llvm22 "$@"
