#!/bin/bash
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -ex

INSTALL_DIR="/home/kernelctf"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
SCRIPT_SRC_DIR="$(cd "$SCRIPT_DIR/.." &>/dev/null && pwd)"
USER="${SUDO_USER:-$USER}"

echo "=== Setting up kernelCTF v5 Environment in $INSTALL_DIR ==="

# Create kernelctf system user & group if missing
if ! id -u kernelctf &>/dev/null; then
    useradd -m -d "$INSTALL_DIR" -s /bin/bash kernelctf
fi
mkdir -p "$INSTALL_DIR"

# Ensure user is in kvm group for /dev/kvm access
if getent group kvm &>/dev/null; then
    usermod -aG kvm kernelctf || adduser kernelctf kvm
fi

# Ensure $USER user is in kernelctf group
if [ -n "$USER" ] && id -u "$USER" &>/dev/null; then
    usermod -aG kernelctf "$USER"
fi

# Configure SSH authorized keys
SSH_KEYS_FILE="$SCRIPT_SRC_DIR/secrets/ssh_keys.txt"

SSH_KEYS=()
if [ -f "$SSH_KEYS_FILE" ]; then
    while IFS= read -r key || [ -n "$key" ]; do
        [[ -z "$key" || "$key" =~ ^[[:space:]]*# ]] && continue
        SSH_KEYS+=("$key")
    done < "$SSH_KEYS_FILE"
fi

add_ssh_keys() {
    local target_home="$1"
    local target_user="$2"
    if [ -d "$target_home" ]; then
        local ssh_dir="$target_home/.ssh"
        local auth_keys="$ssh_dir/authorized_keys"
        mkdir -p "$ssh_dir"
        chmod 700 "$ssh_dir"
        touch "$auth_keys"
        chmod 600 "$auth_keys"
        for key in "${SSH_KEYS[@]}"; do
            grep -F "$key" "$auth_keys" &>/dev/null || echo "$key" >> "$auth_keys"
        done
        if [ -n "$target_user" ]; then
            chown -R "$target_user:$target_user" "$ssh_dir"
        fi
    fi
}

add_ssh_keys "$INSTALL_DIR" "kernelctf"
if [ -n "$USER" ]; then
    add_ssh_keys "/home/$USER" "$USER"
fi
add_ssh_keys "/root" "root"

# Copy files to /home/kernelctf if executed from another directory (e.g. staging)
if [ "$SCRIPT_SRC_DIR" != "$INSTALL_DIR" ]; then
    echo "Copying files from $SCRIPT_SRC_DIR to $INSTALL_DIR..."

    # Copy config files without overwriting existing files on the host (-n / --no-clobber)
    mkdir -p "$INSTALL_DIR/config"
    cp -n "$SCRIPT_SRC_DIR/config"/* "$INSTALL_DIR/config/" 2>/dev/null || true

    # Overwrite and update application code, tooling, infra, and secrets
    for item in server tools infra secrets; do
        cp -r "$SCRIPT_SRC_DIR/$item" "$INSTALL_DIR/"
    done
fi

cd "$INSTALL_DIR"

# Install system packages
export DEBIAN_FRONTEND=noninteractive
echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
apt-get update
apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" install socat qemu-system-x86 iptables-persistent python3 python3-pip python3-yaml python3-httplib2 python3-requests cpio curl ca-certificates cron net-tools build-essential git ninja-build pkg-config libglib2.0-dev libpixman-1-dev flex bison python3-venv

# Build and install QEMU 11 from source if not already installed
CURRENT_QEMU_VER="$(qemu-system-x86_64 --version 2>/dev/null | head -n1 || true)"
if [[ "$CURRENT_QEMU_VER" != *" 11."* ]]; then
    echo "Building and installing QEMU 11..."
    rm -rf /tmp/qemu
    git clone --recurse-submodules --depth 1 https://gitlab.com/qemu-project/qemu.git /tmp/qemu
    cd /tmp/qemu
    ./configure --target-list=x86_64-softmmu --enable-kvm --disable-docs --disable-user --disable-tools
    make -j$(nproc)
    make install
    cd "$INSTALL_DIR"
    rm -rf /tmp/qemu
fi

# Generate server certificates if missing
if [ ! -f secrets/server_cert_and_key.pem ]; then
    echo "Generating server certificate and key..."
    chmod +x infra/server_cert_gen.sh
    ./infra/server_cert_gen.sh
fi

# Activate Google Cloud Service Account and download required releases
echo "Activating GCS service account..."
gcloud auth activate-service-account --key-file="secrets/kernelctf-vm-reader-sa-key.json"

mkdir -p data/releases data/staging

# Parse latest LTS release from config/releases.yaml
LTS_RELEASE=$(python3 infra/get_latest_lts.py)

TARGET_RELEASES=("hardened-v1-7.2-rc5")
if [ -n "$LTS_RELEASE" ]; then
    TARGET_RELEASES+=("$LTS_RELEASE" "${LTS_RELEASE}-kasan")
fi

echo "Ensuring required releases are downloaded: ${TARGET_RELEASES[*]}"
for REL in "${TARGET_RELEASES[@]}"; do
    TARGET_DIR="data/releases/$REL"
    if [ ! -f "$TARGET_DIR/bzImage" ]; then
        echo "Release $REL not found in $TARGET_DIR. Downloading from GCS..."
        mkdir -p "$TARGET_DIR"
        gsutil rsync -rx '.*vmlinux.gz|.*dbgsym.*' "gs://kernelctf-build/releases/$REL" "$TARGET_DIR"
    else
        echo "Release $REL already exists in $TARGET_DIR, skipping download."
    fi
done

# Pre-build / update initramfs image
echo "Building initramfs image..."
chmod +x server/vm/run_vmlinuz.sh server/vm/update_rootfs_image.sh server/vm/rootfs/cmd_wrapper.sh server/vm/rootfs/init server/vm/rootfs/busybox
(cd server/vm && ./update_rootfs_image.sh)

# Setup crontab for auto_release
echo "Setting up auto_release crontab from infra/cron/auto_release.cron..."
chmod +x tools/auto_release.py tools/activate_releases.py
crontab -u kernelctf infra/cron/auto_release.cron
systemctl enable --now cron 2>/dev/null || systemctl enable --now crond

# Set permissions and ownership
chmod -R u+x infra/*.sh server/*.sh 2>/dev/null || true
chmod 755 server/service.sh server/server.py server/utils.py server/qemu.sh infra/get_latest_lts.py tools/activate_releases.py tools/auto_release.py
chmod -R 755 server/vm/
chmod -R a+rX data/ config/

chown -R kernelctf:kernelctf "$INSTALL_DIR"

# Allow members of kernelctf group (e.g. $USER) read/write access to subdirectories and files
chmod -R g+rwX "$INSTALL_DIR"

# Home directory (/home/kernelctf) itself must be 755 (not group-writable) for OpenSSH StrictModes
chmod 755 "$INSTALL_DIR"

# Ensure SSH strict modes are preserved on .ssh directory and authorized_keys
if [ -d "$INSTALL_DIR/.ssh" ]; then
    chmod 700 "$INSTALL_DIR/.ssh"
    chmod 600 "$INSTALL_DIR/.ssh/authorized_keys" 2>/dev/null || true
    chown -R kernelctf:kernelctf "$INSTALL_DIR/.ssh"
fi

# Restrict sensitive secrets to owner and group only
if [ -d secrets ]; then
    chmod 750 secrets
    chmod 640 secrets/* 2>/dev/null || true
fi

# Firewall rules (rate limiting port 1337)
iptables_add_if_missing() {
    iptables -C "$@" 2>/dev/null || iptables -A "$@"
}

iptables_add_if_missing INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables_add_if_missing INPUT -p tcp --dport 1337 -m connlimit --connlimit-above 2 --connlimit-mask 32 -j REJECT --reject-with tcp-reset
iptables_add_if_missing INPUT -p tcp --dport 1337 -j ACCEPT

netfilter-persistent save
netfilter-persistent reload

# Increase system-wide AIO limit and memlock limits
echo 'fs.aio-max-nr = 1048576' > /etc/sysctl.d/99-sysctl.conf
sysctl --system

mkdir -p /etc/security/limits.d
printf "kernelctf soft memlock unlimited\nkernelctf hard memlock unlimited\n" > /etc/security/limits.d/kernelctf.conf

# Setup and restart kernelctf systemd service
cp infra/systemd/kernelctf.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable kernelctf
systemctl restart kernelctf
sleep 1
systemctl --no-pager status kernelctf

echo "=== kernelCTF setup completed successfully ==="
