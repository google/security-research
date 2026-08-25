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

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." &>/dev/null && pwd)"
cd "$REPO_ROOT"

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    echo "Usage: $0 [TARGET_HOST]"
    echo ""
    echo "Deploys the kernelCTF environment to the specified remote VM (default: kernelctf.vrp.ctfcompetition.com)"
    echo "and runs the setup script."
    echo ""
    echo "Example:"
    echo "  $0 kernelctf.vrp.ctfcompetition.com"
    echo "  $0 user@kernelctf.vrp.ctfcompetition.com"
    exit 0
fi

TARGET_HOST="${1:-kernelctf.vrp.ctfcompetition.com}"
REMOTE_STAGING_DIR="/tmp/kernelctf_deploy"

echo "=== Deploying kernelCTF environment to: $TARGET_HOST ==="

# Check critical secrets and credentials
MISSING_SECRETS=0

if [ ! -f "secrets/server_secrets.py" ]; then
    echo "[-] ERROR: Missing critical secret file 'secrets/server_secrets.py'!"
    MISSING_SECRETS=1
fi

if [ ! -f "secrets/kernelctf-vm-reader-sa-key.json" ]; then
    echo "[-] ERROR: Missing critical GCS service account key 'secrets/kernelctf-vm-reader-sa-key.json'!"
    MISSING_SECRETS=1
fi

if [ $MISSING_SECRETS -ne 0 ]; then
    echo "[-] Deployment aborted: Please provide the missing secrets before deploying."
    exit 1
fi

# Optional certificate warning
if [ ! -f "secrets/server_cert_and_key.pem" ]; then
    echo "[!] WARNING: 'secrets/server_cert_and_key.pem' not found locally."
    echo "    A new TLS certificate will be generated automatically on the VM by infra/server_cert_gen.sh."
fi

# Collect directories and files for deployment
REQUIRED_ITEMS=(
    "server"
    "config"
    "tools"
    "infra"
    "secrets"
)

ITEMS_TO_SCP=()
for item in "${REQUIRED_ITEMS[@]}"; do
    if [ -e "$item" ]; then
        ITEMS_TO_SCP+=("$item")
    else
        echo "[-] ERROR: Required directory/file '$item' is missing!"
        exit 1
    fi
done

# Create staging directory on target host
echo "[+] Creating remote staging directory: $REMOTE_STAGING_DIR..."
ssh "$TARGET_HOST" "mkdir -p $REMOTE_STAGING_DIR"

# Transfer files and directories via scp in a single step
echo "[+] Copying deployment items to $TARGET_HOST:$REMOTE_STAGING_DIR/..."
scp -rp "${ITEMS_TO_SCP[@]}" "$TARGET_HOST:$REMOTE_STAGING_DIR/"

# Execute setup script remotely with sudo
echo "[+] Executing infra/setup.sh on $TARGET_HOST with sudo..."
ssh -t "$TARGET_HOST" "sudo bash $REMOTE_STAGING_DIR/infra/setup.sh"

# Cleanup remote staging directory
echo "[+] Cleaning up remote staging directory..."
ssh "$TARGET_HOST" "rm -rf $REMOTE_STAGING_DIR"

echo "=== Deployment to $TARGET_HOST completed successfully! ==="
