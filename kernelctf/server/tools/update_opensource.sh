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

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." &> /dev/null && pwd)
OSS_DIR="$REPO_ROOT/../../security-research/kernelctf/server"

pushd "$OSS_DIR"

git checkout master
git pull

SYNC_DIRS=("client" "config" "docs" "infra" "server" "tests" "tools")

# Synchronize each directory (excluding local build caches, logs, and private test tokens)
for dir in "${SYNC_DIRS[@]}"; do
    if [ -d "$REPO_ROOT/$dir" ]; then
        echo "Syncing directory: $dir/ -> $OSS_DIR/$dir/"
        mkdir -p "$OSS_DIR/$dir"
        rsync -av --delete \
            --exclude='__pycache__' \
            --exclude='*.pyc' \
            --exclude='*secret*' \
            "$REPO_ROOT/$dir/" "$OSS_DIR/$dir/"
    fi
done

# Sync secrets example templates
mkdir -p "$OSS_DIR/secrets"
cp "$REPO_ROOT"/secrets/*.example "$OSS_DIR/secrets/"

# Sync top-level project documentation
cp "$REPO_ROOT/README.md" "$OSS_DIR/README.md"

git add *
git diff --cached
git commit -m "kernelCTF: server: update to latest version" || true

echo ""
echo "===================================================================================="
echo "do a git push and then an exit if you are ready, you will push the following changes"
echo "===================================================================================="
echo ""
git diff origin/master master
echo "===================================================================================="

bash
