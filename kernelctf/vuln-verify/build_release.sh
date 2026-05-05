#!/bin/bash
# Copyright 2025 Google LLC
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
set -eo pipefail

SCRIPT_DIR=$(dirname $(realpath "$0"))
LINUX_DIR="$SCRIPT_DIR/linux"

usage() {
    echo "Usage: $0 <repo_url> <commit_hash> <config_fn> <extra_config_fn> <patch_fn>";
    exit 1;
}

REPO_URL="$1"
COMMIT_HASH="$2"
CONFIG_FN=$(realpath "$3" 2>/dev/null || true)
EXTRA_CONFIG_FN=$(realpath "$4" 2>/dev/null || true)
PATCH_FN=$(realpath "$5" 2>/dev/null || true)

if [[ -z "$REPO_URL" || -z "$COMMIT_HASH" ]]; then usage; fi

mkdir -p "$LINUX_DIR" 2>/dev/null
cd "$LINUX_DIR"

git init
git remote remove origin 2>/dev/null || true
git remote add origin "$REPO_URL"

if [[ "$COMMIT_HASH" != $(git rev-parse HEAD) ]]; then
    git fetch --depth 1 origin "$COMMIT_HASH"
fi
git reset --hard FETCH_HEAD || true

cp "$CONFIG_FN" .config

if [ ! -z "$EXTRA_CONFIG_FN" ]; then
    cp "$EXTRA_CONFIG_FN" kernel/configs/
    make $(basename "$EXTRA_CONFIG_FN")
fi

if [ ! -z "$PATCH_FN" ]; then git apply -v "$PATCH_FN"; fi

make olddefconfig
make -j`nproc`
