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

if [ $# -lt 3 ]; then
  echo "Usage: $0 <release_path> <flag_fn> <init> [<exploit_fn>] [<stdout_file>] [--as-root] [--ignore-ibt]"
  exit 1
fi

RELEASE_PATH=$1
FLAG_FN=$2
INIT=$3
EXPLOIT_FN=$4
STDOUT_FILE=$5
RELEASE=$(basename "$RELEASE_PATH")

IMAGE_RUNNER_DIR="$(dirname "$0")/vm"

RUNNER_ARGS=()
if [[ -n "$FLAG_FN" ]]; then RUNNER_ARGS+=("--mount=$FLAG_FN:/flag:unmap"); fi
if [[ -n "$EXPLOIT_FN" ]]; then RUNNER_ARGS+=("--mount=$EXPLOIT_FN:/exploit:unmap,copy"); fi
if [[ -n "$STDOUT_FILE" ]]; then RUNNER_ARGS+=("--stdout-file=$STDOUT_FILE"); fi
if [[ -f "$RELEASE_PATH/modules.img" ]]; then RUNNER_ARGS+=("--modules-path=$RELEASE_PATH/modules.img"); fi

EXTRA_KERNEL_ARGS=""
if [[ "$IGNORE_IBT" == "1" ]]; then
  EXTRA_KERNEL_ARGS+=" IGNORE_IBT=1"
fi

for arg in "$@"; do
  if [[ "$arg" == "--as-root" ]]; then RUNNER_ARGS+=("--as-root"); fi
  if [[ "$arg" == "--ignore-ibt" ]]; then EXTRA_KERNEL_ARGS+=" IGNORE_IBT=1"; fi
done

exec "$IMAGE_RUNNER_DIR/run_vmlinuz.sh" "$RELEASE_PATH/bzImage" \
  "${RUNNER_ARGS[@]}" \
  --kernel-args="hostname=$RELEASE$EXTRA_KERNEL_ARGS" \
  -- $INIT
