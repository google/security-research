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
echo "Starting kernelCTF Service..."

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." &> /dev/null && pwd)
cd "$REPO_ROOT"

exec socat -dd ssl-l:1337,reuseaddr,fork,cert="$REPO_ROOT/secrets/server_cert_and_key.pem",verify=0,openssl-min-proto-version=tls1.3 exec:"/usr/bin/timeout 3600 python3 -u $SCRIPT_DIR/server.py"
