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

SECRETS_DIR="$REPO_ROOT/secrets"
CLIENT_DIR="$REPO_ROOT/client"
mkdir -p "$SECRETS_DIR" "$CLIENT_DIR"

openssl req -newkey ed25519 -nodes -keyout "$SECRETS_DIR/server_key.pem" -x509 -days 3650 -subj '/CN=kernelctf.vrp.ctfcompetition.com/' -out "$CLIENT_DIR/server_cert.pem"
cat "$SECRETS_DIR/server_key.pem" "$CLIENT_DIR/server_cert.pem" > "$SECRETS_DIR/server_cert_and_key.pem"
chmod 600 "$SECRETS_DIR/server_key.pem" "$SECRETS_DIR/server_cert_and_key.pem"
chmod 644 "$CLIENT_DIR/server_cert.pem"
