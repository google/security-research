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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

REMOTE_TARGET=""
INSECURE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        -k|--insecure)
            INSECURE=1
            shift
            ;;
        --remote)
            if [[ -n "$2" && "$2" != -* ]]; then
                REMOTE_TARGET="$2"
                shift 2
            else
                REMOTE_TARGET="kernelctf.vrp.ctfcompetition.com:1337"
                shift
            fi
            ;;
        --remote=*)
            REMOTE_TARGET="${1#--remote=}"
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [HOST:PORT | --remote [HOST:PORT]] [-k | --insecure]"
            echo ""
            echo "Options:"
            echo "  HOST:PORT             Run tests against remote server at HOST:PORT"
            echo "  --remote [HOST:PORT]  Run tests against remote server (default: kernelctf.vrp.ctfcompetition.com:1337)"
            echo "  -k, --insecure        Ignore TLS/SSL certificate and hostname verification"
            echo "  -h, --help            Show this help message"
            echo ""
            echo "If no arguments are provided, tests run against a local server instance."
            exit 0
            ;;
        *)
            if [[ -z "$REMOTE_TARGET" && "$1" != -* ]]; then
                REMOTE_TARGET="$1"
                shift
            else
                echo "Unknown option: $1"
                exit 1
            fi
            ;;
    esac
done

if [ -n "$REMOTE_TARGET" ]; then
    REMOTE_ARGS=("--remote" "$REMOTE_TARGET")
    if [ $INSECURE -eq 1 ]; then
        REMOTE_ARGS+=("--insecure")
    fi
    echo "=== Running kernelCTF v5 Test Suite (Remote: $REMOTE_TARGET, Insecure: $INSECURE) ==="
else
    REMOTE_ARGS=("--local")
    echo "=== Running kernelCTF v5 Test Suite (Local Mode) ==="
fi

cd "$REPO_ROOT"

CLIENT_PY="$REPO_ROOT/client/cli.py"
EXPLOIT_SH="$SCRIPT_DIR/payloads/test_exploit.sh"
EXPLOIT_RANDOM_SH="$SCRIPT_DIR/payloads/test_exploit_random.sh"

# Test 0: Unit tests
echo ""
echo "--------------------------------------------------------"
echo "[Test 0/4] Running unit tests..."
echo "--------------------------------------------------------"
python3 -m unittest discover -s "$SCRIPT_DIR"

# Test 1: lpe-test with root (expect success)
echo ""
echo "--------------------------------------------------------"
echo "[Test 1/4] Running lpe-test (root mode)..."
echo "--------------------------------------------------------"
python3 "$CLIENT_PY" "$EXPLOIT_SH" --action lpe-test --root "${REMOTE_ARGS[@]}"

# Test 2: vuln-test with root (expect success via sysrq kernel panic)
echo ""
echo "--------------------------------------------------------"
echo "[Test 2/4] Running vuln-test (root mode, sysrq crash)..."
echo "--------------------------------------------------------"
python3 "$CLIENT_PY" "$EXPLOIT_SH" --action vuln-test --root "${REMOTE_ARGS[@]}"

# Test 3: vuln-test without root (verify fake panic spoofing is rejected)
echo ""
echo "--------------------------------------------------------"
echo "[Test 3/4] Running vuln-test (unprivileged user, fake panic prevention)..."
echo "--------------------------------------------------------"
set +e
OUT=$(python3 "$CLIENT_PY" "$EXPLOIT_SH" --action vuln-test "${REMOTE_ARGS[@]}" 2>&1)
EXIT_CODE=$?
set -e

if [[ $EXIT_CODE -ne 0 ]] && [[ "$OUT" =~ "NOT CRASHED" || "$OUT" =~ "Action 'vuln-test' did not succeed" ]]; then
    echo "[+] SUCCESS: Server correctly rejected fake panic from unprivileged userspace exploit!"
else
    echo "[-] FAILED: Server failed to reject unprivileged fake panic!"
    echo "$OUT"
    exit 1
fi

# Test 4: evaluate with root and --ignore-open-slots using test_exploit_random.sh
echo ""
echo "--------------------------------------------------------"
echo "[Test 4/4] Running evaluate (root mode, random flaky runs, --ignore-open-slots, flag generation)..."
echo "--------------------------------------------------------"
TEST_RESEARCHER_TOKEN="${RESEARCHER_TOKEN:-$(python3 -c "import sys, os; sys.path.insert(0, '$REPO_ROOT/secrets'); sys.path.insert(0, '$REPO_ROOT/server'); import server_secrets, researcher_token; print(researcher_token.generate_researcher_token('test@kernelctf.org', researcher_token.derive_signing_key(server_secrets.flag_key), server_secrets.researcher_token_salt_prefix))")}"
python3 "$CLIENT_PY" "$EXPLOIT_RANDOM_SH" --action evaluate --root --ignore-open-slots --researcher-token "$TEST_RESEARCHER_TOKEN" "${REMOTE_ARGS[@]}"

echo ""
echo "========================================================"
echo "[+] All kernelCTF v5 tests passed successfully!"
echo "========================================================"
