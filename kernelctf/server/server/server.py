#!/usr/bin/env -S python3 -u
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

import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
import traceback
from datetime import datetime, timezone
from httplib2 import Http
import yaml

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..'))
sys.path.insert(0, os.path.join(REPO_ROOT, 'secrets'))

import server_secrets
from utils import ProcessStreamer, BinaryMemFd
from researcher_token import verify_researcher_token
from rate_limit import EvaluationRateLimiter
from slot_window import SlotWindow

try:
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass

RELEASES_YAML = os.path.join(REPO_ROOT, 'config', 'releases.yaml')
DATA_DIR = os.path.join(REPO_ROOT, 'data')
EVALUATIONS_DB = os.path.join(DATA_DIR, 'evaluations.db')
RELEASES_DIR = os.path.join(DATA_DIR, 'releases')
STAGING_DIR = os.path.join(DATA_DIR, 'staging')

TIMEOUT = 300
EXPLOIT_CMD = '/exploit'
IGNORE_OPEN_SLOTS = '--ignore-open-slots' in sys.argv
HARDENED_TARGET = "hardened-v1-7.2-rc5"
EVAL_RUNS = 20
VULN_TRIGGER_RUNS = 3
MAX_EVALUATIONS_PER_SLOT = 10

isDevel = os.path.basename(__file__) == 'server_devel.py' or '--devel' in sys.argv
now = datetime.now(timezone.utc)

def get_release_path(target):
    staging_path = os.path.join(STAGING_DIR, target)
    if isDevel and os.path.exists(staging_path):
        return staging_path
    releases_path = os.path.join(RELEASES_DIR, target)
    if os.path.exists(releases_path):
        return releases_path
    return staging_path

def chat_msg(msg, mention=False):
    if mention:
        msg = '<users/all> ' + msg

    if isDevel:
        print('chat_msg: ' + msg)
        return

    Http().request(uri=server_secrets.webhook_url, method='POST', headers={'Content-Type': 'application/json; charset=UTF-8'}, body=json.dumps({'text': msg}))

def warning(msg):
    if isDevel:
        print(f'[WARNING] {msg}')

def get_releases():
    with open(RELEASES_YAML, 'r') as f:
        all_releases = yaml.safe_load(f)

    lts_entries = []
    for rel_id, rel_data in all_releases.items():
        if re.match(r'^lts-\d+(\.\d+)+$', rel_id) and 'release-date' in rel_data:
            lts_entries.append((rel_id, rel_data))

    if not lts_entries:
        raise Exception("No LTS release found in config/releases.yaml")

    lts_entries.sort(key=lambda x: x[1]['release-date'], reverse=True)
    lts_id, latest_lts_data = lts_entries[0]
    release_date = latest_lts_data['release-date']
    targets = [HARDENED_TARGET, lts_id, f"{lts_id}-kasan"]

    for target in targets:
        target_path = get_release_path(target)
        if not os.path.exists(target_path):
            warning(f'release {target} not found in {target_path}')

    return targets, lts_id, release_date


def is_kernel_crashed(dmesg_output):
    if not dmesg_output:
        return False
    crash_patterns = [
        r"Kernel panic",
        r"BUG: KASAN:",
    ]
    for pattern in crash_patterns:
        if re.search(pattern, dmesg_output, re.IGNORECASE):
            return True
    return False

def sign_flag(flag_content):
    signature = hmac.new(server_secrets.flag_key.encode('utf-8'), flag_content.encode('utf-8'), hashlib.sha1).hexdigest()
    return f'kernelCTF{{{flag_content}:{signature}}}'

def run_exploit_qemu(release_id, flag_text, init_cmd, memfd_fd=None, stream_stdout=True, flag_to_match=None, as_root=False):
    pass_fds = ()
    if memfd_fd is not None:
        os.lseek(memfd_fd, 0, os.SEEK_SET)
        memfd_path = f"/proc/self/fd/{memfd_fd}"
        pass_fds = (memfd_fd,)

    with tempfile.TemporaryDirectory() as temp_dir:
        flag_fn = f'{temp_dir}/flag'
        dmesg_fn = f'{temp_dir}/dmesg.log'
        with open(flag_fn, 'wt') as f:
            f.write(flag_text)

        try:
            cmd = [os.path.join(SCRIPT_DIR, 'qemu.sh'), get_release_path(release_id), flag_fn, init_cmd]
            cmd.append(memfd_path if memfd_fd is not None else "")
            cmd.append(dmesg_fn)
            if as_root:
                cmd.append("--as-root")
            if isDevel:
                cmd.append("--ignore-ibt")

            proc = subprocess.Popen(cmd, pass_fds=pass_fds, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)

            if stream_stdout:
                print("--- VM Output Begin ---")

            streamer = ProcessStreamer(proc, stream_stdout=stream_stdout, start_pattern="COMMAND-BEGIN", end_pattern=flag_to_match)
            output = streamer.read_all(timeout=TIMEOUT)
            measured = streamer.get_measured_time()

            dmesg = ""
            if os.path.exists(dmesg_fn):
                with open(dmesg_fn, 'rt', errors='replace') as f:
                    dmesg = f.read()

            return measured, output, dmesg
        finally:
            if stream_stdout:
                print("--- VM Output End ---")

def read_line(prompt=""):
    if prompt:
        sys.stdout.write(prompt)
        sys.stdout.flush()
    line = b""
    while not line.endswith(b"\n"):
        ch = os.read(sys.stdin.fileno(), 1)
        if not ch:
            break
        line += ch
    return line.decode("utf-8", errors="replace").rstrip('\r\n')

def receive_binary_to_memfd(memfd):
    length_str = read_line("Binary length: ").strip()
    if not length_str.isdigit():
        print("Invalid binary length.")
        return None

    length = int(length_str)
    if length <= 0 or length > 50 * 1024 * 1024:
        print("Binary size exceeds maximum allowed limit (50MB).")
        return None

    expected_hash = read_line("SHA256 hash: ").strip().lower()
    if not re.match(r"^[0-9a-f]{64}$", expected_hash):
        print("Invalid SHA256 hash format.")
        return None

    print(f"Streaming {length} bytes...")
    try:
        memfd.read_from_fd(sys.stdin.fileno(), length)
        actual_hash = memfd.get_sha256()
        if actual_hash != expected_hash:
            print(f"Integrity check failed: expected {expected_hash}, got {actual_hash}.")
            return None
        print("Binary payload loaded into memfd successfully.")
        return actual_hash
    except Exception as e:
        print(f"Error receiving binary data: {e}")
        return None

def run_exploit_session(runner_fn):
    with BinaryMemFd("exploit_binary") as memfd:
        binary_hash = receive_binary_to_memfd(memfd)
        if binary_hash is None:
            return False

        os.set_inheritable(memfd.fd, True)
        return runner_fn(memfd, binary_hash)

def lpe_test_action(root):
    def _execute(memfd, binary_hash):
        print(f'Executing target {HARDENED_TARGET} with binary')
        flag_content = secrets.token_hex(16)
        flag_text = f"kernelCTF{{{flag_content}}}\n"
        flag_to_match = flag_content
        try:
            elapsed, output, dmesg = run_exploit_qemu(
                HARDENED_TARGET, flag_text, f"/cmd_wrapper.sh {EXPLOIT_CMD}", memfd.fd, stream_stdout=True, flag_to_match=flag_to_match, as_root=root
            )
            print()
            if flag_to_match in output:
                print(f"[+] Flag leak successful on {HARDENED_TARGET}!")
            else:
                print(f"[-] Flag leak failed on {HARDENED_TARGET} (flag not found in output).")
        except subprocess.TimeoutExpired:
            print(f"Execution timed out after {TIMEOUT} seconds.")
        except Exception as e:
            print(f"Execution error: {e}")
        return True

    return run_exploit_session(_execute)

def vuln_test_action(lts_id, root):
    def _execute_trigger(memfd, binary_hash):
        init_cmd = f"/cmd_wrapper.sh {EXPLOIT_CMD} --vuln-trigger"
        results = {}

        targets_to_run = [f"{lts_id}-kasan", lts_id]
        for target in targets_to_run:
            print(f"\nExecuting vuln trigger on {target}...")
            try:
                elapsed, output, dmesg = run_exploit_qemu(
                    target, "dummy_flag\n", init_cmd, memfd.fd, stream_stdout=True, as_root=root
                )
                if dmesg.strip():
                    print("--- Kernel dmesg Begin ---")
                    print(dmesg.strip())
                    print("--- Kernel dmesg End ---")

                crashed = is_kernel_crashed(dmesg)
                results[target] = "CRASHED" if crashed else "NOT CRASHED"
            except subprocess.TimeoutExpired:
                print(f"Execution on {target} timed out after {TIMEOUT} seconds.")
                results[target] = "TIMEOUT (NOT CRASHED)"
            except Exception as e:
                print(f"Execution error on {target}: {e}")
                results[target] = f"ERROR ({e})"

        print("\n=== Vuln Trigger Execution Results ===")
        for target, status in results.items():
            print(f"  - {target}: {status}")
        print()

        any_crashed = any(status == "CRASHED" for status in results.values())
        if any_crashed:
            print("[+] Vuln trigger execution succeeded (kernel crash detected)!")
        else:
            print("[-] Vuln trigger execution finished without kernel crash.")
        return True

    return run_exploit_session(_execute_trigger)

def evaluate_action(lts_id, release_date, root):
    slot_window = SlotWindow(release_date, ignore_open_slots=IGNORE_OPEN_SLOTS)
    if not slot_window.prompt_if_out_of_window(read_line):
        return False

    show_output_input = read_line("Show VM output during evaluation? (y/n) ").strip().lower()
    show_vm_output = show_output_input in ('y', 'yes')

    researcher_token = read_line("Researcher token: ").strip().lower()
    try:
        researcher_email_hash = verify_researcher_token(researcher_token, server_secrets.flag_key)
    except ValueError as e:
        print(f"Invalid researcher token: {e}. Get a new one via https://forms.gle/Dd8pk7AXW843eDGP6")
        return False

    rate_limiter = EvaluationRateLimiter(EVALUATIONS_DB)

    def _evaluate(memfd, binary_hash):
        slot_window.wait_if_needed()

        if slot_window.is_open():
            allowed, attempts_used = rate_limiter.acquire_slot(
                lts_id, researcher_email_hash, binary_hash, max_evaluations=MAX_EVALUATIONS_PER_SLOT
            )
            if not allowed:
                print(f"\n[-] Evaluation quota exceeded: You have already used {MAX_EVALUATIONS_PER_SLOT}/{MAX_EVALUATIONS_PER_SLOT} evaluation runs for slot '{lts_id}'.")
                return True

            print(f"\n[+] Evaluation run {attempts_used}/{MAX_EVALUATIONS_PER_SLOT} registered for slot '{lts_id}'.")

        flag_id = secrets.token_hex(4)
        run_results = []
        success_count = 0

        # Phase 1: Vulnerability trigger check on KASAN / non-KASAN
        print("\n--- Phase 1: Evaluating vulnerability trigger on LTS targets ---")
        crashed_target = None
        lts_targets = [f"{lts_id}-kasan", lts_id]

        for target in lts_targets:
            print(f"Testing target: {target} (up to {VULN_TRIGGER_RUNS} runs)...")
            for run_idx in range(1, VULN_TRIGGER_RUNS + 1):
                print(f"--- {target} Run {run_idx}/{VULN_TRIGGER_RUNS} ---")
                try:
                    elapsed, output, dmesg = run_exploit_qemu(
                        target, "dummy_flag\n", f"/cmd_wrapper.sh {EXPLOIT_CMD} --vuln-trigger", memfd.fd, stream_stdout=show_vm_output, as_root=root
                    )
                    if is_kernel_crashed(dmesg):
                        crashed_target = target
                        print(f"Run {run_idx} CRASH DETECTED on {target}!")
                        break
                    else:
                        print(f"Run {run_idx} did not crash.")
                except subprocess.TimeoutExpired:
                    print(f"Run {run_idx} TIMEOUT")
                except Exception as e:
                    print(f"Run {run_idx} ERROR: {e}")

            if crashed_target:
                break

        if not crashed_target:
            print(f"\nEvaluation failed: Vulnerability trigger failed to crash LTS / LTS-KASAN kernels (0 crashes in {VULN_TRIGGER_RUNS} runs each).")
            return True

        print(f"\nPhase 1 succeeded (crash confirmed on {crashed_target}).")

        # Phase 2: Hardened target evaluation (EVAL_RUNS runs)
        print(f"\n--- Phase 2: Evaluating exploit on {HARDENED_TARGET} ({EVAL_RUNS} runs) ---")
        for run_idx in range(1, EVAL_RUNS + 1):
            flag_content = secrets.token_hex(16)
            print(f"--- Hardened Run {run_idx}/{EVAL_RUNS} ---")
            try:
                elapsed, output, dmesg = run_exploit_qemu(
                    HARDENED_TARGET, f"kernelCTF{{{flag_content}}}\n", f"/cmd_wrapper.sh {EXPLOIT_CMD}", memfd.fd, stream_stdout=show_vm_output, flag_to_match=flag_content, as_root=root
                )
                if flag_content in output:
                    run_results.append(f"{elapsed:.4f}")
                    success_count += 1
                    print(f"Run {run_idx} SUCCESS ({elapsed:.4f}s)")
                else:
                    run_results.append("-")
                    print(f"Run {run_idx} FAILED (flag not found in output)")
            except subprocess.TimeoutExpired:
                run_results.append("-")
                print(f"Run {run_idx} TIMEOUT")
            except Exception as e:
                run_results.append("-")
                print(f"Run {run_idx} ERROR: {e}")

        if success_count == 0:
            print(f"\nEvaluation failed (0/{EVAL_RUNS} runs succeeded on hardened target).")
            return True

        print(f"\nPhase 2 succeeded ({success_count}/{EVAL_RUNS} runs on {HARDENED_TARGET}).")

        # Phase 3: Overall result & Flag Generation
        print(f"\nEvaluation succeeded (crash verified on {crashed_target}, {success_count}/{EVAL_RUNS} hardened runs)!")
        if slot_window.is_open():
            times_attr = "/".join(run_results)
            attributes = f"time={times_attr}"
            timestamp = time.time_ns() // 1_000_000
            flag_content = f"v5:{HARDENED_TARGET}+{lts_id}:{flag_id}:{attributes}:{timestamp}:{binary_hash}:{researcher_email_hash}"
            flag = sign_flag(flag_content)
            print(f"Flag: {flag}")
        else:
            print("[!] No flag created: Evaluation was run outside of the valid submission window.")
        return True

    return run_exploit_session(_evaluate)

def info_action(targets):
    baseUrl = 'https://storage.googleapis.com/kernelctf-build/releases'
    for target in targets:
        print(f'Target: {target}')
        print(f'  Kernel image (bzImage): {baseUrl}/{target}/bzImage')
        print(f'  Kernel image (vmlinux): {baseUrl}/{target}/vmlinux.gz')
        print(f'  Kernel config: {baseUrl}/{target}/.config')
        print(f'  Derived from COS config: {baseUrl}/{target}/lakitu_defconfig')
        print(f'  Source code info: {baseUrl}/{target}/COMMIT_INFO')
        print()

def print_targets_and_menu(targets):
    print(f'Active targets: {", ".join(targets)}')
    print()
    print('Actions:')
    print('  lpe-test) execute exploit in hardened target (expect flag leak)')
    print('  vuln-test) execute vuln trigger in LTS / LTS-KASAN targets (expect kernel crash)')
    print('  evaluate) evaluate exploit in all targets')
    print('  info) get information about the targets')
    print('  exit) exit')
    print()

def main():
    root = '--root' in sys.argv
    targets, lts_id, release_date = get_releases()

    print(f'Server time: {now.strftime("%Y-%m-%dT%H:%M:%S")}Z')
    print()

    while True:
        if root:
            print('WARNING: Running in root mode!\n')
        print_targets_and_menu(targets)
        action = read_line().strip()
        print()

        is_secret_root = hashlib.sha1(action.encode('utf-8')).hexdigest() == server_secrets.root_mode_hash
        if is_secret_root:
            root = True
            continue

        if action in ("exit", "q", "quit"):
            return
        elif action == "info":
            info_action(targets)
        elif action == "lpe-test":
            lpe_test_action(root)
        elif action == "vuln-test":
            vuln_test_action(lts_id, root)
        elif action == "evaluate":
            evaluate_action(lts_id, release_date, root)
        else:
            print("Invalid action. Expected one of: lpe-test, vuln-test, evaluate, info, exit\n")

if __name__ == '__main__':
    try:
        main()
    except EOFError:
        pass
    except Exception as e:
        print('Something went wrong, please contact us on #kernelctf on Discord (https://discord.gg/A3qZcyaZ69).')
        traceback.print_exc()
        chat_msg('Server exception: ' + traceback.format_exc())

