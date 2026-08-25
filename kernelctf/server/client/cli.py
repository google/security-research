#!/usr/bin/env python3
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

import os
import sys
import time
import argparse
import hashlib
import subprocess
import select
import re

def gray(text):
    return f"\033[90m{text}\033[0m"

def green(text):
    return f"\033[92m{text}\033[0m"

def red(text):
    return f"\033[91m{text}\033[0m"

def cprint(text):
    for line in str(text).split("\n"):
        print(f"[Client] {line}" if line else "")

class ColorWriter:
    def __init__(self):
        self.pending = ""

    def write(self, text):
        self.pending += text
        lines = self.pending.split("\n")
        for line in lines[:-1]:
            sys.stdout.write(self.format_line(line) + "\n")
        self.pending = lines[-1]
        sys.stdout.flush()

    def flush(self):
        if self.pending:
            sys.stdout.write(self.format_line(self.pending))
            sys.stdout.flush()
            self.pending = ""

    def format_line(self, line):
        if re.search(r"\b(fail|failed|CRASHED|ERROR)\b", line, re.IGNORECASE):
            return red(line)
        elif re.search(r"\b(success|succeeded|SUCCESS)\b", line, re.IGNORECASE):
            return green(line)
        else:
            return gray(line)

class ServerSession:
    def __init__(self, proc, writer=None):
        self.proc = proc
        self.writer = writer or ColorWriter()
        self.buffer = ""

    def read_chunk(self, timeout=0.1):
        if self.proc.poll() is not None:
            return None
        r, _, _ = select.select([self.proc.stdout], [], [], timeout)
        if r:
            chunk = os.read(self.proc.stdout.fileno(), 1024)
            if not chunk:
                return None
            text = chunk.decode("utf-8", errors="replace")
            self.buffer += text
            self.writer.write(text)
            return text
        return ""

    def read_until(self, prompt_substrings, timeout=60):
        start_time = time.time()
        while time.time() - start_time < timeout:
            for prompt in prompt_substrings:
                idx = self.buffer.find(prompt)
                if idx != -1:
                    self.buffer = self.buffer[idx + len(prompt):]
                    self.writer.flush()
                    return prompt
            res = self.read_chunk(0.1)
            if res is None:
                break
        self.writer.flush()
        return None

    def send_line(self, line):
        self.proc.stdin.write((line + "\n").encode("utf-8"))
        self.proc.stdin.flush()

    def send_bytes(self, data):
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def read_until_completion(self, start_marker, timeout=300):
        start_time = time.time()
        flag = None
        started = False
        while time.time() - start_time < timeout:
            res = self.read_chunk(0.2)
            if res is None:
                break

            if start_marker and start_marker in self.buffer:
                started = True

            match = re.search(r"Flag:\s*(kernelCTF\{[^}]+\})", self.buffer)
            if match:
                flag = match.group(1)

            # Check if execution finished and menu prompt returned
            if started and ("Actions:" in self.buffer or "Invalid action" in self.buffer):
                break

        self.writer.flush()
        return flag

    def close(self):
        if self.proc.poll() is None:
            try:
                self.send_line("exit")
                self.proc.wait(timeout=3)
            except Exception:
                pass
            if self.proc.poll() is None:
                try:
                    self.proc.kill()
                except Exception:
                    pass

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))

def main():
    parser = argparse.ArgumentParser(description="kernelCTF CLI Client")
    parser.add_argument("binary", type=str, nargs="?", default=None, help="Path to exploit binary (required for evaluate, lpe-test, vuln-test)")
    parser.add_argument("-a", "--action", type=str, required=True, choices=["evaluate", "lpe-test", "vuln-test", "info"], help="Action to execute")
    parser.add_argument("--remote", type=str, default="kernelctf.vrp.ctfcompetition.com:1337", help="Remote server [HOST:PORT] (default: kernelctf.vrp.ctfcompetition.com:1337)")
    parser.add_argument("--local", action="store_true", help="Connect to local server instance instead of remote")
    parser.add_argument("--root", action="store_true", default=False, help="Run server in root mode (for testing, default: False)")
    parser.add_argument("--show-vm-output", action=argparse.BooleanOptionalAction, default=True, help="Show VM output during evaluation (default: True)")
    parser.add_argument("--ignore-open-slots", action="store_true", help="Override submission window check and generate flag on evaluation")
    parser.add_argument("--server-path", type=str, default=None, help="Path to local server.py executable (when using --local)")
    parser.add_argument("-k", "--insecure", action="store_true", help="Ignore TLS/SSL certificate and hostname verification")
    args = parser.parse_args()

    root_secret = None
    root_secret_path = os.path.join(REPO_ROOT, "tests", "root_secret.txt")
    if os.path.exists(root_secret_path):
        with open(root_secret_path, "r", encoding="utf-8") as f:
            root_secret = f.read().strip()

    binary_data = b""
    length = 0
    sha256_hash = ""

    if args.action != "info":
        if not args.binary:
            parser.error(f"the following arguments are required: binary (for action '{args.action}')")

        binary_path = args.binary
        if not os.path.isabs(binary_path):
            candidate = os.path.join(REPO_ROOT, binary_path)
            if os.path.exists(candidate):
                binary_path = candidate

        if not os.path.exists(binary_path):
            print(f"Error: Exploit binary not found: {args.binary}")
            sys.exit(1)

        with open(binary_path, "rb") as f:
            binary_data = f.read()

        length = len(binary_data)
        sha256_hash = hashlib.sha256(binary_data).hexdigest()

        print(f"Loaded binary: {binary_path}")
        print(f"  Length: {length} bytes")
        print(f"  SHA256: {sha256_hash}")

    if not args.local:
        target = args.remote
        if ":" not in target:
            target = f"{target}:1337"

        host = target.split(":", 1)[0]
        ca_cert = os.path.join(REPO_ROOT, "client", "server_cert.pem")
        ssl_params = [f"ssl:{target}"]
        if args.insecure or host in ("127.0.0.1", "localhost", "::1"):
            ssl_params.append("verify=0")
        else:
            ssl_params.append(f"cafile={ca_cert}")

        cmd = ["socat", "-", ",".join(ssl_params)]
        print(f"Connecting to remote server via socat ({' '.join(cmd)})...")
        server_dir = None
    else:
        server_bin = args.server_path or os.path.join(REPO_ROOT, "server", "server.py")
        if not os.path.exists(server_bin):
            print(f"Error: server binary not found at {server_bin}")
            sys.exit(1)

        server_dir = os.path.dirname(os.path.abspath(server_bin))
        cmd = [sys.executable, "-u", server_bin, "--devel"]
        if args.root and not root_secret:
            cmd.append("--root")
        if args.ignore_open_slots:
            cmd.append("--ignore-open-slots")
        print(f"Connecting to local server ({' '.join(cmd)})...")

    proc = subprocess.Popen(
        cmd,
        cwd=server_dir if not args.remote else None,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0
    )

    session = ServerSession(proc)

    # Step 1: Wait for Actions menu
    matched = session.read_until(["Actions:"])
    if not matched:
        cprint("Failed to receive Actions menu from server.")
        session.close()
        sys.exit(1)

    if args.root and root_secret:
        cprint("Enabling root mode on server via secret...")
        session.send_line(root_secret)
        matched = session.read_until(["Actions:"])
        if not matched:
            cprint("Failed to receive Actions menu after enabling root mode.")
            session.close()
            sys.exit(1)

    cprint(f"\nSelecting action: {args.action}")
    session.send_line(args.action)

    if args.action == "info":
        session.read_until(["Actions:"])
        session.close()
        cprint("Done.")
        sys.exit(0)

    # Step 2: Handle evaluate window warning / show vm output prompts
    if args.action == "evaluate":
        prompt = session.read_until(["Do you want to continue anyway? (y/n)", "Show VM output during evaluation? (y/n)"])
        if prompt and "Do you want to continue anyway" in prompt:
            cprint("Responding 'y' to out-of-window warning...")
            session.send_line("y")
            session.read_until(["Show VM output during evaluation? (y/n)"])

        show_output_ans = "y" if args.show_vm_output else "n"
        cprint(f"Show VM output during evaluation: {show_output_ans}")
        session.send_line(show_output_ans)

    # Step 3: Wait for Binary length prompt
    matched = session.read_until(["Binary length:"])
    if not matched:
        cprint("Failed to reach Binary length prompt.")
        session.close()
        sys.exit(1)

    cprint(f"Sending binary length: {length}")
    session.send_line(str(length))

    # Step 4: Wait for SHA256 prompt
    session.read_until(["SHA256 hash:"])
    cprint(f"Sending SHA256 hash: {sha256_hash}")
    session.send_line(sha256_hash)

    # Step 5: Send binary data
    cprint("Sending binary data...")
    session.send_bytes(binary_data)
    session.buffer = ""

    # Step 6: Stream output until execution completes
    start_marker = "Executing" if args.action != "evaluate" else "Evaluating"
    flag = session.read_until_completion(start_marker)

    success = False
    output_text = session.buffer
    if args.action == "lpe-test":
        success = "[+] Flag leak successful" in output_text
    elif args.action == "vuln-test":
        success = "[+] Vuln trigger execution succeeded" in output_text
    elif args.action == "evaluate":
        success = "Evaluation succeeded" in output_text
        if args.ignore_open_slots and not flag:
            cprint(red("Evaluation completed but no flag was captured despite --ignore-open-slots."))
            success = False

    if session.proc.poll() is None:
        cprint("\nAction completed. Disconnecting...")
        session.close()

    cprint("Done.")
    if flag:
        print(f"\nCaptured Flag:\n{green(flag)}")

    if not success:
        cprint(red(f"Action '{args.action}' did not succeed."))
        sys.exit(1)

if __name__ == "__main__":
    main()
