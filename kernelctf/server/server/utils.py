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
import io
import sys
import time
import mmap
import select
import secrets
import hashlib
import subprocess

class ProcessStreamer:
    def __init__(self, proc, stream_stdout=True, start_pattern=None, end_pattern=None):
        self.proc = proc
        self.stream_stdout = stream_stdout
        self.output = ""
        self.start_pattern = start_pattern
        self.end_pattern = end_pattern
        self.start_time = None
        self.end_time = None

    def get_measured_time(self):
        if self.start_time is not None and self.end_time is not None:
            return self.end_time - self.start_time
        return None

    def _process_chunk(self, chunk):
        if not chunk:
            return
        if isinstance(chunk, bytes):
            chunk = chunk.decode("utf-8", errors="replace")
        now = time.time()
        self.output += chunk

        if self.start_pattern and self.start_time is None and self.start_pattern in self.output:
            self.start_time = now
        if self.end_pattern and self.end_time is None and self.end_pattern in self.output:
            self.end_time = now

        if self.stream_stdout:
            sys.stdout.write(chunk)
            sys.stdout.flush()

    def read_all(self, timeout=300):
        t0 = time.time()
        while True:
            if time.time() - t0 > timeout:
                self.proc.kill()
                raise subprocess.TimeoutExpired(self.proc.args, timeout)

            r, _, _ = select.select([self.proc.stdout], [], [], 0.1)
            if r:
                chunk = self.proc.stdout.read(1024)
                if not chunk:
                    break
                self._process_chunk(chunk)

            if self.proc.poll() is not None:
                remaining = self.proc.stdout.read()
                self._process_chunk(remaining)
                break

        return self.output


class BinaryMemFd:
    def __init__(self, prefix="exploit_binary"):
        self.name = f"{prefix}_{secrets.token_hex(8)}"
        self.fd = os.memfd_create(self.name, 0)
        self.length = 0
        self.mm = None
        self.view = None

    def __enter__(self):
        return self

    def read_from_fd(self, src_fd, length):
        self.length = length
        os.ftruncate(self.fd, length)
        self.mm = mmap.mmap(self.fd, length, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
        self.view = memoryview(self.mm)

        f_in = io.FileIO(src_fd, "r", closefd=False)
        offset = 0
        while offset < length:
            n = f_in.readinto(self.view[offset:])
            if not n:
                break
            offset += n

        if offset < length:
            raise IOError(f"Received {offset} bytes, expected {length} bytes.")

    def get_sha256(self):
        if not self.view:
            return None
        return hashlib.sha256(self.view).hexdigest()

    def cleanup(self):
        if self.view is not None:
            zero_chunk = b"\x00" * 4096
            for i in range(0, self.length, 4096):
                chunk_len = min(4096, self.length - i)
                self.view[i:i + chunk_len] = zero_chunk[:chunk_len]
            try:
                self.view.release()
            except Exception:
                pass
            self.view = None

        if self.mm is not None:
            try:
                self.mm.close()
            except Exception:
                pass
            self.mm = None

        if self.fd is not None:
            try:
                os.close(self.fd)
            except Exception:
                pass
            self.fd = None

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
