#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import socket
from pwn import *

def handle_pow(r):
    print(r.recvuntil(b'python3 '))
    print(r.recvuntil(b' solve '))
    challenge = r.recvline().decode('ascii').strip()
    p = process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    r.sendline(solution)
    print(r.recvuntil(b'Correct\n'))

r = remote('127.0.0.1', 1337)
print(r.recvuntil(b'== proof-of-work: '))
if r.recvline().startswith(b'enabled'):
    handle_pow(r)

l = listen()
l2 = listen()

r.readuntil(b'URL to open.', timeout=10)
r.sendline(bytes('http://localhost:{}/ok'.format(l.lport), 'ascii'))

_ = l.wait_for_connection()

print(l.readuntil(b'GET /ok HTTP/1.1'))
content = f"<script>fetch('http://localhost:{l2.lport}/foo')</script>"
response = f'HTTP/1.1 200 OK\nContent-Length: {len(content)}\n\n{content}'
l.send(response.encode())

_ = l2.wait_for_connection()
print(l2.readuntil(b'GET /foo HTTP/1.1'))

exit(0)
