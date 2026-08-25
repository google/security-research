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

"""
check_required_config.py

Verifies that required kernel config settings (specified in required.config or a given file)
are satisfied in a target .config file.
"""

import sys
import os
import re

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def parse_config(filepath, strict=False):
    config = {}
    with open(filepath, 'r') as f:
        for line_num, raw_line in enumerate(f, 1):
            line = raw_line.strip()
            if not line:
                continue

            # Skip comment lines (lines starting with #, but not # CONFIG_...)
            if line.startswith('#') and not re.match(r'^#\s*CONFIG_\w+', line):
                continue

            # Disabled: # CONFIG_FOO is not set  OR  CONFIG_FOO=n
            m_off = re.match(r'^(?:#\s*(CONFIG_\w+)\s+is not set|(CONFIG_\w+)=n)$', line)
            if m_off:
                cfg = m_off.group(1) or m_off.group(2)
                config[cfg] = 'n'
                continue

            # Enabled / set: CONFIG_FOO=y / m / "str" / 123
            m_on = re.match(r'^(CONFIG_\w+)=(.*)$', line)
            if m_on:
                config[m_on.group(1)] = m_on.group(2)
                continue

            if strict:
                print(f"Error: Cannot interpret line {line_num} in '{filepath}': '{line}'")
                sys.exit(1)

    return config


def check_config(target_file, required_file, verbose=True):
    if not os.path.isfile(target_file):
        raise FileNotFoundError(f"Target config file '{target_file}' not found.")
    if not os.path.isfile(required_file):
        raise FileNotFoundError(f"Required configs file '{required_file}' not found.")

    if verbose:
        print(f"Checking '{required_file}' against '{target_file}'...\n")

    required = parse_config(required_file, strict=True)
    target = parse_config(target_file, strict=False)

    all_ok = True
    errors = []
    for key, want in required.items():
        if key not in target:
            msg = f"{key}: unknown option (not found in target config, expected '{want}')"
            errors.append(msg)
            if verbose:
                print(f"❌ [FAIL] {msg}")
            all_ok = False
            continue
        got = target[key]
        if got == want:
            if verbose:
                print(f"✅ [OK]   {key} = {got}")
        else:
            msg = f"{key}: expected '{want}', got '{got}'"
            errors.append(msg)
            if verbose:
                print(f"❌ [FAIL] {msg}")
            all_ok = False

    if verbose:
        print()
        if all_ok:
            print("🎉 All required configuration settings are satisfied!")
        else:
            print("⚠️  Some required configuration settings failed verification.")

    return all_ok, errors


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target.config> [required.config]")
        sys.exit(1)

    target_file = sys.argv[1]
    required_file = sys.argv[2] if len(sys.argv) > 2 else os.path.join(SCRIPT_DIR, "kernel_configs", "required.config")

    all_ok, _ = check_config(target_file, required_file, verbose=True)
    sys.exit(0 if all_ok else 1)


if __name__ == '__main__':
    main()
