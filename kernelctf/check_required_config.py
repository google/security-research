#!/usr/bin/env python3
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

            if line.startswith('###'):
                continue

            if not strict and line.startswith('#') and not line.startswith('# CONFIG_'):
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

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target.config> [required.config]")
        sys.exit(1)

    target_file = sys.argv[1]
    required_file = sys.argv[2] if len(sys.argv) > 2 else os.path.join(SCRIPT_DIR, "required.config")

    if not os.path.isfile(target_file):
        print(f"Error: Target config file '{target_file}' not found.")
        sys.exit(1)

    if not os.path.isfile(required_file):
        print(f"Error: Required configs file '{required_file}' not found.")
        sys.exit(1)

    print(f"Checking '{required_file}' against '{target_file}'...\n")

    required = parse_config(required_file, strict=True)
    target = parse_config(target_file, strict=False)

    all_ok = True
    for key, want in required.items():
        got = target.get(key, 'n') # Default missing target configs to 'n'
        if got == want:
            print(f"✅ [OK]   {key} = {got}")
        else:
            print(f"❌ [FAIL] {key}: expected '{want}', got '{got}'")
            all_ok = False

    print()
    if all_ok:
        print("🎉 All required configuration settings are satisfied!")
    else:
        print("⚠️  Some required configuration settings failed verification.")

    sys.exit(0 if all_ok else 1)

if __name__ == '__main__':
    main()
