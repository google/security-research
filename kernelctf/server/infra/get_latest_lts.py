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
import re
import sys
import yaml

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..'))
RELEASES_YAML = os.path.join(REPO_ROOT, 'config', 'releases.yaml')

def get_latest_lts(yaml_path=RELEASES_YAML):
    if not os.path.exists(yaml_path):
        sys.exit(f"Error: {yaml_path} does not exist")

    with open(yaml_path, 'r') as f:
        releases = yaml.safe_load(f) or {}

    lts_entries = []
    for rel_id, rel_data in releases.items():
        if re.match(r'^lts-\d+(\.\d+)+$', rel_id) and isinstance(rel_data, dict) and 'release-date' in rel_data:
            lts_entries.append((rel_id, rel_data))

    if not lts_entries:
        sys.exit("Error: No valid LTS release found in config/releases.yaml")

    lts_entries.sort(key=lambda x: x[1]['release-date'], reverse=True)
    return lts_entries[0][0]

if __name__ == '__main__':
    yaml_path = sys.argv[1] if len(sys.argv) > 1 else RELEASES_YAML
    print(get_latest_lts(yaml_path))
