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

import argparse
import os
import shutil
import sys
import requests
import yaml

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..'))

sys.path.insert(0, SCRIPT_DIR)
from check_required_config import check_config

RELEASES_YAML = os.path.join(REPO_ROOT, 'config', 'releases.yaml')
DATA_DIR = os.path.join(REPO_ROOT, 'data')
STAGING_DIR = os.path.join(DATA_DIR, 'staging')
RELEASES_DIR = os.path.join(DATA_DIR, 'releases')
CONFIGS_DIR = os.path.join(SCRIPT_DIR, 'kernel_configs')

with open(RELEASES_YAML, 'r') as f:
    releases = yaml.safe_load(f)

parser = argparse.ArgumentParser()
parser.add_argument("--releases", type=str, help="Comma separated list of releases to activate")
args, _ = parser.parse_known_args()

new_releases = []
if args.releases:
    for release_id in args.releases.split(','):
        if release_id not in releases:
            print(f"Error: Target release ID {release_id} not found in config/releases.yaml")
            exit(1)
        new_releases.append(release_id)
else:
    for release_id, release in releases.items():
        if os.path.isdir(os.path.join(RELEASES_DIR, release_id)):
            print(f"Release already found, skipping: {release_id}")
            continue
        new_releases.append(release_id)

def versiontuple(v):
    return tuple(map(int, (v.split("."))))

def get_required_config(release_id):
    if release_id.startswith('hardened-'):
        return "hardened-v1.config"
    base_version = release_id.replace("lts-", "").split("-")[0]
    if release_id.startswith('lts-') and versiontuple(base_version) >= versiontuple("6.12.104"):
        return "lts-6.12-v2.config"
    return None

fail = False
for release_id in new_releases:
    release = releases[release_id]
    cfg_file = os.path.join(STAGING_DIR, release_id, ".config")
    if not os.path.exists(cfg_file):
        print(f"Error: config file {cfg_file} not found")
        fail = True
        continue

    req_config = get_required_config(release_id)
    if req_config:
        print(f"Verifying {release_id} config against {req_config}...")
        ok, errors = check_config(cfg_file, os.path.join(CONFIGS_DIR, req_config), verbose=True)
        if not ok:
            print(f"config check fail for {release_id}: {errors}")
            fail = True
    else:
        with open(cfg_file, 'rt') as f:
            config = f.readlines()

        base_version = release_id.replace("lts-", "").split("-")[0]
        checks = []
        if release_id.startswith('lts-'):
            if versiontuple(base_version) >= versiontuple("6.6.64"):
                checks.append("CONFIG_IO_URING=y")
            else:
                checks.append("# CONFIG_IO_URING is not set")
        elif release_id.startswith('cos-'):
            checks.append("CONFIG_IO_URING=y")
        elif release_id.startswith('mitigation-'):
            if release_id != 'mitigation-6.1-broken':
                checks.append("CONFIG_KMALLOC_SPLIT_VARSIZE=y")
            checks.append("CONFIG_SLAB_VIRTUAL=y")

        for check in checks:
            if not check + "\n" in config:
                print(f'config check fail: {release_id} does not have the config: "{check}"')
                fail = True

for release_id in new_releases:
    release = releases[release_id]
    baseUrl = f'https://storage.googleapis.com/kernelctf-build/releases/{release_id}/'
    files = ['bzImage', '.config', 'lakitu_defconfig', 'COMMIT_INFO']
    if release.get('vmlinux', True):
        files.append('vmlinux.gz')

    for file in files:
        result = requests.head(baseUrl + file)
        print(f'{release_id}/{file}: {result.status_code}')
        if result.status_code != 200:
            print("ERROR!")
            fail = True

if fail:
    print("There were errors. Stopping release.")
    exit(1)

if len(new_releases) == 0:
    print("Nothing to release. Exiting.")
    exit(2)

if input(f"There were no errors. Ready to release the following: {', '.join(new_releases)}. Go? (y/n) ") != "y":
    print("ok. aborting.")
    exit(0)

print("Release!")
os.makedirs(RELEASES_DIR, exist_ok=True)
for release_id in new_releases:
    src_path = os.path.join(STAGING_DIR, release_id)
    dst_path = os.path.join(RELEASES_DIR, release_id)
    print(f"Copying {src_path} -> {dst_path}")
    shutil.copytree(src_path, dst_path)
print("Done.")
