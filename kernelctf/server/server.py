#!/usr/bin/env -S python3 -u
import os
import re
import traceback
import tempfile
import sys
import hmac
import hashlib
import server_secrets
import time
import subprocess
import json
from datetime import datetime, timezone

RELEASES_YAML = 'releases.yaml'
SLOTS_JSON = 'slots.json'
DEPRECATED_TARGETS = ["cos-97", "cos-105", "cos-109"]
ALLOWED_CAPABILITIES = ["userns", "io_uring"]

sys.path.append('/usr/local/lib/python3.9/dist-packages')
from httplib2 import Http
import yaml

os.chdir(os.path.dirname(__file__))
isDevel = os.path.basename(__file__) == 'server_devel.py' or '--devel' in sys.argv
now = datetime.now(timezone.utc)
release_dir = './releases_new' if isDevel else './releases'

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
    with open(RELEASES_YAML, 'r') as f: releases = yaml.safe_load(f)

    target_latest = {}
    for release_id, release in list(releases.items()):
        if not os.path.exists(f'{release_dir}/{release_id}'):
            warning(f'release {release_id} not found in the {release_dir} folder')
            del releases[release_id]
            continue

        m = re.match(r'(?P<target>lts|mitigation(-v3|-v3b|-v4)?|cos-\d+)-(?P<version>\d+(\.\d+)+)', release_id)
        if m is None:
            warning(f'release {release_id} does not match regex')
            del releases[release_id]
            continue

        released = release['release-date'] <= now

        if release.get('available-until', now) < now:
            release['deprecated'] = True

        target = m.group('target')

        if released and not release.get('deprecated', False) and target not in DEPRECATED_TARGETS:
            if not target in target_latest or target_latest[target]['release-date'] < release['release-date']:
                target_latest[target] = release

        release['id'] = release_id
        release['released'] = released
        release['target'] = target

    for release in releases.values():
        release['latest'] = target_latest.get(release['target']) == release
        if not release['released']:
            release['status'] = 'future'
        elif release['latest']:
            release['status'] = 'latest'
        else:
            release['status'] = 'deprecated'

    return releases

def get_slots():
    if not os.path.isfile(SLOTS_JSON): return {}
    with open('slots.json', 'rt') as f: return json.load(f)

def print_releases(releases, slots, deprecated_only):
    def print_filtered(name, status_filter):
        filtered = [r for r in releases.values() if r['status'] == status_filter]
        if len(filtered) == 0: return

        print(f'{name}:')
        for release in filtered:
            taken = slots.get(release["id"])
            takenStr = f" | Slot is taken by {taken} (probably not eligible anymore)" if taken else ""
            availableStr = f" | Deprecation date: {release['available-until'].strftime('%Y-%m-%d %H:%M')}Z" if 'available-until' in release else ""
            print(f'  - {release["id"].ljust(24)}   | Release date: {release["release-date"].strftime("%Y-%m-%d %H:%M").ljust(12)}Z{takenStr}{availableStr}')
        print()

    if deprecated_only:
        print_filtered('Deprecated targets', 'deprecated')
    else:
        print_filtered('Current targets', 'latest')
        print_filtered('Future targets', 'future')    

def are_you_sure(prompt):
    print(prompt)
    res = input("Are you sure you want to continue? (y/n) ") == "y"
    print()
    return res

def main():
    releases = get_releases()
    slots = get_slots()

    print(f'Server time: {now.strftime("%Y-%m-%dT%H:%M:%S")}Z')
    print()

    show_deprecated = False
    while True:
        print_releases(releases, slots, show_deprecated)
        print('Select a target (or type "deprecated" to see deprecated targets):')
        release_id = input().strip()
        if release_id == "exit" or release_id == "q" or release_id == "quit":
            return

        print()

        if release_id == "deprecated":
            show_deprecated = True
            continue
        show_deprecated = False

        release = releases.get(release_id)
        if not release:
            print('Invalid target. Expected one of the followings: %s' % ', '.join(releases))
            print()
            continue

        while True:
            print('Actions:')
            print('  run) run target')
            print('  info) get information about the target')
            print('  back) back to the target list')
            print()
            action = input().strip()
            print()

            # long random generated secret, not bruteforcable
            root = '--root' in sys.argv or hashlib.sha1(action.encode('utf-8')).hexdigest() == server_secrets.root_mode_hash

            if action == 'back':
                break
            elif action == 'exit' or action == "q" or action == "quit":
                return
            elif action == 'info':
                baseUrl = 'https://storage.googleapis.com/kernelctf-build/releases'
                print(f'Kernel image (bzImage): {baseUrl}/{release_id}/bzImage')
                if release.get('vmlinux', True):
                    print(f'Kernel image (vmlinux): {baseUrl}/{release_id}/vmlinux.gz')
                print(f'Kernel config: {baseUrl}/{release_id}/.config')
                print(f'  -> derived from COS config: {baseUrl}/{release_id}/lakitu_defconfig')
                print(f'Source code info: {baseUrl}/{release_id}/COMMIT_INFO')
                print()
            elif root or action == 'run':
                capabilities_done = False
                while not capabilities_done:
                    print("Enter capabilities needed (comma-separated, or leave empty)")
                    print(f"options: {ALLOWED_CAPABILITIES}")
                    capabilities = input(": ").strip()
                    capabilities_done = True

                    capabilities = [capability.strip() for capability in capabilities.split(",")] if capabilities else []
                    capabilities = list(set(capabilities))

                    for capability in capabilities:
                        if capability not in ALLOWED_CAPABILITIES:
                            print(f"{capability} not in the available capabilities.")
                            capabilities_done = False

                flagPrefix = 'invalid:'
                if release['status'] == 'future':
                    print('[!] Warning: this target is not released yet and not eligible! Use only for pre-testing.')
                    answer = input('Do you want to run anyway (y/n) or wait until the slot opening (w) ')
                    if answer == 'y':
                        flagPrefix = 'future:'
                    elif answer == 'w':
                        prev_notification = 0
                        while True:
                            time_left = int((release['release-date'] - datetime.now(timezone.utc)).total_seconds())
                            if time_left <= 0:
                                flagPrefix = ''
                                break

                            if prev_notification != time_left:
                                print(f'Only {time_left} seconds left...')
                                prev_notification = time_left

                            time.sleep(0.05) # check 20 times per second, start as soon as possible
                    else:
                        continue
                elif release['status'] == 'deprecated' and "io_uring" in capabilities and now >= datetime(2025, 1, 23, 12, 00, 00, tzinfo=timezone.utc):
                    # you can target deprecated releases during the io_uring promotion
                    flagPrefix = ''
                elif release['status'] == 'deprecated':
                    flagPrefix = 'deprecated:'
                    if not are_you_sure('[!] Warning: this target is already deprecated and not eligible! Use only for reproduction.'):
                        continue
                elif release['status'] == 'latest':
                    flagPrefix = ''

                print('Executing target %s' % release_id)

                with tempfile.TemporaryDirectory() as temp_dir:
                    flag_fn = f'{temp_dir}/flag'
                    with open(flag_fn, 'wt') as f:
                        if len(capabilities) == 0:
                            flag_content = f'{flagPrefix}v1:{release_id}:{int(time.time())}'
                        else:
                            flag_content = f'{flagPrefix}v2:{release_id}:{",".join(capabilities)}:{int(time.time())}'
                        signature = hmac.new(server_secrets.flag_key.encode('utf-8'), flag_content.encode('utf-8'), hashlib.sha1).hexdigest()
                        flag = f'kernelCTF{{{flag_content}:{signature}}}'
                        f.write(flag + '\n')

                    subprocess.check_call(['./qemu.sh', f'{release_dir}/{release_id}', flag_fn, '/bin/bash' if root else '/home/user/run.sh', ",".join(capabilities)])
            else:
                print('Invalid action. Expected one of the followings: run, info, back')
                print()

try:
    main()
except EOFError:
    pass
except Exception as e:
    print('Something went wrong, please contact us on #kernelctf on Discord (https://discord.gg/A3qZcyaZ69).')
    traceback.print_exc()
    chat_msg('Server exception: ' + traceback.format_exc())

