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

import json
import os
import re
import subprocess
import sys
import traceback
from datetime import datetime, timedelta, timezone
from httplib2 import Http
import requests
import yaml

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..'))
sys.path.insert(0, os.path.join(REPO_ROOT, 'secrets'))

import server_secrets

STATE_FILE = os.path.join(REPO_ROOT, 'config', 'auto_release.yaml')
RELEASES_YAML = os.path.join(REPO_ROOT, 'config', 'releases.yaml')
SA_KEY_FILE = os.path.join(REPO_ROOT, 'secrets', 'kernelctf-vm-reader-sa-key.json')
DATA_DIR = os.path.join(REPO_ROOT, 'data')
STAGING_DIR = os.path.join(DATA_DIR, 'staging')
RELEASES_DIR = os.path.join(DATA_DIR, 'releases')
TARGETS = ["lts-6.12"]
DEVEL = "--devel" in sys.argv

def chat_msg(msg):
    print(f"Sending Google Chat message: {msg}")
    if DEVEL or not hasattr(server_secrets, 'webhook_url'):
        return

    Http().request(
        uri=server_secrets.webhook_url, 
        method='POST', 
        headers={'Content-Type': 'application/json; charset=UTF-8'}, 
        body=json.dumps({'text': msg})
    )

def discord_msg(msg):
    if DEVEL or not hasattr(server_secrets, 'discord_webhook_url'):
        return
    print(f"Sending Discord message: {msg}")
    requests.post(server_secrets.discord_webhook_url, json={"content": msg})

def run(*args, **kwargs):
    try:
        return subprocess.run(text=True, capture_output=True, check=True, *args, **kwargs)
    except subprocess.CalledProcessError as e:
        raise Exception(f"Command {e.cmd} failed with exit code {e.returncode}:\n{e.stdout}\n{e.stderr}") from None

def get_kernelctf_releases():
    if os.path.exists(SA_KEY_FILE):
        run(["gcloud", "auth", "activate-service-account", f"--key-file={SA_KEY_FILE}"])
    res = run(["gsutil", "ls", "gs://kernelctf-build/releases/"]).stdout
    return [os.path.basename(line.rstrip('/')) for line in res.splitlines()]

def activate_releases(auto_confirm, filter_releases=None):
    activate_script = os.path.join(SCRIPT_DIR, "activate_releases.py")
    cmd = [sys.executable, "-u", activate_script]
    if filter_releases:
        cmd.extend(["--releases", ",".join(filter_releases)])
    res = run(cmd, input="y\n" if auto_confirm else "n\n").stdout
    return ("There were no errors." in res or "Done." in res), res

def download_release(rel):
    target_dir = os.path.join(STAGING_DIR, rel)
    os.makedirs(target_dir, exist_ok=True)
    run(["gsutil", "rsync", "-rx", ".*vmlinux.gz|.*dbgsym.*", f"gs://kernelctf-build/releases/{rel}", target_dir])

def get_scheduled_releases():
    if os.path.exists(RELEASES_YAML):
        with open(RELEASES_YAML, "r") as f:
            return f.read()
    return ""

def add_new_releases(yaml_dict):
    content = get_scheduled_releases()
    yaml_dict = { k: v for k, v in yaml_dict.items() if k not in content }
    if not yaml_dict: return
    with open(RELEASES_YAML, "w") as f:
        f.write("\n".join(yaml_dict.values()) + "\n\n" + content)

def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'r') as f:
            return yaml.safe_load(f) or []
    return []

def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, 'w') as f:
        yaml.dump(state, f, default_flow_style=False, sort_keys=False)

def get_next_prep_monday(schedules, now):
    if not schedules:
        prep_date = datetime(2026, 4, 6, 12, 0, 0, tzinfo=timezone.utc)
    else:
        prep_date = datetime.fromisoformat(schedules[-1]['prepare-date'].replace('Z', '+00:00'))

    while (now - prep_date).total_seconds() >= 14 * 24 * 3600:
        prep_date += timedelta(days=14)

    return prep_date

def version_tuple(v):
    try:
        parts = v.split('-', 1)[1].split('.')
        return tuple(int(x) for x in parts if x.isdigit())
    except Exception:
        return (0,)

def fmt_date(dt):
    return dt.strftime('%Y-%m-%dT12:00:00Z')

def kernelctf_release(schedules, now, deps):
    get_kernelctf_releases = deps["get_kernelctf_releases"]
    activate_releases = deps["activate_releases"]
    download_release = deps["download_release"]
    discord_msg = deps["discord_msg"]
    get_scheduled_releases = deps["get_scheduled_releases"]
    add_new_releases = deps["add_new_releases"]
    chat_msg = deps["chat_msg"]

    prep_monday = get_next_prep_monday(schedules, now)
    activate_wednesday = prep_monday + timedelta(days=2)
    slot_monday = prep_monday + timedelta(days=7)
    slot_friday = slot_monday + timedelta(days=4)

    has_entry = False
    for s in schedules:
        prep_date = datetime.fromisoformat(s['prepare-date'].replace('Z', '+00:00'))
        if abs((prep_date - prep_monday).total_seconds()) < 24 * 3600 * 13:
            has_entry = True
            break

    if not has_entry:
        new_entry = {
            "prepare-date": fmt_date(prep_monday),
            "release-date": fmt_date(activate_wednesday),
            "slot-start": fmt_date(slot_monday),
            "slot-end": fmt_date(slot_friday),
            "downloaded": False,
            "activated": False,
            "releases": [],
            "discord_msg": ""
        }
        schedules.append(new_entry)

    current_entry = None
    for s in schedules:
        if s['prepare-date'] == fmt_date(prep_monday):
            current_entry = s
            break

    if not current_entry:
        return True

    # STEP 1: Week 1 Monday - release preparation process
    if now >= prep_monday and not current_entry.get("downloaded"):
        print(f"[{fmt_date(now)}] Initiating Monday release preparation...")
        try:
            found = get_kernelctf_releases()
            print(f"Retrieved {len(found)} kernelCTF releases from GCS")
            found_names = []
            scheduled = get_scheduled_releases()

            for target in TARGETS:
                matches = [path for path in found if re.search(rf"({target}[0-9.]+)$", path)]
                if not matches:
                    continue
                
                latest = sorted([os.path.basename(p) for p in matches], key=version_tuple, reverse=True)[0]
                if latest not in scheduled:
                    found_names.append(latest)

            if not found_names:
                print("No new releases to prepare.")
                return False

            print(f"Determined latest release versions for tracking: {found_names}")

            # Write new release configurations to releases.yaml on Monday
            yaml_append = {}
            for release in found_names:
                yaml_append[release] = f"{release}:\n  release-date: {fmt_date(activate_wednesday)}"

            for release_name in found_names:
                print(f"Downloading target release: {release_name}")
                download_release(release_name)
                kasan_name = f"{release_name}-kasan"
                print(f"Downloading target release: {kasan_name}")
                download_release(kasan_name)

            print("Writing new release configurations to releases.yaml:\n" + '\n'.join(yaml_append.values()))
            add_new_releases(yaml_append)

            print("Executing dry-run activation pre-check...")
            success, out = activate_releases(False, found_names)
            if success:
                print("Pre-check successful. Preparing Discord notification.")
                releases_formatted = ", ".join(f"`{r}`" for r in found_names)
                msg = (
                    f"Hey! We are releasing target(s): {releases_formatted}. "
                    f"The evaluation slot opens next Monday (`{fmt_date(slot_monday)}`) and closes on Friday (`{fmt_date(slot_friday)}`)."
                )
                chat_msg(f"Releases are ready. Will activate the releases and send this Discord message on Wednesday ({fmt_date(activate_wednesday)}):\n{msg}")
                
                current_entry["downloaded"] = True
                current_entry["releases"] = found_names
                current_entry["discord_msg"] = msg
                return True
            else:
                chat_msg(f"Release preparation error:\n{out}")
                return False
        except Exception as e:
            chat_msg(f"Release preparation exception: {traceback.format_exc()}")
            return False

    # STEP 2: Week 1 Wednesday - activate releases and send prepared Discord announcement
    if current_entry.get("downloaded") and not current_entry.get("activated"):
        if now >= activate_wednesday:
            print(f"[{fmt_date(now)}] Wednesday activation target reached. Activating releases...")
            try:
                releases_to_activate = current_entry.get("releases", [])
                if not releases_to_activate and "discord_msg" in current_entry:
                    filters = re.findall(r"`([^`]+)`", current_entry["discord_msg"])
                    releases_to_activate = [f for f in filters if not f.startswith("20")]

                success, out = activate_releases(True, releases_to_activate)
                if success:
                    print("Releases activated successfully. Sending Discord notification announcement.")
                    discord_msg(current_entry["discord_msg"])
                    current_entry["activated"] = True
                    return True
                else:
                    chat_msg(f"Release activation error:\n{out}")
                    return False
            except Exception as e:
                chat_msg(f"Release activation exception: {traceback.format_exc()}")
                return False

    print(f"[{fmt_date(now)}] Nothing to do. Exiting...")
    return False

def main():
    os.chdir(REPO_ROOT)
    deps = {
        "get_kernelctf_releases": get_kernelctf_releases,
        "activate_releases": activate_releases,
        "download_release": download_release,
        "discord_msg": discord_msg,
        "get_scheduled_releases": get_scheduled_releases,
        "add_new_releases": add_new_releases,
        "chat_msg": chat_msg
    }
    
    now = datetime.now(timezone.utc)
    schedules = load_state()
    
    changed = kernelctf_release(schedules, now, deps)
    if changed:
        save_state(schedules)

if __name__ == "__main__":
    main()
