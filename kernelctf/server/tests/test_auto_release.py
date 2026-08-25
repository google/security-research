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
import unittest
from datetime import datetime, timezone, timedelta

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..'))
sys.path.insert(0, REPO_ROOT)

from tools.auto_release import kernelctf_release

class TestAutoReleaseCron(unittest.TestCase):
    MONDAY = datetime(2026, 4, 6, 12, 0, 0, tzinfo=timezone.utc)
    TUESDAY = MONDAY + timedelta(days=1)
    WEDNESDAY = MONDAY + timedelta(days=2)
    THURSDAY = MONDAY + timedelta(days=3)
    SLOT_MONDAY = MONDAY + timedelta(days=7)
    SLOT_FRIDAY = SLOT_MONDAY + timedelta(days=4)

    def assertNoop(self, schedules, check_date):
        called = False
        def dummy(*args, **kwargs):
            nonlocal called
            called = True
            raise Exception("Should not be called")

        deps = {
            "get_kernelctf_releases": dummy,
            "activate_releases": dummy,
            "download_release": dummy,
            "discord_msg": dummy,
            "get_scheduled_releases": dummy,
            "add_new_releases": dummy,
            "chat_msg": dummy
        }

        success = kernelctf_release(schedules, check_date, deps)
        self.assertFalse(success)
        self.assertFalse(called)

    def test_full_release_lifecycle(self):
        schedules = []
        messages = []
        discord_messages = []
        added_yaml = []
        downloads = []

        def get_kernelctf_releases():
            return ["lts-6.12.74", "lts-6.12.74-kasan"]

        def activate_releases(auto_confirm, *args, **kwargs):
            return True, "There were no errors."

        def discord_msg(msg):
            discord_messages.append(msg)
        
        def add_new_releases(yaml_dict):
            added_yaml.extend(yaml_dict.values())

        def chat_msg(msg):
            messages.append(msg)

        def download_release(rel):
            downloads.append(rel)

        deps = {
            "get_kernelctf_releases": get_kernelctf_releases,
            "activate_releases": activate_releases,
            "download_release": download_release,
            "discord_msg": discord_msg,
            "get_scheduled_releases": lambda: "",
            "add_new_releases": add_new_releases,
            "chat_msg": chat_msg
        }

        # Step 1: Monday - release preparation, yaml added, discord message prepared
        success_mon = kernelctf_release(schedules, self.MONDAY, deps)
        self.assertTrue(success_mon)
        self.assertEqual(len(downloads), 2)
        self.assertIn("lts-6.12.74", downloads)
        self.assertIn("lts-6.12.74-kasan", downloads)
        self.assertEqual(len(schedules), 1)
        self.assertTrue(schedules[0]["downloaded"])
        self.assertFalse(schedules[0]["activated"])
        self.assertEqual(len(messages), 1)
        self.assertIn("Releases are ready", messages[0])
        self.assertEqual(len(added_yaml), 1)
        self.assertIn("lts-6.12.74", added_yaml[0])
        self.assertIn("2026-04-08T12:00:00Z", added_yaml[0])

        slot_mon_str = self.SLOT_MONDAY.strftime('%Y-%m-%dT12:00:00Z')
        slot_fri_str = self.SLOT_FRIDAY.strftime('%Y-%m-%dT12:00:00Z')
        self.assertIn("lts-6.12.74", schedules[0]["discord_msg"])
        self.assertIn(slot_mon_str, schedules[0]["discord_msg"])
        self.assertIn(slot_fri_str, schedules[0]["discord_msg"])
        # Discord message not yet sent on Monday
        self.assertEqual(len(discord_messages), 0)

        # Step 2: Tuesday - noop
        self.assertNoop(schedules, self.TUESDAY)

        # Step 3: Wednesday - activation and sending prepared discord announcement
        success_wed = kernelctf_release(schedules, self.WEDNESDAY, deps)
        self.assertTrue(success_wed)
        self.assertTrue(schedules[0]["activated"])
        self.assertEqual(len(discord_messages), 1)
        self.assertIn("lts-6.12.74", discord_messages[0])
        self.assertIn(slot_mon_str, discord_messages[0])
        self.assertIn(slot_fri_str, discord_messages[0])

        # Step 4: Thursday - noop
        self.assertNoop(schedules, self.THURSDAY)

    def test_monday_prep_no_new_releases(self):
        schedules = []
        failed = False

        def get_kernelctf_releases():
            return ["lts-6.12.50"]

        def fail(*args, **kwargs):
            nonlocal failed
            failed = True
            raise Exception("Should not be called")

        deps = {
            "get_kernelctf_releases": get_kernelctf_releases,
            "activate_releases": fail,
            "download_release": fail,
            "discord_msg": fail,
            "get_scheduled_releases": lambda: "lts-6.12.50:\n  release-date: 2026-03-20T12:00:00Z",
            "add_new_releases": fail,
            "chat_msg": fail
        }

        success = kernelctf_release(schedules, self.MONDAY, deps)
        self.assertFalse(success)
        self.assertFalse(failed)

if __name__ == "__main__":
    unittest.main()
