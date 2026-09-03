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

import math
import time
from datetime import datetime, timezone, timedelta

class SlotWindow:
    def __init__(self, release_date, ignore_open_slots=False):
        self.release_date = release_date
        self.ignore_open_slots = ignore_open_slots
        self.start, self.end = self.calculate_window(release_date)
        self.wait_for_slot = False

    @staticmethod
    def calculate_window(release_date):
        if isinstance(release_date, str):
            release_date = datetime.fromisoformat(release_date.replace("Z", "+00:00"))
        if release_date.tzinfo is None:
            release_date = release_date.replace(tzinfo=timezone.utc)

        # Window starts on next Monday at 12:00 UTC after the release date and ends on Friday at 12:00 UTC
        days_until_monday = (7 - release_date.weekday()) % 7
        window_start = (release_date + timedelta(days=days_until_monday)).replace(
            hour=12, minute=0, second=0, microsecond=0
        )
        if window_start < release_date:
            window_start += timedelta(days=7)
        window_end = window_start + timedelta(days=4)
        return window_start, window_end

    def is_open(self, now=None):
        if self.ignore_open_slots:
            return True
        current_utc = now or datetime.now(timezone.utc)
        return self.start <= current_utc <= self.end

    def is_before(self, now=None):
        current_utc = now or datetime.now(timezone.utc)
        return current_utc < self.start

    def is_after(self, now=None):
        current_utc = now or datetime.now(timezone.utc)
        return current_utc > self.end

    def prompt_if_out_of_window(self, read_line_fn=input):
        current_utc = datetime.now(timezone.utc)
        if self.is_open(current_utc):
            return True

        is_before = self.is_before(current_utc)
        print(f"[!] Warning: Current time ({current_utc.strftime('%Y-%m-%d %H:%M:%S')} UTC) is {'before' if is_before else 'after'} the evaluation submission window:")
        print(f"    Window: {self.start.strftime('%Y-%m-%d %H:%M:%S')} UTC to {self.end.strftime('%Y-%m-%d %H:%M:%S')} UTC")
        print("[!] If evaluation succeeds, NO flag will be created or given to you.")

        prompt = f"Do you want to continue anyway (y/n){' or wait until the slot opening (w)' if is_before else ''}? "
        answer = read_line_fn(prompt).strip().lower()
        print()

        if is_before and answer in ('w', 'wait'):
            self.wait_for_slot = True
            return True
        elif answer in ('y', 'yes'):
            self.wait_for_slot = False
            return True

        print("Evaluation cancelled.")
        return False

    def wait_if_needed(self):
        if not self.wait_for_slot:
            return

        prev_notification = -1
        print(f"Waiting for slot opening at {self.start.strftime('%Y-%m-%d %H:%M:%S')} UTC...")
        while True:
            remaining = (self.start - datetime.now(timezone.utc)).total_seconds()
            if remaining <= 0:
                print("\n[+] Submission window is now open! Starting evaluation...")
                break

            time_left = int(math.ceil(remaining))
            if prev_notification != time_left:
                print(f"Only {time_left} seconds left...")
                prev_notification = time_left

            time.sleep(min(1.0, max(0.0, remaining)))
