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
from unittest.mock import patch

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..'))
sys.path.insert(0, os.path.join(REPO_ROOT, 'server'))

from slot_window import SlotWindow

class TestSlotWindow(unittest.TestCase):
    def test_calculate_window_wednesday_release(self):
        # Wednesday release -> Next Monday 12:00 UTC to Friday 12:00 UTC
        release_date = datetime(2026, 8, 26, 12, 0, 0, tzinfo=timezone.utc)
        window = SlotWindow(release_date)
        
        expected_start = datetime(2026, 8, 31, 12, 0, 0, tzinfo=timezone.utc)
        expected_end = datetime(2026, 9, 4, 12, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(window.start, expected_start)
        self.assertEqual(window.end, expected_end)

    def test_calculate_window_iso_string(self):
        release_str = "2026-08-26T12:00:00Z"
        window = SlotWindow(release_str)
        self.assertEqual(window.start, datetime(2026, 8, 31, 12, 0, 0, tzinfo=timezone.utc))
        self.assertEqual(window.end, datetime(2026, 9, 4, 12, 0, 0, tzinfo=timezone.utc))

    def test_is_open_and_bounds(self):
        release_date = datetime(2026, 8, 26, 12, 0, 0, tzinfo=timezone.utc)
        window = SlotWindow(release_date)

        before = datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)
        during = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
        after = datetime(2026, 9, 5, 12, 0, 0, tzinfo=timezone.utc)

        self.assertTrue(window.is_before(before))
        self.assertFalse(window.is_open(before))
        self.assertFalse(window.is_after(before))

        self.assertFalse(window.is_before(during))
        self.assertTrue(window.is_open(during))
        self.assertFalse(window.is_after(during))

        self.assertFalse(window.is_before(after))
        self.assertFalse(window.is_open(after))
        self.assertTrue(window.is_after(after))

    def test_ignore_open_slots(self):
        release_date = datetime(2026, 8, 26, 12, 0, 0, tzinfo=timezone.utc)
        window = SlotWindow(release_date, ignore_open_slots=True)
        before = datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)
        self.assertTrue(window.is_open(before))

    def test_prompt_before_window_wait(self):
        release_date = datetime(2026, 8, 26, 12, 0, 0, tzinfo=timezone.utc)
        window = SlotWindow(release_date)
        before = datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)

        with patch("slot_window.datetime") as mock_dt:
            mock_dt.now.return_value = before
            mock_dt.fromisoformat = datetime.fromisoformat
            mock_dt.side_effect = lambda *args, **kwargs: datetime(*args, **kwargs)

            # Test answering 'w'
            res = window.prompt_if_out_of_window(lambda prompt="": "w")
            self.assertTrue(res)
            self.assertTrue(window.wait_for_slot)

            # Test answering 'y'
            res = window.prompt_if_out_of_window(lambda prompt="": "y")
            self.assertTrue(res)
            self.assertFalse(window.wait_for_slot)

            # Test answering 'n'
            res = window.prompt_if_out_of_window(lambda prompt="": "n")
            self.assertFalse(res)

    def test_prompt_after_window(self):
        release_date = datetime(2026, 8, 26, 12, 0, 0, tzinfo=timezone.utc)
        window = SlotWindow(release_date)
        after = datetime(2026, 9, 6, 12, 0, 0, tzinfo=timezone.utc)

        with patch("slot_window.datetime") as mock_dt:
            mock_dt.now.return_value = after
            mock_dt.fromisoformat = datetime.fromisoformat
            mock_dt.side_effect = lambda *args, **kwargs: datetime(*args, **kwargs)

            # Test answering 'y'
            res = window.prompt_if_out_of_window(lambda prompt="": "y")
            self.assertTrue(res)

            # Test answering 'n'
            res = window.prompt_if_out_of_window(lambda prompt="": "n")
            self.assertFalse(res)

    def test_wait_if_needed(self):
        release_date = datetime(2026, 8, 26, 12, 0, 0, tzinfo=timezone.utc)
        window = SlotWindow(release_date)
        window.wait_for_slot = True
        
        # When current time is past start, wait_if_needed should complete immediately
        with patch("slot_window.datetime") as mock_dt:
            mock_dt.now.return_value = window.start + timedelta(seconds=1)
            window.wait_if_needed()

    def test_wait_if_needed_subsecond_precision(self):
        release_date = datetime(2026, 8, 26, 12, 0, 0, tzinfo=timezone.utc)
        window = SlotWindow(release_date)
        window.wait_for_slot = True

        call_count = 0
        times = [
            window.start - timedelta(milliseconds=400), # 0.4s left (ceil=1, not open)
            window.start + timedelta(milliseconds=10),  # open
        ]

        def fake_now(tz=None):
            nonlocal call_count
            t = times[min(call_count, len(times) - 1)]
            call_count += 1
            return t

        with patch("slot_window.datetime") as mock_dt, patch("slot_window.time.sleep") as mock_sleep:
            mock_dt.now.side_effect = fake_now
            window.wait_if_needed()
            self.assertGreaterEqual(call_count, 2)
            mock_sleep.assert_called()

if __name__ == "__main__":
    unittest.main()
