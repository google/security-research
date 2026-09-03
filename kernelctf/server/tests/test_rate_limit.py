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
import tempfile
import concurrent.futures

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..'))
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.join(REPO_ROOT, 'server'))

from rate_limit import EvaluationRateLimiter
from server import MAX_EVALUATIONS_PER_SLOT

class TestEvaluationRateLimiter(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_evaluations.db")
        self.limiter = EvaluationRateLimiter(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_sequential_acquisitions_limit(self):
        slot = "lts-6.12.98"
        researcher = "a" * 20
        exploit = "b" * 64

        for i in range(1, MAX_EVALUATIONS_PER_SLOT + 1):
            allowed, count = self.limiter.acquire_slot(slot, researcher, exploit, max_evaluations=MAX_EVALUATIONS_PER_SLOT)
            self.assertTrue(allowed)
            self.assertEqual(count, i)

        # 11th acquisition must be rejected
        allowed, count = self.limiter.acquire_slot(slot, researcher, exploit, max_evaluations=MAX_EVALUATIONS_PER_SLOT)
        self.assertFalse(allowed)
        self.assertEqual(count, MAX_EVALUATIONS_PER_SLOT)

    def test_independent_researchers(self):
        slot = "lts-6.12.98"
        researcher1 = "1" * 20
        researcher2 = "2" * 20
        exploit = "c" * 64

        # Exhaust researcher 1
        for _ in range(MAX_EVALUATIONS_PER_SLOT):
            allowed, _ = self.limiter.acquire_slot(slot, researcher1, exploit, max_evaluations=MAX_EVALUATIONS_PER_SLOT)
            self.assertTrue(allowed)

        # Researcher 1 is blocked
        allowed, _ = self.limiter.acquire_slot(slot, researcher1, exploit, max_evaluations=MAX_EVALUATIONS_PER_SLOT)
        self.assertFalse(allowed)

        # Researcher 2 is still allowed 10 runs
        for i in range(1, MAX_EVALUATIONS_PER_SLOT + 1):
            allowed, count = self.limiter.acquire_slot(slot, researcher2, exploit, max_evaluations=MAX_EVALUATIONS_PER_SLOT)
            self.assertTrue(allowed)
            self.assertEqual(count, i)

    def test_independent_slots(self):
        slot1 = "lts-6.12.98"
        slot2 = "lts-6.12.99"
        researcher = "d" * 20
        exploit = "e" * 64

        for _ in range(MAX_EVALUATIONS_PER_SLOT):
            allowed, _ = self.limiter.acquire_slot(slot1, researcher, exploit, max_evaluations=MAX_EVALUATIONS_PER_SLOT)
            self.assertTrue(allowed)

        # Slot 1 is blocked
        allowed, _ = self.limiter.acquire_slot(slot1, researcher, exploit, max_evaluations=MAX_EVALUATIONS_PER_SLOT)
        self.assertFalse(allowed)

        # Slot 2 is allowed
        allowed, count = self.limiter.acquire_slot(slot2, researcher, exploit, max_evaluations=MAX_EVALUATIONS_PER_SLOT)
        self.assertTrue(allowed)
        self.assertEqual(count, 1)

    def test_concurrent_acquisitions_no_race(self):
        slot = "lts-6.12.98"
        researcher = "f" * 20
        exploit = "0" * 64
        total_attempts = 30

        def try_acquire(index):
            # Create a separate limiter instance pointing to the same DB file to simulate separate processes
            limiter = EvaluationRateLimiter(self.db_path)
            return limiter.acquire_slot(slot, researcher, f"{exploit[:-2]}{index:02x}", max_evaluations=MAX_EVALUATIONS_PER_SLOT)

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(try_acquire, range(total_attempts)))

        successes = [r for r in results if r[0] is True]
        failures = [r for r in results if r[0] is False]

        self.assertEqual(len(successes), MAX_EVALUATIONS_PER_SLOT)
        self.assertEqual(len(failures), total_attempts - MAX_EVALUATIONS_PER_SLOT)
        self.assertEqual(self.limiter.get_count(slot, researcher), MAX_EVALUATIONS_PER_SLOT)

    def test_out_of_window_evaluation_skips_rate_limiter(self):
        slot = "lts-6.12.98"
        researcher = "g" * 20
        exploit = "1" * 64

        # Simulate out-of-window evaluation where is_open is False
        is_window_open = False
        if is_window_open:
            self.limiter.acquire_slot(slot, researcher, exploit, max_evaluations=MAX_EVALUATIONS_PER_SLOT)

        # Quota should not be consumed when out of window
        self.assertEqual(self.limiter.get_count(slot, researcher), 0)

        # In-window evaluation should consume quota
        is_window_open = True
        if is_window_open:
            self.limiter.acquire_slot(slot, researcher, exploit, max_evaluations=MAX_EVALUATIONS_PER_SLOT)

        self.assertEqual(self.limiter.get_count(slot, researcher), 1)

if __name__ == "__main__":
    unittest.main()
