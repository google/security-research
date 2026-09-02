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
import time
import re
import hmac
import hashlib

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..'))
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.join(REPO_ROOT, 'server'))
sys.path.insert(0, os.path.join(REPO_ROOT, 'secrets'))

from researcher_token import (
    derive_signing_key,
    generate_researcher_token,
    verify_researcher_token,
    RESEARCHER_TOKEN_KEY_DERIVATION_PURPOSE,
)
import server_secrets

FLAG_REGEX = re.compile(
    r"^kernelCTF\{(?P<data>v5:(?P<target>[^+:]+)\+(?P<lts>[^:]+):(?P<runId>[^:]+):(?P<attributes>[^:]+):(?P<timestamp>\d+):(?P<exploitHash>[0-9a-fA-F]{64}):(?P<researcherEmailHash>[0-9a-fA-F]{20})):(?P<sig>[0-9a-fA-F]+)\}$"
)

class TestResearcherToken(unittest.TestCase):
    def setUp(self):
        self.master_key = server_secrets.flag_key
        self.salt_prefix = server_secrets.researcher_token_salt_prefix
        self.signing_key = derive_signing_key(self.master_key)

    def test_key_derivation(self):
        expected = hmac.new(
            self.master_key.encode('utf-8'),
            RESEARCHER_TOKEN_KEY_DERIVATION_PURPOSE.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        self.assertEqual(self.signing_key, expected)
        self.assertEqual(len(self.signing_key), 64)

    def test_generate_and_verify_token(self):
        email = "researcher@example.com"
        token = generate_researcher_token(email, self.signing_key, self.salt_prefix)
        self.assertEqual(len(token), 40)
        self.assertTrue(re.fullmatch(r"^[0-9a-f]{40}$", token))

        # Check hash component
        salted_email = self.salt_prefix + email
        expected_hash20 = hashlib.sha256(salted_email.encode('utf-8')).hexdigest()[:20]
        self.assertEqual(token[:20], expected_hash20)

        # Check signature component
        expected_sig20 = hmac.new(
            self.signing_key.encode('utf-8'),
            expected_hash20.encode('utf-8'),
            hashlib.sha1
        ).hexdigest()[:20]
        self.assertEqual(token[20:], expected_sig20)

        # Verify token
        self.assertEqual(verify_researcher_token(token, self.master_key), expected_hash20)
        self.assertEqual(verify_researcher_token(token.upper(), self.master_key), expected_hash20)
        self.assertEqual(verify_researcher_token(f"  {token}  ", self.master_key), expected_hash20)

    def test_email_normalization(self):
        token1 = generate_researcher_token("Researcher@Example.Com ", self.signing_key, self.salt_prefix)
        token2 = generate_researcher_token("researcher@example.com", self.signing_key, self.salt_prefix)
        self.assertEqual(token1, token2)

    def test_empty_email_raises(self):
        with self.assertRaises(ValueError):
            generate_researcher_token("", self.signing_key, self.salt_prefix)
        with self.assertRaises(ValueError):
            generate_researcher_token("   ", self.signing_key, self.salt_prefix)

    def test_tampered_token_fails(self):
        token = generate_researcher_token("researcher@example.com", self.signing_key, self.salt_prefix)
        
        # Tamper with hash part
        tampered_hash = ('0' if token[0] != '0' else '1') + token[1:]
        with self.assertRaises(ValueError):
            verify_researcher_token(tampered_hash, self.master_key)

        # Tamper with sig part
        tampered_sig = token[:-1] + ('0' if token[-1] != '0' else '1')
        with self.assertRaises(ValueError):
            verify_researcher_token(tampered_sig, self.master_key)

    def test_invalid_formats_fail(self):
        for invalid_token in ["", "short", "a" * 39, "a" * 41, "z" * 40, "g" * 40]:
            with self.assertRaises(ValueError):
                verify_researcher_token(invalid_token, self.master_key)

    def test_wrong_master_key_fails(self):
        token = generate_researcher_token("researcher@example.com", self.signing_key, self.salt_prefix)
        with self.assertRaises(ValueError):
            verify_researcher_token(token, "wrong_master_key")

    def test_flag_regex_match(self):
        token = generate_researcher_token("researcher@example.com", self.signing_key, self.salt_prefix)
        researcher_email_hash = token[:20]
        target = "hardened-v1-7.2-rc5"
        lts = "lts-6.12.98"
        flag_id = "beef1234"
        run_results = ["1.2345", "0.9876", "-", "2.3400"]
        attributes = f"time={'/'.join(run_results)}"
        timestamp_ms = time.time_ns() // 1_000_000
        exploit_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        flag_content = f"v5:{target}+{lts}:{flag_id}:{attributes}:{timestamp_ms}:{exploit_hash}:{researcher_email_hash}"
        sig = hmac.new(self.master_key.encode('utf-8'), flag_content.encode('utf-8'), hashlib.sha1).hexdigest()
        flag = f"kernelCTF{{{flag_content}:{sig}}}"

        m = FLAG_REGEX.match(flag)
        self.assertIsNotNone(m)
        self.assertEqual(m.group("target"), target)
        self.assertEqual(m.group("lts"), lts)
        self.assertEqual(m.group("runId"), flag_id)
        self.assertEqual(m.group("attributes"), attributes)
        self.assertEqual(m.group("timestamp"), str(timestamp_ms))
        self.assertGreater(int(m.group("timestamp")), 1000000000000)  # ms timestamp check
        self.assertEqual(m.group("exploitHash"), exploit_hash)
        self.assertEqual(m.group("researcherEmailHash"), researcher_email_hash)
        self.assertEqual(len(m.group("researcherEmailHash")), 20)
        self.assertEqual(m.group("sig"), sig)

        # Verify signature over the full <data> group
        data = m.group("data")
        expected_sig = hmac.new(self.master_key.encode('utf-8'), data.encode('utf-8'), hashlib.sha1).hexdigest()
        self.assertEqual(expected_sig, m.group("sig"))

if __name__ == "__main__":
    unittest.main()
