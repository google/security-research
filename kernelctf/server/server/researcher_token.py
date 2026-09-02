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

import hashlib
import hmac
import re

RESEARCHER_TOKEN_KEY_DERIVATION_PURPOSE = "kernelctf_researcher_token_signing_key"

def derive_signing_key(master_key: str) -> str:
    """
    Derives a dedicated researcher token signing key from the master flag signing key
    using HMAC-SHA256 with domain separation.
    """
    return hmac.new(
        master_key.encode("utf-8"),
        RESEARCHER_TOKEN_KEY_DERIVATION_PURPOSE.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

def generate_researcher_token(email: str, signing_key: str, salt_prefix: str) -> str:
    """
    Generates a 40-character hex researcher token for a given email address.
    1. Hashes salt_prefix + email with SHA-256, truncated to 20 hex chars (80 bits).
    2. Signs the 20-hex hash with HMAC-SHA1 using signing_key, truncated to 20 hex chars (80 bits).
    3. Concatenates them into a 40 hex character token.
    """
    normalized_email = (email or "").strip().lower()
    if not normalized_email:
        raise ValueError("Empty researcher email")

    salted_email = salt_prefix + normalized_email
    hash_hex = hashlib.sha256(salted_email.encode("utf-8")).hexdigest()
    hash20 = hash_hex[:20]

    sig_hex = hmac.new(
        signing_key.encode("utf-8"),
        hash20.encode("utf-8"),
        hashlib.sha1
    ).hexdigest()
    sig20 = sig_hex[:20]

    return hash20 + sig20

def verify_researcher_token(token: str, master_key: str) -> str:
    """
    Verifies a 40-character hex researcher token against the master key.
    Returns the 20-character researcher email hash (hash20) if valid,
    or raises ValueError if the token is invalid.
    """
    token = (token or "").strip().lower()
    if not re.fullmatch(r"^[0-9a-f]{40}$", token):
        raise ValueError("Invalid researcher token format (expected 40-character hex string)")

    hash20 = token[:20]
    sig20 = token[20:]

    signing_key = derive_signing_key(master_key)
    expected_sig20 = hmac.new(
        signing_key.encode("utf-8"),
        hash20.encode("utf-8"),
        hashlib.sha1
    ).hexdigest()[:20]

    if not hmac.compare_digest(sig20, expected_sig20):
        raise ValueError("Invalid researcher token signature")

    return hash20
