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
"""kernelCTF flag parsing shared by check-submission.py and vuln-verify/prebuild.py."""
import re

# Regular expression to handle kernelCTF flag without signature
FLAG_REGEX = r"kernelCTF\{(?:[^:]+:)?(?:v1:([^:]+)|v2:([^:]+):([^:]*)):\d+\}"

def flag_release(match):
    """Returns the release (e.g. lts-6.6.90) of a FLAG_REGEX match (v1 or v2 flag)."""
    return match.group(1) or match.group(2)
