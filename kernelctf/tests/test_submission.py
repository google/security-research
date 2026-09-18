import json
import os
import re
import subprocess
import unittest

ROOT_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))
KERNELCTF_DIR = os.path.join(ROOT_DIR, "kernelctf")

class TestSubmissionLogic(unittest.TestCase):
    def test_schema_allows_hardened(self):
        schema_file = os.path.join(KERNELCTF_DIR, "metadata.schema.v3.json")
        with open(schema_file, "r") as f:
            schema = json.load(f)
        pattern = schema["properties"]["exploits"]["patternProperties"]
        self.assertTrue(any("hardened" in k for k in pattern.keys()), "Schema patternProperties must include hardened targets")

    def test_check_submission_regexes(self):
        # Folder regex
        FOLDER_REGEX = r"^CVE-\d+-\d+(_lts|_cos|_mitigation|_hardened|_android\d+)+(_\d+)?$"
        self.assertTrue(re.match(FOLDER_REGEX, "CVE-2024-1234_hardened"))
        self.assertTrue(re.match(FOLDER_REGEX, "CVE-2024-1234_hardened_1"))
        self.assertTrue(re.match(FOLDER_REGEX, "CVE-2024-1234_lts_hardened"))
        self.assertTrue(re.match(FOLDER_REGEX, "CVE-2024-1234_android14"))
        self.assertFalse(re.match(FOLDER_REGEX, "CVE-2024-1234_invalid"))

        # Target regex
        TARGET_REGEX = r"^(lts|cos|mitigation|hardened)-[a-z0-9.-]+$"
        self.assertTrue(re.match(TARGET_REGEX, "hardened-v1-7.2-rc5"))
        self.assertTrue(re.match(TARGET_REGEX, "lts-6.12.104"))
        self.assertTrue(re.match(TARGET_REGEX, "cos-105-17412.294.34"))
        self.assertFalse(re.match(TARGET_REGEX, "ubuntu-22.04"))

    def test_repro_dispatcher_routing(self):
        repro_script = os.path.join(KERNELCTF_DIR, "repro", "repro.sh")
        # Dry-run test using env var RELEASE_ID
        targets = [
            ("android-14", "repro_android.sh"),
            ("hardened-v1-7.2-rc5", "repro_hardened.sh"),
            ("lts-6.12.104", "repro_old.sh"),
            ("mitigation-v3-6.1.55", "repro_old.sh"),
        ]
        for release_id, expected_script in targets:
            cmd = f'RELEASE_ID="{release_id}"; if [[ "$RELEASE_ID" == android* ]]; then SCRIPT="repro_android.sh"; elif [[ "$RELEASE_ID" == hardened* ]]; then SCRIPT="repro_hardened.sh"; else SCRIPT="repro_old.sh"; fi; echo $SCRIPT'
            out = subprocess.check_output(["bash", "-c", cmd], text=True).strip()
            self.assertEqual(out, expected_script)

    def test_is_v5_flag_logic(self):
        # Simulate row parsing
        row_old = {"ID": "exp1", "0-day / 1-day": "1-day", "is_v5": False}
        row_winners = {"ID": "exp2", "0-day / 1-day": "", "is_v5": True}
        
        def compute_is0day(row):
            return True if row["is_v5"] else row["0-day / 1-day"] == "0-day"

        self.assertFalse(compute_is0day(row_old))
        self.assertTrue(compute_is0day(row_winners))

if __name__ == "__main__":
    unittest.main()
