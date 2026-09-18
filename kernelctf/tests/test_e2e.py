import csv
import json
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))
KERNELCTF_DIR = os.path.join(ROOT_DIR, "kernelctf")
TESTS_DIR = os.path.join(KERNELCTF_DIR, "tests")
SUBMISSION_DIR = os.path.join(TESTS_DIR, "CVE-2024-99999_hardened")

class TestEndToEndSubmissionAndRepro(unittest.TestCase):
    def setUp(self):
        # 1. Ensure release bzImage exists
        self.hardened_bzImage = os.path.join(KERNELCTF_DIR, "releases", "hardened-v1-7.2-rc5", "bzImage")
        if not os.path.isfile(self.hardened_bzImage):
            os.makedirs(os.path.dirname(self.hardened_bzImage), exist_ok=True)
            subprocess.run([
                "wget", "-q", "-c",
                "https://storage.googleapis.com/kernelctf-build/releases/hardened-v1-7.2-rc5/bzImage",
                "-O", self.hardened_bzImage
            ], check=True)

        # 2. Symlink test files into cache directories
        os.makedirs(os.path.join(KERNELCTF_DIR, ".cache"), exist_ok=True)
        link_targets = {
            ".cache/winners.csv": "tests/fake_winners.csv",
            ".cache/public.csv": "tests/fake_public.csv",
            "vuln-verify/kernelctf_winners_sheet.csv": "tests/fake_winners.csv",
            "vuln-verify/kernelctf_public_sheet.csv": "tests/fake_public.csv",
            ".cache/metadata.schema.v3.json": "metadata.schema.v3.json",
        }

        self.backups = []
        for dst_rel, src_rel in link_targets.items():
            dst = os.path.join(KERNELCTF_DIR, dst_rel)
            src = os.path.join(KERNELCTF_DIR, src_rel)
            bak = dst + ".bak" if os.path.exists(dst) else None
            if bak: os.rename(dst, bak)
            os.symlink(src, dst)
            self.backups.append((dst, bak))

    def tearDown(self):
        # Remove symlinks and restore backups
        for link, bak in self.backups:
            if os.path.islink(link) or os.path.exists(link): os.remove(link)
            if bak and os.path.exists(bak): os.rename(bak, link)

    def test_e2e_submission_repro_and_verify(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            gh_output_file = os.path.join(tmp_dir, "github_output.txt")

            # 1. Run check-submission.py with --submission-dir
            env = dict(os.environ, GITHUB_OUTPUT=gh_output_file)
            check_sub_script = os.path.join(KERNELCTF_DIR, "check-submission.py")
            res = subprocess.run(
                ["python3", check_sub_script, "--submission-dir", SUBMISSION_DIR],
                cwd=ROOT_DIR,
                env=env,
                capture_output=True,
                text=True
            )
            self.assertEqual(res.returncode, 0, f"check-submission.py failed:\n{res.stdout}\n{res.stderr}")

            # Verify JSON outputs from check-submission.py
            with open(gh_output_file, "r") as f:
                output_lines = [line.strip() for line in f if "=" in line]
            outputs = dict(line.split("=", 1) for line in output_lines)

            self.assertIn("targets", outputs)
            targets = json.loads(outputs["targets"])
            self.assertEqual(targets, ["hardened-v1-7.2-rc5"])

            self.assertIn("submission_dir", outputs)
            self.assertEqual(outputs["submission_dir"], "CVE-2024-99999_hardened")

            self.assertIn("exploits_info", outputs)
            exploits_info = json.loads(outputs["exploits_info"])
            self.assertIn("hardened-v1-7.2-rc5", exploits_info)
            self.assertEqual(exploits_info["hardened-v1-7.2-rc5"]["lts_slot"], "lts-6.12.104")
            self.assertNotIn("io_uring", exploits_info["hardened-v1-7.2-rc5"].get("uses", []))

            # 2. Run repro.sh using the target and exploit info
            repro_dir = os.path.join(tmp_dir, "repro_run")
            os.makedirs(os.path.join(repro_dir, "exp"), exist_ok=True)
            shutil.copyfile(
                os.path.join(SUBMISSION_DIR, "exploit", targets[0], "exploit"),
                os.path.join(repro_dir, "exp", "exploit")
            )
            os.chmod(os.path.join(repro_dir, "exp", "exploit"), 0o755)

            # Symlink the exact hardened-v1-7.2-rc5 bzImage
            os.symlink(self.hardened_bzImage, os.path.join(repro_dir, "bzImage"))

            repro_env = dict(
                os.environ,
                RELEASE_ID=targets[0],
                EXPLOIT_INFO=json.dumps(exploits_info[targets[0]]),
                AS_ROOT="1"
            )
            repro_script = os.path.join(KERNELCTF_DIR, "repro", "repro.sh")
            res_repro = subprocess.run(
                ["bash", repro_script, "1"],
                cwd=repro_dir,
                env=repro_env,
                capture_output=True,
                text=True
            )
            self.assertEqual(res_repro.returncode, 0, f"repro.sh failed:\n{res_repro.stdout}\n{res_repro.stderr}")
            self.assertIn("Got the flag! Congrats!", res_repro.stdout)
            repro_log_file = os.path.join(repro_dir, "repro_log_1.txt")
            self.assertTrue(os.path.isfile(repro_log_file))
            with open(repro_log_file, "r") as f:
                log_content = f.read()
            self.assertIn("kernelCTF{", log_content)

            # Also verify unprivileged exploit execution fails to read /flag
            repro_env_unprivileged = dict(
                os.environ,
                RELEASE_ID=targets[0],
                EXPLOIT_INFO=json.dumps(exploits_info[targets[0]])
            )
            res_repro_unpriv = subprocess.run(
                ["bash", repro_script, "2"],
                cwd=repro_dir,
                env=repro_env_unprivileged,
                capture_output=True,
                text=True
            )
            self.assertNotEqual(res_repro_unpriv.returncode, 0, "Unprivileged exploit unexpectedly succeeded!")
            with open(os.path.join(repro_dir, "repro_log_2.txt"), "r") as f:
                unpriv_log = f.read()
            self.assertIn("Permission denied", unpriv_log)

            # 3. Run vuln-verify/verify.py sanity checks
            verify_script = os.path.join(KERNELCTF_DIR, "vuln-verify", "verify.py")
            res_verify = subprocess.run(
                ["python3", verify_script, "--no-build", "--no-verify", "--no-stable", "--no-upstream", "--no-gh-auth", SUBMISSION_DIR],
                cwd=os.path.join(KERNELCTF_DIR, "vuln-verify"),
                env=dict(os.environ, IMAGE_RUNNER_DIR=os.path.join(KERNELCTF_DIR, "server", "server", "vm")),
                capture_output=True,
                text=True
            )
            # In sanity-check mode (--no-build --no-verify), verify.py runs without fatal error
            self.assertNotIn("Error:", res_verify.stderr)
            self.assertIn("exp9999 on lts-6.12.104", res_verify.stdout)

if __name__ == "__main__":
    unittest.main()
