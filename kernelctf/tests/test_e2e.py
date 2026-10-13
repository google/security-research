import csv
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest

ROOT_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))
KERNELCTF_DIR = os.path.join(ROOT_DIR, "kernelctf")
TESTS_DIR = os.path.join(KERNELCTF_DIR, "tests")
SUBMISSION_DIR = os.path.join(TESTS_DIR, "CVE-2024-99999_hardened")
TARGET = "hardened-v1-7.2-rc5"
EXPLOIT_DIR = os.path.join(SUBMISSION_DIR, "exploit", TARGET)

def make_submission(tmp_dir, members):
    """Copies the test submission into tmp_dir and adds an original.tar.gz built from members ({archive_path: bytes})."""
    submission_dir = os.path.join(tmp_dir, os.path.basename(SUBMISSION_DIR))
    shutil.copytree(SUBMISSION_DIR, submission_dir)
    with tarfile.open(os.path.join(submission_dir, "original.tar.gz"), "w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return submission_dir

def original_members(exploit_name="exploit", exploit_data=None):
    """Returns archive members mirroring the submission: compiled exploit binary plus its sources."""
    def read(name):
        with open(os.path.join(EXPLOIT_DIR, name), "rb") as f: return f.read()
    return {"exploit.c": read("exploit.c"), "Makefile": read("Makefile"), exploit_name: read("exploit") if exploit_data is None else exploit_data}

def run_check_submission(submission_dir, gh_output_file):
    return subprocess.run(
        ["python3", os.path.join(KERNELCTF_DIR, "check-submission.py"), "--submission-dir", submission_dir],
        cwd=ROOT_DIR,
        env=dict(os.environ, GITHUB_OUTPUT=gh_output_file),
        capture_output=True,
        text=True
    )

class FakeSheetsTestCase(unittest.TestCase):
    def setUp(self):
        # Copy (not symlink) test files into cache directories, so they get a fresh mtime and fetch() treats them as a valid cache
        os.makedirs(os.path.join(KERNELCTF_DIR, ".cache"), exist_ok=True)
        fixtures = {
            ".cache/winners.csv": "tests/fake_winners.csv",
            ".cache/public.csv": "tests/fake_public.csv",
            "vuln-verify/kernelctf_winners_sheet.csv": "tests/fake_winners.csv",
            "vuln-verify/kernelctf_public_sheet.csv": "tests/fake_public.csv",
            ".cache/metadata.schema.v3.json": "metadata.schema.v3.json",
        }

        self.backups = []
        for dst_rel, src_rel in fixtures.items():
            dst = os.path.join(KERNELCTF_DIR, dst_rel)
            src = os.path.join(KERNELCTF_DIR, src_rel)
            bak = dst + ".bak" if os.path.lexists(dst) else None
            if bak: os.rename(dst, bak)
            shutil.copyfile(src, dst)
            self.backups.append((dst, bak))

    def tearDown(self):
        # Remove copied fixtures and restore backups
        for dst, bak in self.backups:
            if os.path.lexists(dst): os.remove(dst)
            if bak and os.path.lexists(bak): os.rename(bak, dst)

class TestCheckSubmissionExploitHash(FakeSheetsTestCase):
    def check(self, members):
        with tempfile.TemporaryDirectory() as tmp_dir:
            return run_check_submission(make_submission(tmp_dir, members), os.path.join(tmp_dir, "github_output.txt"))

    def test_v5_exploit_binary_hash_matches(self):
        res = self.check(original_members())
        self.assertEqual(res.returncode, 0, f"check-submission.py failed:\n{res.stdout}\n{res.stderr}")
        self.assertIn("The hash of the `exploit` binary in `original.tar.gz` matches", res.stdout)

    def test_v5_exploit_binary_in_subfolder_hash_matches(self):
        res = self.check(original_members(exploit_name="build/out/exploit"))
        self.assertEqual(res.returncode, 0, f"check-submission.py failed:\n{res.stdout}\n{res.stderr}")
        self.assertIn("The hash of the `build/out/exploit` binary in `original.tar.gz` matches", res.stdout)

    def test_v5_exploit_binary_hash_mismatch(self):
        res = self.check(original_members(exploit_data=b"tampered exploit binary"))
        self.assertNotEqual(res.returncode, 0, f"check-submission.py unexpectedly succeeded:\n{res.stdout}")
        self.assertIn("Expected an `exploit` binary in `original.tar.gz` with SHA256 hash of", res.stdout + res.stderr)

    def test_v5_exploit_binary_missing(self):
        res = self.check(original_members(exploit_name="exploit.bin"))
        self.assertNotEqual(res.returncode, 0, f"check-submission.py unexpectedly succeeded:\n{res.stdout}")
        self.assertIn("No `exploit` binary was found in `original.tar.gz`", res.stdout + res.stderr)

class TestEndToEndSubmissionAndRepro(FakeSheetsTestCase):
    def setUp(self):
        # Ensure release bzImage exists
        self.hardened_bzImage = os.path.join(KERNELCTF_DIR, "releases", TARGET, "bzImage")
        if not os.path.isfile(self.hardened_bzImage):
            os.makedirs(os.path.dirname(self.hardened_bzImage), exist_ok=True)
            subprocess.run([
                "wget", "-q", "-c",
                f"https://storage.googleapis.com/kernelctf-build/releases/{TARGET}/bzImage",
                "-O", self.hardened_bzImage
            ], check=True)
        super().setUp()

    def test_e2e_submission_repro_and_verify(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            gh_output_file = os.path.join(tmp_dir, "github_output.txt")

            # 1. Run check-submission.py with --submission-dir
            res = run_check_submission(make_submission(tmp_dir, original_members()), gh_output_file)
            self.assertEqual(res.returncode, 0, f"check-submission.py failed:\n{res.stdout}\n{res.stderr}")

            # Verify JSON outputs from check-submission.py
            with open(gh_output_file, "r") as f:
                output_lines = [line.strip() for line in f if "=" in line]
            outputs = dict(line.split("=", 1) for line in output_lines)

            self.assertIn("targets", outputs)
            targets = json.loads(outputs["targets"])
            self.assertEqual(targets, [TARGET])

            self.assertIn("submission_dir", outputs)
            self.assertEqual(outputs["submission_dir"], "CVE-2024-99999_hardened")

            self.assertIn("exploits_info", outputs)
            exploits_info = json.loads(outputs["exploits_info"])
            self.assertIn(TARGET, exploits_info)
            self.assertEqual(exploits_info[TARGET]["lts_slot"], "lts-6.12.104")
            self.assertNotIn("io_uring", exploits_info[TARGET].get("uses", []))

            # 2. Run repro.sh using the target and exploit info
            repro_dir = os.path.join(tmp_dir, "repro_run")
            os.makedirs(os.path.join(repro_dir, "exp"), exist_ok=True)
            shutil.copyfile(os.path.join(EXPLOIT_DIR, "exploit"), os.path.join(repro_dir, "exp", "exploit"))
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
