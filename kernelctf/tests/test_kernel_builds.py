import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "vuln-verify"))
import kernel_builds
from kernel_builds import Resolver, KernelBuildError, resolve_target, BEFORE, AFTER, BASE, BASE_PATCHED, UPS_BEFORE, UPS_AFTER

UPS = "60e6489f8e3b086bd1130ad4450a2c112e863791"
UPS_PARENT = "8c0726e0a1b2c3d4e5f60718293a4b5c6d7e8f90"
STABLE = "db81ad20fd8aef7cc7d536c52ee5ea4c1f979128"
STABLE_PARENT = "acd24d5f0e1d2c3b4a5968778695a4b3c2d1e0f9"
BASE_COMMIT = "1234567890abcdef1234567890abcdef12345678"

class TestResolveTarget(unittest.TestCase):
    def test_v5_uses_lts_slot(self):
        self.assertEqual(resolve_target("exp1", {"is_v5": True, "LTS slot": "lts-6.12.104"}, "hardened-v1-7.2-rc5"), "lts-6.12.104")

    def test_hardened_uses_lts_slot(self):
        self.assertEqual(resolve_target("exp1", {"is_v5": False, "LTS slot": "lts-6.12.1"}, "hardened-x"), "lts-6.12.1")

    def test_missing_lts_slot(self):
        with self.assertRaises(KernelBuildError):
            resolve_target("exp1", {"is_v5": True, "LTS slot": ""}, "lts-6.12.1")

    def test_mitigation_6_1(self):
        self.assertEqual(resolve_target("exp1", {"is_v5": False}, "mitigation-6.1"), "mitigation-6.1-v2")
        self.assertEqual(resolve_target("exp1", {"is_v5": False}, "lts-6.6.90"), "lts-6.6.90")

class TestResolverPlan(unittest.TestCase):
    def setUp(self):
        with mock.patch("os.path.isfile", return_value=False):
            self.resolver = Resolver({})
        self.resolver.cache_db = {"upstream_commits": {UPS: UPS}, "stable_commits": {f"{UPS}_6.12": STABLE}}
        parents = {STABLE: STABLE_PARENT, UPS: UPS_PARENT}
        self.resolver.get_parent_commit = lambda c: parents[c]
        self.resolver.release_info = lambda release: ("builds/lts-6.12.56.config", "6.12", "https://github.com/gregkh/linux", BASE_COMMIT)

    def test_names_match_existing_cache_names(self):
        tp = self.resolver.plan("exp436", UPS, "lts-6.12.56", stable=True, upstream=True, target_patching=False)
        self.assertEqual({role: spec.name for role, spec in tp.builds.items()}, {
            BEFORE: "exp436_6_12_kasan_wo_patch_acd24d5",
            AFTER: "exp436_6_12_kasan_patched_db81ad2",
            UPS_BEFORE: "exp436_upstream_kasan_wo_patch_8c0726e",
            UPS_AFTER: "exp436_upstream_kasan_patched_60e6489",
        })
        self.assertEqual(list(tp.builds), [BEFORE, AFTER, UPS_BEFORE, UPS_AFTER])
        self.assertEqual(tp.builds[BEFORE].repo_url, kernel_builds.STABLE_REPO)
        self.assertEqual(tp.builds[UPS_AFTER].repo_url, kernel_builds.UPSTREAM_REPO)

    def test_target_patching_order_and_names(self):
        tp = self.resolver.plan("exp436", UPS, "lts-6.12.56", stable=True, upstream=True, target_patching=True)
        self.assertEqual(list(tp.builds), [BASE, BEFORE, AFTER, BASE_PATCHED, UPS_BEFORE, UPS_AFTER])
        self.assertEqual(tp.builds[BASE].name, "lts-6.12.56_kasan")
        self.assertEqual(tp.builds[BASE_PATCHED].name, "lts-6.12.56_kasan_exp436_db81ad2")
        self.assertEqual(tp.builds[BASE_PATCHED].patch_fn, "patches/db81ad2.patch")

    def test_no_backport(self):
        self.resolver.cache_db["stable_commits"] = {}
        self.resolver._sql_value_or_none = lambda query, params: None
        tp = self.resolver.plan("exp436", UPS, "lts-6.12.56", stable=True, upstream=True, target_patching=False)
        self.assertIsNone(tp.stable_commit)
        self.assertEqual(list(tp.builds), [UPS_BEFORE, UPS_AFTER])

    def test_stable_and_upstream_disabled(self):
        tp = self.resolver.plan("exp436", UPS, "lts-6.12.56", stable=False, upstream=False, target_patching=False)
        self.assertEqual(tp.builds, {})
        self.assertEqual(tp.stable_commit, "n/a")

class TestBuildKernelValidation(unittest.TestCase):
    def test_rejects_unknown_repo(self):
        with self.assertRaises(KernelBuildError):
            kernel_builds.build_kernel(kernel_builds.BuildSpec("x", "https://evil.example/linux", UPS, "c"), verbose=False)

    def test_rejects_invalid_name(self):
        with self.assertRaises(KernelBuildError):
            kernel_builds.build_kernel(kernel_builds.BuildSpec("x;rm -rf /", kernel_builds.STABLE_REPO, UPS, "c"), verbose=False)

    def test_rejects_invalid_release(self):
        with self.assertRaises(KernelBuildError):
            Resolver({}).release_info("lts-6.12.1; id")

if __name__ == "__main__":
    unittest.main()
