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
"""Shared KASAN kernel build resolution, building and public cache access for verify.py and prebuild.py.

All paths are relative to the vuln-verify directory (callers chdir there first)."""
import json
import os
import re
import shutil
import sqlite3
import subprocess
from dataclasses import dataclass, field
import requests
from utils import parseCsv, fetch, readTextFile, run, is_cached, writeTextFile

PUBLIC_CSV_BASE_URL = "https://docs.google.com/spreadsheets/d/e/2PACX-1vS1REdTA29OJftst8xN5B5x8iIUcxuK6bXdzF8G1UXCmRtoNsoQ9MbebdRdFnj6qZ0Yd7LwQfvYC2oF/pub?output=csv&single=true"
OLD_SHEET_GID = "2095368189"
WINNERS_SHEET_GID = "855892526"
KERNEL_DANCE_SQL_URL = "https://linux-mirror-db.storage.googleapis.com/mirror.sl3"
KERNEL_DANCE_SQL_FN = "kernel-dance.sqlite3"
KERNELCTF_RELEASES_URL = "https://storage.googleapis.com/kernelctf-build/releases"
PUBLIC_CACHE_URL = "https://storage.googleapis.com/kernelctf-build/vuln-verify/builds"
CACHE_DB_FN = "cache.json"
STABLE_REPO = "https://github.com/gregkh/linux"
UPSTREAM_REPO = "https://github.com/torvalds/linux"
VALID_REPO_URLS = {
    "https://github.com/gregkh/linux",
    "https://cos.googlesource.com/third_party/kernel",
    "https://github.com/thejh/linux"
}
BUILD_REPO_URLS = VALID_REPO_URLS | {STABLE_REPO, UPSTREAM_REPO}
RELEASE_RE = r"^(lts|cos|mitigation)-[a-z0-9.-]+$"
BUILD_NAME_RE = r"^[A-Za-z0-9_.-]+$"
STABLE_COMMIT_QUERY = """
    SELECT upstream.`commit`
    FROM upstream
    LEFT JOIN tags ON tags.`commit` = upstream.`commit`
    WHERE (upstream.upstream LIKE :hash OR upstream.`commit` LIKE :hash)
      AND tags.tags LIKE :tag
"""
UPSTREAM_COMMIT_QUERY = "SELECT DISTINCT upstream.`upstream` FROM upstream WHERE (upstream.upstream LIKE :hash OR upstream.`commit` LIKE :hash)"

# Build roles of a target. Dict insertion order in TargetPlan.builds is the build and verification order.
BASE = "base"                  # target release source with KASAN (target patching only)
BEFORE = "before"              # stable kernel before the patch commit
AFTER = "after"                # stable kernel with the patch commit
BASE_PATCHED = "base_patched"  # target release source with the patch applied (target patching only)
UPS_BEFORE = "ups_before"      # upstream kernel before the patch commit
UPS_AFTER = "ups_after"        # upstream kernel with the patch commit

class KernelBuildError(Exception):
    pass

@dataclass
class BuildSpec:
    name: str
    repo_url: str
    commit: str
    config_fn: str
    patch_fn: str = ""

@dataclass
class TargetPlan:
    release: str
    kernel_ver: str
    ups_commit: str
    stable_commit: str = "n/a"  # None if the upstream commit was not backported to kernel_ver
    parent_commit: str = "n/a"
    ups_parent_commit: str = None
    builds: dict = field(default_factory=dict)  # role -> BuildSpec

def bzimage_fn(name):
    return f"builds/{name}_bzImage"

def build_log_fn(name):
    return f"builds/{name}_build.log"

def load_public_sheet():
    sheet = {}
    for gid, fn, is_v5 in [(OLD_SHEET_GID, "kernelctf_public_sheet.csv", False), (WINNERS_SHEET_GID, "kernelctf_winners_sheet.csv", True)]:
        sheet.update({ x["ID"]: {**x, "is_v5": is_v5} for x in parseCsv(fetch(f"{PUBLIC_CSV_BASE_URL}&gid={gid}", fn, cache_time=24*3600)) })
    return sheet

def hash_from_url(url):
    m = re.search(r"(?:id|h)=([0-9a-f]+)", url) or re.search(r"/commit/([0-9a-f]+)", url)
    return m.group(1) if m else url.strip()

def check_hash(hash):
    if hash is not None and not re.match(r"^[0-9a-fA-F]+$", hash):
        raise KernelBuildError(f"invalid commit hash '{hash}'")
    return hash

def resolve_target(exp_id, sheet_row, target):
    """Maps a submission target to the release whose kernel config and version are used for the builds."""
    if sheet_row.get("is_v5") or target.startswith("hardened-"):
        lts_slot = sheet_row.get("LTS slot")
        if not lts_slot:
            raise KernelBuildError(f"LTS slot not found in spreadsheet for {exp_id}")
        return lts_slot
    return "mitigation-6.1-v2" if target == "mitigation-6.1" else target

class Resolver:
    """Resolves the stable / upstream commits and the KASAN builds of a submission target (results are cached in cache.json)."""
    def __init__(self, gh_headers):
        self.gh_headers = gh_headers
        self.cache_db = json.loads(readTextFile(CACHE_DB_FN)) if os.path.isfile(CACHE_DB_FN) else {}
        self.sql = None

    def save_cache(self):
        writeTextFile(CACHE_DB_FN, json.dumps(self.cache_db, indent=4))

    def _cache(self, category, key, getter):
        value = self.cache_db.setdefault(category, {}).get(key)
        if not value:
            self.cache_db[category][key] = value = getter()
        return value

    def _sql_value_or_none(self, query, params):
        if not self.sql:  # the database is ~1GB, only download it if a lookup is not cached yet
            if not is_cached(KERNEL_DANCE_SQL_FN, 3600*24*7):
                print(f"  [CACHE] downloading {KERNEL_DANCE_SQL_FN}...")
                if run(["wget", "-O", KERNEL_DANCE_SQL_FN, KERNEL_DANCE_SQL_URL]) is None:
                    raise KernelBuildError(f"downloading {KERNEL_DANCE_SQL_URL} failed")
            self.sql = sqlite3.connect(KERNEL_DANCE_SQL_FN).cursor()
        results = self.sql.execute(query, params).fetchall()
        if len(results) > 1:
            raise KernelBuildError(f"Multiple results for query '{query}' (with params {params}): {results}")
        return results[0][0] if len(results) > 0 else None

    def _sql_value(self, query, params):
        result = self._sql_value_or_none(query, params)
        if not result:
            raise KernelBuildError(f"No results for query '{query}' (with params {params})")
        return result

    def get_stable_commit(self, commit_hash, kernel_ver):
        return check_hash(self._cache("stable_commits", f"{commit_hash}_{kernel_ver}", lambda:
            self._sql_value_or_none(STABLE_COMMIT_QUERY, {"hash": f"{commit_hash}%", "tag": f"tags/v{kernel_ver}.%"})))

    def get_upstream_commit(self, commit_hash):
        return check_hash(self._cache("upstream_commits", f"{commit_hash}", lambda: self._sql_value(UPSTREAM_COMMIT_QUERY, {"hash": f"{commit_hash}%"})))

    def get_parent_commit(self, commit_hash):
        return check_hash(json.loads(fetch(f"https://api.github.com/repos/gregkh/linux/commits/{commit_hash}", f".cache/{commit_hash}.json",
            self.gh_headers))["parents"][0]["sha"])

    def release_info(self, release):
        """Returns (config_fn, kernel_ver, repo_url, base_commit) of a kernelCTF release."""
        if not re.match(RELEASE_RE, release):
            raise KernelBuildError(f"invalid release '{release}'")
        config_fn = f"builds/{release}.config"
        config = fetch(f"{KERNELCTF_RELEASES_URL}/{release}/.config", config_fn)
        commit_info_txt = fetch(f"{KERNELCTF_RELEASES_URL}/{release}/COMMIT_INFO", f"builds/{release}_COMMIT_INFO")
        commit_info = {x[0]: x[1] for x in [line.split("=") for line in commit_info_txt.strip().split("\n")]}
        repo_url = commit_info["REPOSITORY_URL"]
        if repo_url not in VALID_REPO_URLS:
            raise KernelBuildError(f"invalid repo_url '{repo_url}'")
        kernel_ver = re.search(r"Linux/x86 (\d+\.\d+)\.\d+ Kernel Configuration", config).group(1)
        return config_fn, kernel_ver, repo_url, check_hash(commit_info["COMMIT_HASH"])

    def plan(self, exp_id, commit_hash, release, stable, upstream, target_patching):
        config_fn, kernel_ver, repo_url, base_commit = self.release_info(release)
        tp = TargetPlan(release, kernel_ver, self.get_upstream_commit(commit_hash))
        if stable:
            tp.stable_commit = self.get_stable_commit(tp.ups_commit, kernel_ver)
            tp.parent_commit = self.get_parent_commit(tp.stable_commit) if tp.stable_commit else None
        if upstream:
            tp.ups_parent_commit = self.get_parent_commit(tp.ups_commit)

        # Known limitation: the cache names below do not contain the release (whose .config is used), only the kernel version. Old-rules
        # submissions with two targets of the same version (e.g. lts-6.1.36 + mitigation-6.1) shared one build. The names are kept
        # unchanged so the existing public cache stays valid, v5 submissions have a single target (the LTS slot) so they are not affected.
        p_id = f"{exp_id}_{kernel_ver.replace('.', '_')}"
        if target_patching:
            tp.builds[BASE] = BuildSpec(f"{release}_kasan", repo_url, base_commit, config_fn)
        if stable and tp.stable_commit:
            tp.builds[BEFORE] = BuildSpec(f"{p_id}_kasan_wo_patch_{tp.parent_commit[0:7]}", STABLE_REPO, tp.parent_commit, config_fn)
            tp.builds[AFTER] = BuildSpec(f"{p_id}_kasan_patched_{tp.stable_commit[0:7]}", STABLE_REPO, tp.stable_commit, config_fn)
            if target_patching:
                tp.builds[BASE_PATCHED] = BuildSpec(f"{release}_kasan_{exp_id}_{tp.stable_commit[0:7]}", repo_url, base_commit, config_fn, f"patches/{tp.stable_commit[0:7]}.patch")
        if upstream:
            tp.builds[UPS_BEFORE] = BuildSpec(f"{exp_id}_upstream_kasan_wo_patch_{tp.ups_parent_commit[0:7]}", UPSTREAM_REPO, tp.ups_parent_commit, config_fn)
            tp.builds[UPS_AFTER] = BuildSpec(f"{exp_id}_upstream_kasan_patched_{tp.ups_commit[0:7]}", UPSTREAM_REPO, tp.ups_commit, config_fn)
        return tp

def build_kernel(spec, verbose):
    """Builds spec into builds/{name}_bzImage and writes builds/{name}_build.log. Returns whether the build succeeded."""
    if not re.match(BUILD_NAME_RE, spec.name) or spec.repo_url not in BUILD_REPO_URLS:
        raise KernelBuildError(f"invalid build spec: {spec}")
    check_hash(spec.commit)
    log_fn = build_log_fn(spec.name)
    cmd = f"./build_release.sh {spec.repo_url} {spec.commit} {spec.config_fn} kasan.config {spec.patch_fn}"
    print(f"Running '{cmd}'")

    if verbose:
        print(f"::group::Building {spec.name}")
        success = subprocess.run(f"{cmd} 2>&1 | tee {log_fn}.tmp", shell=True).returncode == 0
        print("::endgroup::")
    else:
        success = run(f"{cmd} >{log_fn}.tmp 2>&1") is not None

    os.rename(f"{log_fn}.tmp", log_fn)  # move in case of error too, so we won't run it again
    if success:
        os.rename("linux/arch/x86/boot/bzImage", bzimage_fn(spec.name))
    return success

def export_build(name, out_dir):
    """Copies a successful build (bzImage + build log) into out_dir (prebuild uploads it from there to the public cache)."""
    os.makedirs(out_dir, exist_ok=True)
    for fn in [bzimage_fn(name), build_log_fn(name)]:
        shutil.copyfile(fn, os.path.join(out_dir, os.path.basename(fn)))

def _public_cache_request(method, name, **kwargs):
    response = requests.request(method, f"{PUBLIC_CACHE_URL}/{name}_bzImage", **kwargs)
    # GCS returns 403 (not 404) for anonymous requests of missing objects
    if response.status_code in (403, 404):
        return None
    response.raise_for_status()
    return response

def public_cache_exists(name):
    return _public_cache_request("HEAD", name) is not None

def download_public_cache(name):
    """Downloads builds/{name}_bzImage from the public cache. Returns False if it is not cached."""
    response = _public_cache_request("GET", name, stream=True)
    if response is None:
        return False
    fn = bzimage_fn(name)
    with open(f"{fn}.tmp", "wb") as f:
        for chunk in response.iter_content(chunk_size=1 << 20):
            f.write(chunk)
    os.rename(f"{fn}.tmp", fn)
    return True
