#!/usr/bin/env -S python3 -u
# example: GITHUB_TOKEN=$(cat ~/.github_pat) IMAGE_RUNNER_DIR=~/prjs/kernel-research-repo/image_runner ./verify.py ~/prjs/gob-isekernel/exploits/exp93_98_*
import json
import re
import os
import sys
import sqlite3
import shutil
import subprocess
import argparse

summary_lines = []
summary_fn = os.environ.get("GITHUB_STEP_SUMMARY")
def log(*args, **kwargs):
    print(*args, **kwargs)
    if not summary_fn: return

    s = " ".join(map(str, args))
    # Convert ANSI colors to Markdown colors (bolding + status words/emojis)
    colors = {31: "🔴", 32: "🟢", 33: "🟡"}
    for code, emoji in colors.items():
        s = re.sub(f'\\033\\[{code}m(.*?)\\033\\[0m', f'{emoji} **\1**', s)
    # Strip other ANSI colors
    s = re.sub(r'\033\[[0-9;]*m', '', s)
    summary_lines.append(s)

def write_summary():
    if not summary_fn: return
    with open(summary_fn, "a") as f:
        f.write("### Vulnerability Verification Results\n")
        f.write("```\n")
        f.write("\n".join(summary_lines).strip() + "\n")
        f.write("```\n")

from utils import parseCsv, fetch, readTextFile, run, is_cached, writeTextFile, CACHE_FOREVER, red, green, yellow

parser = argparse.ArgumentParser()
parser.add_argument("--build", action=argparse.BooleanOptionalAction, default=True)
parser.add_argument("--verify", action=argparse.BooleanOptionalAction, default=True)
parser.add_argument("--force-verify", action=argparse.BooleanOptionalAction, default=False)
parser.add_argument("--upstream", action=argparse.BooleanOptionalAction, default=True)
parser.add_argument("--stable", action=argparse.BooleanOptionalAction, default=True)
parser.add_argument("--target-patching", action=argparse.BooleanOptionalAction, default=False)
parser.add_argument("--gcs-cache", action=argparse.BooleanOptionalAction, default=True)
parser.add_argument("--verbose-build", action=argparse.BooleanOptionalAction, default=False)
parser.add_argument("--no-gh-auth", action="store_true")
parser.add_argument("exploit_paths", nargs="+")
args = parser.parse_args()

IMAGE_RUNNER_DIR = os.environ.get("IMAGE_RUNNER_DIR")
if not IMAGE_RUNNER_DIR:
    log("Error: IMAGE_RUNNER_DIR environment variable is missing", file=sys.stderr)
    sys.exit(1)

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
if not GITHUB_TOKEN and not args.no_gh_auth:
    log("Error: GITHUB_TOKEN environment variable is missing (use --no-gh-auth to skip)", file=sys.stderr)
    sys.exit(1)

GH_HEADERS = {"Authorization": f"Bearer {GITHUB_TOKEN}"} if GITHUB_TOKEN and not args.no_gh_auth else {}

CACHE_DB_FN = "cache.json"
PUBLIC_CSV_URL = "https://docs.google.com/spreadsheets/d/e/2PACX-1vS1REdTA29OJftst8xN5B5x8iIUcxuK6bXdzF8G1UXCmRtoNsoQ9MbebdRdFnj6qZ0Yd7LwQfvYC2oF/pub?output=csv"
KERNEL_DANCE_SQL_URL = "https://linux-mirror-db.storage.googleapis.com/mirror.sl3"
KERNEL_DANCE_SQL_FN = "kernel-dance.sqlite3"
KERNELCTF_RELEASES_URL = "https://storage.googleapis.com/kernelctf-build/releases"
STABLE_COMMIT_QUERY = """
    SELECT upstream.`commit`
    FROM upstream
    LEFT JOIN tags ON tags.`commit` = upstream.`commit`
    WHERE (upstream.upstream LIKE :hash OR upstream.`commit` LIKE :hash)
      AND tags.tags LIKE :tag
"""
UPSTREAM_COMMIT_QUERY = "SELECT DISTINCT upstream.`upstream` FROM upstream WHERE (upstream.upstream LIKE :hash OR upstream.`commit` LIKE :hash)"
STABLE_REPO = "https://github.com/gregkh/linux"
UPSTREAM_REPO = "https://github.com/torvalds/linux"
GCS_BASE_URL = "gs://kernelctf-build/vuln-verify"

def gcs_download(local_fn, gcs_fn):
    if not args.gcs_cache or os.path.isfile(local_fn):
        return os.path.isfile(local_fn)
    print(f"  [CACHE] downloading {os.path.basename(local_fn)} from GCS...")
    return run(["gcloud", "storage", "cp", f"{GCS_BASE_URL}/{gcs_fn}", local_fn], fail_silent=True) is not None

def gcs_upload(local_fn, gcs_fn, gzip=False):
    if not args.gcs_cache or not os.path.isfile(local_fn):
        return
    print(f"  [CACHE] uploading {os.path.basename(local_fn)} to GCS...")
    cmd = ["gcloud", "storage", "cp"] + (["-Z"] if gzip else []) + [local_fn, f"{GCS_BASE_URL}/{gcs_fn}"]
    run(cmd)

args.exploit_paths = [os.path.abspath(p) for p in args.exploit_paths]
os.chdir(os.path.dirname(__file__))

public_csv = parseCsv(fetch(PUBLIC_CSV_URL, "kernelctf_public_sheet.csv"), "ID")
#pprint(public_csv)

if not is_cached(KERNEL_DANCE_SQL_FN, 3600*24*7):
    print(f"  [CACHE] downloading {KERNEL_DANCE_SQL_FN}...")
    run(["wget", "-O", KERNEL_DANCE_SQL_FN, KERNEL_DANCE_SQL_URL])
sqlconn = sqlite3.connect(KERNEL_DANCE_SQL_FN)
sql = sqlconn.cursor()

def sql_value(query, *params):
    results = sql.execute(query, *params).fetchall()
    if len(results) != 1:
        raise Exception(f"Multiple results for query '{query}' (with params {params}): {results}" if results else f"No results for query '{query}' (with params {params})")
    return results[0][0] if len(results) > 0 else None


def hash_from_url(url):
    return re.search(r"(?:id|h)=([0-9a-f]+)", url).group(1)

cache_db = json.loads(readTextFile(CACHE_DB_FN)) if os.path.isfile(CACHE_DB_FN) else {}

def cache(category, key, getter):
    value = cache_db.setdefault(category, {}).get(key)
    if not value:
        cache_db[category][key] = value = getter()
    return value

def save_cache():
    writeTextFile(CACHE_DB_FN, json.dumps(cache_db, indent=4))

def get_stable_commit(commit_hash, kernel_ver):
    return cache("stable_commits", f"{commit_hash}_{kernel_ver}", lambda:
                 sql_value(STABLE_COMMIT_QUERY, {"hash": f"{commit_hash}%", "tag": f"tags/v{kernel_ver}.%"}))

def get_upstream_commit(commit_hash):
    return cache("upstream_commits", f"{commit_hash}", lambda: sql_value(UPSTREAM_COMMIT_QUERY, {"hash": f"{commit_hash}%"}))

def get_parent_commit(commit_hash):
    return json.loads(fetch(f"https://api.github.com/repos/gregkh/linux/commits/{commit_hash}", f".cache/{commit_hash}.json",
                GH_HEADERS))["parents"][0]["sha"]

builds = []
all_success = True
for i_exp, exp_dir in enumerate(args.exploit_paths):
    metadata = json.loads(readTextFile(f"{exp_dir}/metadata.json"))
    exp_ids = "exp" + "_".join(x.replace("exp", "") for x in metadata["submission_ids"])
    first_exp_id = metadata["submission_ids"][0]
    commit_hash_pr = hash_from_url(metadata["vulnerability"]["patch_commit"])
    commit_hash = hash_from_url(public_csv[first_exp_id]["Patch commit"])
    if commit_hash != commit_hash_pr:
        log(f"WARNING! {exp_ids}: public commit hash ({commit_hash}) does not match PR commit hash ({commit_hash_pr})")
    exp_success = False
    exp_fail = False
    targets = list(metadata["exploits"].keys())
    for i_target, target in enumerate(targets):
        orig_target = target
        if target == "mitigation-6.1":
            target = "mitigation-6.1-v2"
        config = fetch(f"{KERNELCTF_RELEASES_URL}/{target}/.config", f"builds/{target}.config")
        commit_info_txt = fetch(f"{KERNELCTF_RELEASES_URL}/{target}/COMMIT_INFO", f"builds/{target}_COMMIT_INFO")
        commit_info = {x[0]: x[1] for x in [line.split("=") for line in commit_info_txt.strip().split("\n")]}
        repo_url = commit_info["REPOSITORY_URL"]
        base_commit = commit_info["COMMIT_HASH"]
        kernel_ver = re.search(r"Linux/x86 (\d+\.\d+)\.\d+ Kernel Configuration", config).group(1)
        stable_commit = "n/a"
        parent_commit = "n/a"
        if args.stable:
            stable_commit = get_stable_commit(commit_hash, kernel_ver)
            parent_commit = get_parent_commit(stable_commit)
        if args.upstream:
            ups_commit = get_upstream_commit(commit_hash)
            ups_parent_commit = get_parent_commit(ups_commit)
        log(f"[{round(i_exp+1 + i_target/len(targets),2):g}/{len(args.exploit_paths)}] {exp_ids} on {target}: "
              f"{kernel_ver}, commit: {commit_hash}, stable: {stable_commit}, parent: {parent_commit}")

        config_fn = f"builds/{target}.config"
        def build_release_(name, repo_url, commit_hash, patch_commit_fn=""):
            bzImage_fn = f"builds/{name}_bzImage"
            vmlinux_fn = f"builds/{name}_vmlinux"
            log_fn = f"builds/{name}_build.log"

            if gcs_download(bzImage_fn, f"builds/{name}_bzImage"):
                return True

            if not args.build or os.path.isfile(log_fn):
                return False

            cmd = f"./build_release.sh {repo_url} {commit_hash} {config_fn} kasan.config {patch_commit_fn}"
            print(f"Running '{cmd}'")

            if args.verbose_build:
                print(f"::group::Building {name}")
                success = subprocess.run(f"{cmd} 2>&1 | tee {log_fn}.tmp", shell=True).returncode == 0
                print("::endgroup::")
            else:
                success = run(f"{cmd} >{log_fn}.tmp 2>&1") is not None

            os.rename(f"{log_fn}.tmp", log_fn)  # move in case of error too, so we won't run it again
            if success:
                os.rename("linux/arch/x86/boot/bzImage", bzImage_fn)
                os.rename("linux/vmlinux", vmlinux_fn)
                gcs_upload(bzImage_fn, f"builds/{name}_bzImage")
                gcs_upload(vmlinux_fn, f"builds/{name}_vmlinux", gzip=True)
                gcs_upload(log_fn, f"builds/{name}_build.log")
            return success

        def build_release(name, *args):
            success = build_release_(name, *args)
            log(f"  [BUILD] {exp_ids} -> {name}: {success}")

        p_id = f"{first_exp_id}_{kernel_ver.replace('.', '_')}"
        name_orig = target
        name_base = f"{target}_kasan"
        build_targets = [name_orig]

        if args.target_patching:
            build_targets.append(name_base)
            build_release(name_base, repo_url, base_commit)

        if args.stable:
            name_before_patch = f"{p_id}_kasan_wo_patch_{parent_commit[0:7]}"
            name_after_patch = f"{p_id}_kasan_patched_{stable_commit[0:7]}"
            build_release(name_before_patch, STABLE_REPO, parent_commit)
            build_release(name_after_patch, STABLE_REPO, stable_commit)
            build_targets.extend([name_before_patch, name_after_patch])

            if args.target_patching:
                name_base_patched = f"{target}_kasan_{first_exp_id}_{stable_commit[0:7]}"
                build_release(name_base_patched, repo_url, base_commit, f"patches/{stable_commit[0:7]}.patch")
                build_targets.append(name_base_patched)

        if args.upstream:
            ups_name_before_patch = f"{first_exp_id}_upstream_kasan_wo_patch_{ups_parent_commit[0:7]}"
            ups_name_after_patch = f"{first_exp_id}_upstream_kasan_patched_{ups_commit[0:7]}"
            build_release(ups_name_before_patch, UPSTREAM_REPO, ups_parent_commit)
            build_release(ups_name_after_patch, UPSTREAM_REPO, ups_commit)
            build_targets.extend([ups_name_before_patch, ups_name_after_patch])

        if args.verify or args.force_verify:
            exp_fn = f"{exp_dir}/exploit/{orig_target}/exploit"
            shutil.copyfile(exp_fn, f"{IMAGE_RUNNER_DIR}/rootfs/exp")

            if not os.path.isfile(f"builds/{target}_bzImage"):
                print(f"  [DOWNLOAD] downloading release {target}...")
                run(f"wget -qO builds/{target}_bzImage {KERNELCTF_RELEASES_URL}/{target}/bzImage")

        res = {}
        for name in build_targets:
            log_fn = f"verify_results/{first_exp_id}_{name}.txt"

            if not args.force_verify:
                gcs_download(log_fn, log_fn)

            if args.force_verify or (args.verify and not os.path.isfile(log_fn)):
                print(f"  [RUN] running exploit {first_exp_id}_{name}...")
                run(f"((timeout 3m ./run_exploit.sh {name}; EC=$?; echo; echo EXIT_CODE=$EC)|sed -u 's/\\r//g') 2>&1 >{log_fn}")
                gcs_upload(log_fn, log_fn)

            pwned = None
            if not os.path.isfile(log_fn):
                result = "verification was not run"
            else:
                result = "<unknown>"
                logs = readTextFile(log_fn)
                if "Usage: ./run_exploit.sh" in logs:
                    result = "build failed"
                elif (m := re.search(r"KASAN: .*", logs)):
                    result = m.group(0)
                    pwned = True
                elif "CTF{secret_flag_deadbeef}" in logs:
                    result = "got the flag"
                    pwned = True
                elif "Attempted to kill init!" in logs:
                    result = "exploit exited"
                    pwned = False
                elif "Kernel panic" in logs:
                    result = "kernel panic"
                    pwned = True
                elif "majority vote failed" in logs:
                    result = "prefetch failed"
                elif "Running command: /exp.sh" not in logs:
                    result = "VM hanged before running exploit"
                elif "EXIT_CODE=124" in logs:
                    result = "timed out"
                    pwned = False

            res[name] = pwned
            log(f"  [VERIFY] {exp_ids}_{name}: {result}")

        success_target_patching = res[name_base] == True and res[name_base_patched] == False if args.stable and args.target_patching else None
        success_patch_commit = res[name_before_patch] == True and res[name_after_patch] == False if args.stable else None
        success_upstream_patch = res[ups_name_before_patch] == True and res[ups_name_after_patch] == False if args.upstream else None
        success = success_target_patching or success_patch_commit or success_upstream_patch
        fail = (args.stable and (args.target_patching and res[name_base_patched] or res[name_after_patch])) or (args.upstream and res[ups_name_after_patch])
        exp_success = exp_success or success
        exp_fail = exp_fail or fail
        if args.stable:
            if args.target_patching:
                log(f"  Target patching test: {success_target_patching} (before: {res[name_base]}, after: {res[name_base_patched]})")
            log(f"  Patch commit test: {success_patch_commit} (before: {res[name_before_patch]}, after: {res[name_after_patch]})")
        if args.upstream:
            log(f"  Upstream patch commit test: {success_upstream_patch} (before: {res[ups_name_before_patch]}, after: {res[ups_name_after_patch]})")

        if success_target_patching and not success_patch_commit:
            log("  [STAT] Only target patching worked.")
        if not success_target_patching and success_patch_commit:
            log("  [STAT] Only patch commit testing worked.")
        if success_upstream_patch and not success_patch_commit:
            log("  [STAT] Only upstream patch worked.")
        if not success_upstream_patch and success_patch_commit:
            log("  [STAT] Only stable patch worked.")

        log(f"  Verification of {exp_ids} on {target}: {red('FAIL') if fail else green('SUCCESS') if success else yellow('UNKNOWN')}")
        log()

    log(f"[PR_VERIFY] of {exp_ids}: {red('FAIL') if exp_fail else green('SUCCESS') if exp_success else yellow('UNKNOWN')}")
    log()
    if exp_fail or not exp_success:
        all_success = False

save_cache()
write_summary()
sys.exit(0 if all_success else 1)
