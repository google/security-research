#!/usr/bin/env -S python3 -u
# example: GITHUB_TOKEN=$(cat ~/.github_pat) IMAGE_RUNNER_DIR=~/prjs/kernel-research-repo/image_runner ./verify.py ~/prjs/gob-isekernel/exploits/exp93_98_*
import html
import json
import re
import os
import sys
import shutil
import argparse
from utils import bold, readTextFile, run, red, green, yellow, extract_crash_report
from kernel_builds import (KernelBuildError, Resolver, load_public_sheet, hash_from_url, resolve_target, bzimage_fn, build_log_fn, build_kernel,
    download_public_cache, KERNELCTF_RELEASES_URL, BASE, BEFORE, AFTER, BASE_PATCHED, UPS_BEFORE, UPS_AFTER)

summary_lines = []
summary_fn = os.environ.get("GITHUB_STEP_SUMMARY")
def log(*args, **kwargs):
    print(*args, **kwargs)
    if not summary_fn: return

    s = " ".join(map(str, args))
    # Convert ANSI colors to Markdown colors (bolding + status words/emojis)
    s = re.sub(r'\033\[1m(.*?)\033\[0m', r'🟪 \1', s)
    colors = {31: "🔴", 32: "🟢", 33: "🟡"}
    for code, emoji in colors.items():
        s = re.sub(f'\\033\\[{code}m(.*?)\\033\\[0m', f'{emoji} \\1', s)
    # Strip other ANSI colors
    s = re.sub(r'\033\[[0-9;]*m', '', s)
    summary_lines.append(s)

summary_sections = []  # extra Markdown sections shown after the results (crash reports)

def log_crash_report(title, sections):
    print(f"{title}:")
    markdown = [f"#### {html.escape(title)}"]
    for section_title, lines in sections:
        if section_title:
            print(f"{section_title}:")
        print("\n".join(lines))
        code = "```\n" + "\n".join(lines) + "\n```"
        markdown.append(f"<details><summary>{html.escape(section_title)}</summary>\n\n{code}\n\n</details>" if section_title else code)
    print()
    summary_sections.append("\n\n".join(markdown))

def write_summary():
    if not summary_fn or not summary_lines: return
    title = "Vulnerability Verification Results" if args.verify else "Kernel Preparation Results"
    with open(summary_fn, "a") as f:
        f.write(f"### {title}\n\n```\n{"\n".join(summary_lines).strip()}\n```")
        for section in summary_sections:
            f.write(f"\n\n{section}")

def fatal(msg):
    log(msg, file=sys.stderr)
    write_summary()
    sys.exit(1)

parser = argparse.ArgumentParser()
parser.add_argument("--build", action=argparse.BooleanOptionalAction, default=True)
parser.add_argument("--verify", action=argparse.BooleanOptionalAction, default=True)
parser.add_argument("--upstream", action=argparse.BooleanOptionalAction, default=True)
parser.add_argument("--stable", action=argparse.BooleanOptionalAction, default=True)
parser.add_argument("--target-patching", action=argparse.BooleanOptionalAction, default=False)
parser.add_argument("--public-cache", action=argparse.BooleanOptionalAction, default=True, help="download missing kernels from the public GCS cache (read-only, no credentials)")
parser.add_argument("--verbose-build", action=argparse.BooleanOptionalAction, default=False)
parser.add_argument("--no-gh-auth", action="store_true")
parser.add_argument("exploit_paths", nargs="+")
args = parser.parse_args()

IMAGE_RUNNER_DIR = os.environ.get("IMAGE_RUNNER_DIR")
if args.verify and not IMAGE_RUNNER_DIR:
    fatal("Error: IMAGE_RUNNER_DIR environment variable is missing")

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
if not GITHUB_TOKEN and not args.no_gh_auth:
    fatal("Error: GITHUB_TOKEN environment variable is missing (use --no-gh-auth to skip)")

GH_HEADERS = {"Authorization": f"Bearer {GITHUB_TOKEN}"} if GITHUB_TOKEN and not args.no_gh_auth else {}

args.exploit_paths = [os.path.abspath(p) for p in args.exploit_paths]
os.chdir(os.path.dirname(__file__))
os.makedirs("builds", exist_ok=True)
os.makedirs("verify_results", exist_ok=True)

public_csv = load_public_sheet()
#pprint(public_csv)
resolver = Resolver(GH_HEADERS)

def check_sub_path(exp_dir, rel_path):
    p = os.path.join(exp_dir, rel_path)
    if not os.path.realpath(p).startswith(os.path.realpath(exp_dir) + os.sep) or (os.path.islink(p) and not os.path.isfile(p)):
        fatal(f"Error: submission path '{p}' resolves outside '{exp_dir}' or is an invalid symlink")
    return p

# Which kernel's crash report to show in the summary: upstream before the patch, then stable before the patch, then any other kernel
CRASH_REPORT_PRIORITY = {UPS_BEFORE: 0, BEFORE: 1}

def success_color(success):
    return green('SUCCESS') if success else red('FAIL') if not success else yellow('UNKNOWN')

all_success = True
all_builds_ok = True
missing_kernels = False
for i_exp, exp_dir in enumerate(args.exploit_paths):
    # WARNING: metadata is not trusted and needs to be sanitized
    metadata = json.loads(readTextFile(check_sub_path(exp_dir, "metadata.json")))
    for x in metadata["submission_ids"]:
        if not re.match(r"^exp\d+$", x):
            fatal(f"Error: invalid exp_id '{x}'")
    exp_ids = "exp" + "_".join(x.replace("exp", "") for x in metadata["submission_ids"])
    first_exp_id = metadata["submission_ids"][0]
    commit_hash_pr = hash_from_url(metadata["vulnerability"]["patch_commit"])
    commit_hash = hash_from_url(public_csv[first_exp_id]["Patch commit"])
    if commit_hash != commit_hash_pr:
        log(f"WARNING! {exp_ids}: public commit hash ({commit_hash}) does not match PR commit hash ({commit_hash_pr})")
    exp_success = False
    crashes = []  # (priority, kernel name, crash report) of the kernels which crashed, the lowest priority is shown in the summary
    exp_fail = False
    targets = list(metadata["exploits"].keys())
    for target in targets:
        if not re.match(r"^(lts|cos|mitigation|hardened)-[a-z0-9.-]+$", target):
            fatal(f"Error: invalid target '{target}'")
    for i_target, target in enumerate(targets):
        orig_target = target
        try:
            target = resolve_target(first_exp_id, public_csv[first_exp_id], target)
            tp = resolver.plan(first_exp_id, commit_hash, target, args.stable, args.upstream, args.target_patching)
        except KernelBuildError as e:
            fatal(f"Error: {e}")

        if tp.stable_commit:
            log(f"[{round(i_exp+1 + i_target/len(targets),2):g}/{len(args.exploit_paths)}] {exp_ids} on {target}: "
                f"{tp.kernel_ver}, commit: {commit_hash[:10]}, stable: {tp.stable_commit[:10]}, parent: {tp.parent_commit[:10]}")
        else:
            log(f"[{round(i_exp+1 + i_target/len(targets),2):g}/{len(args.exploit_paths)}] {exp_ids} on {target}: "
                f"{tp.kernel_ver}, commit: {commit_hash[:10]}. "
                f"Upstream commit {tp.ups_commit} was not backported to {tp.kernel_ver}, skipping fix verification on this kernel version...")

        def build_release_(spec):
            if os.path.isfile(bzimage_fn(spec.name)):
                return True

            if args.public_cache and download_public_cache(spec.name):
                print(f"  [CACHE] downloaded {spec.name} from the public cache")
                return True

            if not args.build or os.path.isfile(build_log_fn(spec.name)):
                return False

            return build_kernel(spec, args.verbose_build)

        for spec in tp.builds.values():
            success = build_release_(spec)
            all_builds_ok = all_builds_ok and success
            log(f"  [BUILD] {exp_ids} -> {spec.name}: {success}")

        if not args.verify:
            continue

        exp_fn = check_sub_path(exp_dir, f"exploit/{orig_target}/exploit")
        shutil.copyfile(exp_fn, f"{IMAGE_RUNNER_DIR}/rootfs/exp")

        if not os.path.isfile(bzimage_fn(target)):
            print(f"  [DOWNLOAD] downloading release {target}...")
            run(["wget", "-qO", bzimage_fn(target), f"{KERNELCTF_RELEASES_URL}/{target}/bzImage"])

        names = {role: spec.name for role, spec in tp.builds.items()}
        res = {}
        for role, name in [(None, target)] + list(names.items()):
            log_fn = f"verify_results/{first_exp_id}_{name}.txt"

            if not os.path.isfile(bzimage_fn(name)):
                res[name] = None
                missing_kernels = True
                log(f"  [VERIFY] {exp_ids}_{name}: {bold('kernel is missing (not in the public cache and not built)')}")
                continue

            if not os.path.isfile(log_fn):
                print(f"  [RUN] running exploit {first_exp_id}_{name}...")
                run(f"((timeout 3m ./run_exploit.sh {name}; EC=$?; echo; echo EXIT_CODE=$EC)|sed -u 's/\\r//g') 2>&1 >{log_fn}")

            pwned = None
            if not os.path.isfile(log_fn):
                result = "verification was not run"
            else:
                result = "<unknown>"
                logs = readTextFile(log_fn)
                if (m := re.search(r"KASAN: .*", logs)):
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
                elif "Running id and then the exploit" not in logs:
                    result = "VM hanged before running exploit"
                elif "EXIT_CODE=124" in logs:
                    result = "timed out"
                    pwned = False
                elif "EXIT_CODE=" in logs:
                    result = "exploit exited"
                    pwned = False

            res[name] = pwned
            report = extract_crash_report(logs) if pwned else None
            if report:
                crashes.append((CRASH_REPORT_PRIORITY.get(role, len(CRASH_REPORT_PRIORITY)), name, report))
            log(f"  [VERIFY] {exp_ids}_{name}: {bold(result)}")

        r = lambda role: res[names[role]]
        has_target_patching = BASE_PATCHED in names
        has_stable = AFTER in names
        has_upstream = UPS_AFTER in names
        success_target_patching = r(BASE) == True and r(BASE_PATCHED) == False if has_target_patching else None
        success_patch_commit = r(BEFORE) == True and r(AFTER) == False if has_stable else None
        success_upstream_patch = r(UPS_BEFORE) == True and r(UPS_AFTER) == False if has_upstream else None
        success = success_target_patching or success_patch_commit or success_upstream_patch
        fail = (has_stable and (has_target_patching and r(BASE_PATCHED) or r(AFTER))) or (has_upstream and r(UPS_AFTER))
        exp_success = exp_success or success
        exp_fail = exp_fail or fail
        if has_stable:
            if has_target_patching:
                log(f"  Target patching test: {success_color(success_target_patching)} (before: {r(BASE)}, after: {r(BASE_PATCHED)})")
            log(f"  Stable patch commit test: {success_color(success_patch_commit)} (before: {r(BEFORE)}, after: {r(AFTER)})")
        if has_upstream:
            log(f"  Upstream patch commit test: {success_color(success_upstream_patch)} (before: {r(UPS_BEFORE)}, after: {r(UPS_AFTER)})")

        if args.target_patching and success_target_patching and not success_patch_commit:
            log("  [STAT] Only target patching worked.")
        if args.target_patching and not success_target_patching and success_patch_commit:
            log("  [STAT] Only patch commit testing worked.")
        if args.stable and args.upstream:
            if success_upstream_patch and not success_patch_commit:
                log("  [STAT] Only upstream patch worked.")
            if not success_upstream_patch and success_patch_commit:
                log("  [STAT] Only stable patch worked.")

        log(f"  Verification of {exp_ids} on {target}: {red('FAIL') if fail else green('SUCCESS') if success else yellow('UNKNOWN')}")
        log()

    if not args.verify:
        continue

    log(f"[PR_VERIFY] of {exp_ids}: {red('FAIL') if exp_fail else green('SUCCESS') if exp_success else yellow('UNKNOWN')}")
    log()
    if crashes:
        _, crash_name, report = min(crashes, key=lambda c: c[0])
        log_crash_report(f"Crash report of {exp_ids}_{crash_name}", report)
    if exp_fail or not exp_success:
        all_success = False

if missing_kernels:
    log("Some kernels are missing. To build them into the public cache, run the prebuild (or wait for its daily run), then add the \"vuln-verify\" label to the PR:")
    log("  gh workflow run kernelctf-vulnverify-prebuild.yaml --repo google/security-research")
    log()

resolver.save_cache()
write_summary()
sys.exit(0 if (all_success if args.verify else all_builds_ok) else 1)
