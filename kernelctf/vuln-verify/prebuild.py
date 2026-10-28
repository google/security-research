#!/usr/bin/env -S python3 -u
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
"""Prebuilds the KASAN kernels needed by vuln-verify for recent (v5 and old-rules) submissions (the public cache is only written by this prebuild).

  plan:  lists the kernels missing from the public cache as a GitHub Actions matrix (`builds` output)
  build: builds one kernel and copies it with its build log into --out-dir"""
import argparse
import datetime
import json
import os
import re
import sys
from kernel_builds import KernelBuildError, Resolver, BuildSpec, load_public_sheet, hash_from_url, resolve_target, build_kernel, export_build, public_cache_exists
sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from flags import FLAG_REGEX, flag_release

MAX_AGE_DAYS = 90

def gh_append(var_name, content):
    fn = os.environ.get(f"GITHUB_{var_name}")
    if fn:
        with open(fn, "at") as f: f.write(content + "\n")

def cmd_plan(args):
    sheet = load_public_sheet()
    gh_token = os.environ.get("GITHUB_TOKEN")
    resolver = Resolver({"Authorization": f"Bearer {gh_token}"} if gh_token else {})
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=args.max_age_days)

    builds = {}
    warnings = []
    no_patch_commit = []
    for exp_id, row in sheet.items():
        # v5 rows have a single target, old-rules rows have one flag per target
        targets = [row["Target"]] if row["is_v5"] else sorted({flag_release(m) for m in re.finditer(FLAG_REGEX, row.get("Flags", ""))})
        submission_time = row.get("Submission time" if row["is_v5"] else "Flag submission time")
        if not submission_time:
            warnings.append(f"{exp_id}: submission time is missing")
            continue
        try:
            submitted_at = datetime.datetime.fromisoformat(submission_time)
        except ValueError:
            warnings.append(f"{exp_id}: invalid submission time '{submission_time}'")
            continue
        if submitted_at < cutoff: continue
        if not row["Patch commit"].strip():
            no_patch_commit.append(exp_id)  # common for old-rules flags, reported as one notice below
            continue
        if not targets:
            warnings.append(f"{exp_id}: no targets found in the flags")
            continue

        for target in targets:
            try:
                release = resolve_target(exp_id, row, target)
                tp = resolver.plan(exp_id, hash_from_url(row["Patch commit"]), release, stable=True, upstream=True, target_patching=False)
            except KernelBuildError as e:
                warnings.append(f"{exp_id} ({target}): cannot resolve builds: {e}")
                continue
            if not tp.stable_commit:
                warnings.append(f"{exp_id} ({target}): upstream commit {tp.ups_commit} was not backported to {tp.kernel_ver}, only upstream kernels are built")

            for spec in tp.builds.values():
                if spec.name in builds: continue
                cached = public_cache_exists(spec.name)
                print(f"[{'CACHED' if cached else 'MISSING'}] {exp_id} ({target}) -> {spec.name}")
                if not cached:
                    builds[spec.name] = {"name": spec.name, "repo_url": spec.repo_url, "commit": spec.commit, "release": release}

    resolver.save_cache()
    for w in warnings:
        print(f"::warning::{w}")
    if no_patch_commit:
        print(f"::notice::Skipped {len(no_patch_commit)} submission(s) without a patch commit: {', '.join(no_patch_commit)}")
    gh_append("STEP_SUMMARY", f"### vuln-verify prebuild plan\n\nKernels to build: {len(builds)}\n" + "".join(f"\n - `{x}`" for x in builds) +
        ("\n\n**Warnings:**\n" + "".join(f"\n - ⚠️ {w}" for w in warnings) if warnings else "") +
        (f"\n\nSkipped {len(no_patch_commit)} submission(s) without a patch commit: {', '.join(no_patch_commit)}" if no_patch_commit else ""))
    gh_append("OUTPUT", f"builds={json.dumps(list(builds.values()))}")

def cmd_build(args):
    config_fn = Resolver({}).release_info(args.release)[0]
    if not build_kernel(BuildSpec(args.name, args.repo_url, args.commit, config_fn), verbose=True):
        sys.exit(f"Building {args.name} failed")
    export_build(args.name, args.out_dir)

parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(required=True)
plan_parser = subparsers.add_parser("plan")
plan_parser.add_argument("--max-age-days", type=int, default=MAX_AGE_DAYS)
plan_parser.set_defaults(func=cmd_plan)
build_parser = subparsers.add_parser("build")
build_parser.add_argument("--name", required=True)
build_parser.add_argument("--repo-url", required=True)
build_parser.add_argument("--commit", required=True)
build_parser.add_argument("--release", required=True)
build_parser.add_argument("--out-dir", required=True)
build_parser.set_defaults(func=cmd_build)
args = parser.parse_args()
if args.func is cmd_build:
    args.out_dir = os.path.abspath(args.out_dir)

os.chdir(os.path.dirname(os.path.abspath(__file__)))
os.makedirs("builds", exist_ok=True)
args.func(args)
