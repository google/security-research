#!/usr/bin/env -S python3 -u
import os
import sys
import json
import jsonschema
import hashlib
from utils import *

PUBLIC_CSV_URL = "https://docs.google.com/spreadsheets/d/e/2PACX-1vS1REdTA29OJftst8xN5B5x8iIUcxuK6bXdzF8G1UXCmRtoNsoQ9MbebdRdFnj6qZ0Yd7LwQfvYC2oF/pub?output=csv"
POC_FOLDER = "pocs/linux/kernelctf/"
EXPLOIT_DIR = "exploit/"
MIN_SCHEMA_VERSION = 2
# DEBUG = "--debug" in sys.argv

argv = [arg for arg in sys.argv if not arg.startswith("--")]
print(f"[-] Argv: {argv}")

mergeInto = argv[1] if len(argv) >= 2 else "origin/master"
print(f"[-] Params: mergeInto = {mergeInto}")

mergeBase = run(f"git merge-base HEAD {mergeInto}")[0]
print(f"[-] mergeBase = {mergeBase}")

prFiles = run(f"git diff --name-only {mergeBase}")

checkAtLeastOne(prFiles, "There are no files in the submission")
prFiles = checkList(prFiles, lambda f: f.startswith(POC_FOLDER), f"The following files are outside of the `{POC_FOLDER}` folder which is not allowed")

subDirName = checkOnlyOne(subdirEntries(prFiles, POC_FOLDER), "Only one submission is allowed per PR. Found multiple submissions")
checkRegex(subDirName, r"^CVE-\d+-\d+(_lts|_cos|_mitigation)+(_\d+)?$", f"The submission folder name is invalid (`{subDirName}`)")

print(f"[-] Processing submission... Folder = {subDirName}")
cve, *targets = subDirName.split('_')
submissionFolder = f"{POC_FOLDER}{subDirName}/"
files = [f[len(submissionFolder):] for f in prFiles]
printList("Submission files", files)

exploitFolders = subdirEntries(files, EXPLOIT_DIR)
printList("Exploit folders", exploitFolders)

validExploitFolderPrefixes = [f"{t}-" for t in targets] + ["extra-"]
checkList(exploitFolders, lambda f: any(f.startswith(p) for p in validExploitFolderPrefixes),
    f"The submission folder name (`{subDirName}`) is not consistent with the exploits in the `{EXPLOIT_DIR}` folder. " +
    f"Based on the folder name (`{subDirName}`), the subfolders are expected to be prefixed with one of these: {', '.join(f'`{t}-`' for t in targets)}, " +
    "but this is not true for the following entries: <LIST>. You can put the extra files into a folder prefixed with `extra-`, " +
    "but try to make it clear what's the difference between this exploit and the others.")

reqFilesPerExploit = ["Makefile", "exploit.c", "exploit"]

checkList(["metadata.json", "docs/vulnerability.md"], lambda f: f in files, "The following files are missing")
if "docs/exploit.md" not in files:
    warning("docs/exploit.md was not found, expecting per-exploit exploit.md")
    reqFilesPerExploit.append("exploit.md")

for exploitFolder in exploitFolders:
    checkList(reqFilesPerExploit, lambda file: f"{EXPLOIT_DIR}{exploitFolder}/{file}",
        f"The following files are missing from exploit ({exploitFolder})")

with open(f"{submissionFolder}metadata.json", "rt") as f: metadata = json.load(f)
print("\nMetadata:\n" + json.dumps(metadata, indent=4) + "\n")

schemaVersionM = checkRegex(metadata["$schema"], r"^https://google.github.io/security-research/kernelctf/metadata.schema.v(\d+).json$",
    "The `$schema` field of the `metadata.json` file is invalid")

if schemaVersionM:
    schemaVersion = int(schemaVersionM.group(1))
    if schemaVersion < MIN_SCHEMA_VERSION:
        error(f"The `metadata.json` schema version (v{schemaVersion}) is not supported anymore, " +
            f"please use `metadata.schema.v{MIN_SCHEMA_VERSION}.json`. Verifying file against v{MIN_SCHEMA_VERSION}.")

        schemaVersion = MIN_SCHEMA_VERSION

    schemaUrl = f"https://google.github.io/security-research/kernelctf/metadata.schema.v{schemaVersion}.json"
    schema = json.loads(fetch(schemaUrl, f"metadata.schema.v{schemaVersion}.json"))

    metadataErrors = list(jsonschema.Draft202012Validator(schema).iter_errors(metadata))
    if len(metadataErrors) > 0:
        for err in metadataErrors:
            error(f"Schema validation of `metadata.json` failed at the `<root>{err.json_path[1:]}` node with the following error: `{err.message}`")

submissionIds = metadata.get("submission_ids", None) or metadata["submission_id"]
if isinstance(submissionIds, str):
    submissionIds = [submissionIds]
submissionIds.sort()
print(f"[-] Submission IDs = {submissionIds}")

publicCsv = fetch(PUBLIC_CSV_URL, "public.csv")
publicSheet = { x["ID"]: x for x in parseCsv(publicCsv) }
# print(json.dumps(publicSheet, indent=4))

for submissionId in set(submissionIds).difference(publicSheet.keys()):
    fail(f"submission ID ({submissionId}) was not found on public spreadsheet")

submissionIds = list(set(submissionIds).intersection(publicSheet.keys()))
submissionIds.sort()

# Regular expression to handle kernelCTF flag without signature
flagRegex = r"kernelCTF\{(?:[^:]+:)?(?:v1:([^:]+)|v2:([^:]+):([^:]*)):\d+\}"
def flagTarget(flag):
    match = checkRegex(flag, flagRegex, f"The flag (`{flag}`) is invalid")
    if match.group(1):
        # v1 flag
        return match.group(1)

    # v2 flag
    return match.group(2)

targetFlagTimes = {}
flags = []
for submissionId in submissionIds:
    publicData = publicSheet[submissionId]
    is0Day = publicData["0-day / 1-day"] == "0-day"
    exploitHash = publicData["Exploit hash"]
    archiveFn = "original.tar.gz" if len(submissionIds) == 1 else f"original_{submissionId}.tar.gz"

    if exploitHash != "":
        if archiveFn not in files:
            if not is0Day:
                warning(f"The file `{archiveFn}` is missing, but submission is not a 0-day submission, so skipping exploit hash verification.")
            else:
                error(f"The file `{archiveFn}` is missing. Expected file with SHA256 hash of `{exploitHash}`.")
        else:
            with open(f"{submissionFolder}{archiveFn}", "rb") as f: originalTarGz = f.read()
            calculated = hashlib.sha256(originalTarGz).hexdigest()

            if exploitHash != calculated:
                error(f"Expected `{archiveFn}` with SHA256 hash of `{exploitHash}`, but the file's checksum is `{calculated}`.")
            else:
                print(f"[+] The hash of the file `{archiveFn}` matches the expected `{exploitHash}` value.")

    for flag in publicData["Flags"].strip().split('\n'):
        flags.append(flag)
        targetFlagTimes[flagTarget(flag)] = publicData["Flag submission time"]

    if cve != publicData["CVE"]:
        error(f"The CVE on the public spreadsheet for submission `{submissionId}` is `{publicData['CVE']}` but the PR is for `{cve}`.")

flagTargets = set([flagTarget(flag) for flag in flags])
if "mitigation-6.1-v2" in flagTargets:
    flagTargets = flagTargets - {"mitigation-6.1-v2"} | {"mitigation-6.1"}
print(f"[-] Got flags for the following targets: {', '.join(flagTargets)}")
checkList(flagTargets, lambda t: t in exploitFolders, f"Missing exploit for target(s)")
checkList(exploitFolders, lambda t: t in flagTargets, f"Found extra exploit(s) without flag submission", True)
if schemaVersion >= 3:
    checkList(flagTargets, lambda t: t in metadata["exploits"].keys(), f"Missing metadata information for exploit(s)")

def summary(success, text):
    if warnings:
        text += "\n\n**Warnings:**\n\n" + '\n\n'.join(f" - ⚠️ {x}" for x in warnings)

    ghSet("STEP_SUMMARY", text)
    print(f"\n[+] {text}") if success else fail(text)

if len(errors) > 0:
    summary(False, f"The file structure verification of the PR failed with the following errors:\n{formatList([f'❌ {e}' for e in errors], True)}")

ghSet("OUTPUT", "targets=" + json.dumps([f for f in flagTargets]))
ghSet("OUTPUT", f"submission_dir={subDirName}")

exploits_info = {}
for target in flagTargets:
    if schemaVersion >= 3:
        exploit_info = metadata["exploits"].get(target)
        if not exploit_info: continue
        exploits_info[target] = { key: exploit_info[key] for key in ["uses", "requires_separate_kaslr_leak"] if key in exploit_info }
        exploits_info[target]["flag_time"] = targetFlagTimes[target]
ghSet("OUTPUT", f"exploits_info={json.dumps(exploits_info)}")
ghSet("OUTPUT", f"artifact_backup_dir={'_'.join(submissionIds)}")

summary(True, f"✅ The file structure verification of the PR was successful!")
