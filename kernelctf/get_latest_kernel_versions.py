#!/usr/bin/env -S python3 -u
import json
from utils import *
from lxml import etree

releases = []

def add_release(release_id, branch=None):
    url = f"https://storage.googleapis.com/kernelctf-build/releases/{release_id}/bzImage"
    status_code = requests.head(url).status_code
    if status_code == 200:
        print("  -> Release already exists, skipping...")
        return
    if status_code != 403:
        fail(f"Unexpected HTTP status code for release check: {status_code} (url = {url})")

    global releases
    releases.append({ "releaseId": release_id, "branch": branch })

latest_lts = run("git ls-remote --tags --sort='-v:refname' https://github.com/gregkh/linux 'v6.1.*[0-9]'")[0].split("refs/tags/")[1]
print(f"Latest LTS: {latest_lts}")
add_release(f"lts-{latest_lts[1:]}")

for cos_milestone in [97, 105]:
    release_notes = fetch(f"https://cloud.google.com/feeds/cos-{cos_milestone}-release-notes.xml")
    tree = etree.XML(release_notes.encode('utf-8'))
    entries = tree.xpath("//*[local-name() = 'content']/text()")
    latest_entry = entries[0]
    version_tuple = checkOnlyOne(list(set(re.findall(f"cos-{cos_milestone}-(\d+)-(\d+)-(\d+)", latest_entry))), "too many versions were found")
    release_id = f"cos-{cos_milestone}-{'.'.join(version_tuple)}"
    commit = checkOnlyOne(re.findall("https://cos.googlesource.com/third_party/kernel/\+/([0-9a-f]{40})", latest_entry), "multiple commits were found")
    print(f"Latest COS {cos_milestone}: {release_id}, commit = {commit}")
    add_release(release_id, commit)

ghSet("OUTPUT", "releases=" + json.dumps(releases))
