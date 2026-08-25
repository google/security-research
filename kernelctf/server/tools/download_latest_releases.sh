#!/bin/bash
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

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." &>/dev/null && pwd)"
cd "$REPO_ROOT"

STAGING_DIR="$REPO_ROOT/data/staging"
mkdir -p "$STAGING_DIR"

gcloud auth activate-service-account --key-file="secrets/kernelctf-vm-reader-sa-key.json"

echo "Getting all releases..."
gsutil ls gs://kernelctf-build/releases/ > /tmp/kernelctf_releases.txt

DAY_OF_WEEK=$(date +%u)  # Monday is 1, Tuesday is 2, ..., Sunday is 7

TARGET="lts-6.12"
RELEASE=$(sed -nr "s/.*($TARGET[0-9.]+)\//\1/p" /tmp/kernelctf_releases.txt | sort -Vr | head -n1)
KASAN_RELEASE="${RELEASE}-kasan"
DOWNLOAD_RELEASES=("$RELEASE" "$KASAN_RELEASE")

if [[ $DAY_OF_WEEK -le 3 ]]; then
  # Monday to Wednesday: release new slot on this week's Friday
  DAYS_UNTIL_RELEASE=$(( 5 - $DAY_OF_WEEK ))
  RELEASE_TIME_TEXT="this Friday"
else
  # Thursday to Friday: release new slot on next week's Friday
  DAYS_UNTIL_RELEASE=$(( 12 - $DAY_OF_WEEK ))
  RELEASE_TIME_TEXT="next Friday"
fi

for REL in "${DOWNLOAD_RELEASES[@]}"; do
    echo -n "Target release: $REL - "
    
    if [ ! -d "$STAGING_DIR/$REL" ]; then
        echo "NEW !!!"
    else
        echo "already downloaded"
    fi
done

YAML=""
RELEASES=""

RELEASE_TIME="$(date -d "+$DAYS_UNTIL_RELEASE days" +%Y-%m-%d)T12:00:00Z"
echo "Release time: $RELEASE_TIME ($RELEASE_TIME_TEXT)"

for REL in "${DOWNLOAD_RELEASES[@]}"; do
    if [ ! -d "$STAGING_DIR/$REL" ]; then
        if [ "$REL" == "$RELEASE" ]; then
            YAML="${YAML}${REL}:\n  release-date: ${RELEASE_TIME}\n"
        fi
        RELEASES="${RELEASES}\`${REL}\`, "

        echo "NEW, downloading $REL..."
        echo " ================ "
        mkdir -p "$STAGING_DIR/$REL"
        gsutil rsync -rx '.*vmlinux.gz|.*dbgsym.*' "gs://kernelctf-build/releases/$REL" "$STAGING_DIR/$REL"
        echo $' ================ \n' 
    fi
done

echo
echo " === config/releases.yaml === "
printf "$YAML"
echo " ============================ "

RELEASES_YAML="config/releases.yaml"
[ ! -f "$RELEASES_YAML" ] && RELEASES_YAML="releases.yaml"

if [ -n "$YAML" ]; then
    read -p "Do you want to apply changes to $RELEASES_YAML? [y/n] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sed -i "1s/^/${YAML}\n/" "$RELEASES_YAML"
    fi

    echo
    echo "Hey! We are releasing the following targets at \`${RELEASE_TIME}\` ($RELEASE_TIME_TEXT): ${RELEASES:0:-2}."
else
    echo "No new releases to download."
fi
rm -f /tmp/kernelctf_releases.txt
