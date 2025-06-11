#!/usr/bin/env bash

set -e

if ! command -v curl &> /dev/null || ! command -v jq &> /dev/null; then
    echo "Error: This script requires 'curl' and 'jq' to be installed." >&2
    exit 1
fi

API_URL="https://chromiumdash.appspot.com/fetch_releases?channel=Stable&platform=Linux&num=1"

VERSION=$(curl -s "${API_URL}" | jq -r '.[0].version') || exit 1

VERSION_REGEX='^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
if ! [[ "${VERSION}" =~ ${VERSION_REGEX} ]]; then
    echo "Error: returned version doesn't fit the expected format." >&2
    echo "Want: ${VERSION_REGEX}" >&2
    echo "Got: ${VERSION}" >&2
    exit 1
fi

MAJOR=$(echo "${VERSION}" | cut -d '.' -f 1)

KCTF_CTF_DIR="$(realpath --no-symlinks "$(dirname "${BASH_SOURCE-$0}")/..")"
CHALLENGE_DIR="${KCTF_CTF_DIR}/chrome-${MAJOR}"

if [[ -d "${CHALLENGE_DIR}" ]]; then
    echo "Challenge ${CHALLENGE_DIR} exists already, nothing to do."
    exit 0
fi

VERSIONS_TO_KEEP_ALIVE=3
TO_DELETE=$((MAJOR - ${VERSIONS_TO_KEEP_ALIVE}))
OLD_CHALLENGE_DIR="${KCTF_CTF_DIR}/chrome-${TO_DELETE}"

if [[ -d "${OLD_CHALLENGE_DIR}" ]]; then
    echo "Deleting old challenge directory ${OLD_CHALLENGE_DIR}"
    rm -R "${OLD_CHALLENGE_DIR}"
fi

"${KCTF_CTF_DIR}/scripts/create_challenge.sh" "${VERSION}"
