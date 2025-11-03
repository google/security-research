#!/usr/bin/env bash

set -e

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <chrome-version>" >&2
    echo "Example: $0 137.0.7151.55" >&2
    exit 1
fi

VERSION=$1

VERSION_REGEX='^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
if ! [[ "${VERSION}" =~ ${VERSION_REGEX} ]]; then
    echo "Error: Invalid version format." >&2
    echo "The version must be a valid Chrome version (e.g., 137.0.7151.55)" >&2
    exit 1
fi

MAJOR=$(echo "${VERSION}" | cut -d '.' -f 1)

KCTF_CTF_DIR="$(realpath --no-symlinks "$(dirname "${BASH_SOURCE-$0}")/..")"

source "${KCTF_CTF_DIR}/kctf/activate"

CHALLENGE_DIR="${KCTF_CTF_DIR}/chrome-${MAJOR}"

kctf chal create --template chrome --challenge-dir "${CHALLENGE_DIR}" "chrome-${MAJOR}"
echo "${VERSION}" > "${CHALLENGE_DIR}/challenge/version"

echo "Created challenge at ${CHALLENGE_DIR}"

deactivate >/dev/null 2>&1
