#!/usr/bin/env bash

set -e

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 MAJOR path/to/exploit.tar.gz" >&2
    echo "Example: $0 137 ~/Downloads/exploit.tar.gz" >&2
    exit 1
fi

MAJOR=$1
EXPLOIT_PATH=$2

VERSION_REGEX='^[0-9]+$'
if ! [[ "${MAJOR}" =~ ${VERSION_REGEX} ]]; then
    echo "Error: Invalid version format." >&2
    echo "The version must be a valid major version (e.g. 137)" >&2
    exit 1
fi

if ! [[ -f "${EXPLOIT_PATH}" ]]; then
    echo "Error: File not found at the specified path: '${EXPLOIT_PATH}'" >&2
    exit 1
fi

FILENAME=$(basename -- "${EXPLOIT_PATH}")
if [[ "${FILENAME}" != "exploit.tar.gz" ]]; then
    echo "Error: Filename must be 'exploit.tar.gz', but found '${FILENAME}'." >&2
    exit 1
fi

KCTF_CTF_DIR="$(realpath --no-symlinks "$(dirname "${BASH_SOURCE-$0}")/..")"
CHALLENGE_DIR="${KCTF_CTF_DIR}/chrome-${MAJOR}"
REPRO_CHROME_DIR="${KCTF_CTF_DIR}/repro-chrome"
REPRO_EXPLOIT_DIR="${KCTF_CTF_DIR}/repro-exploit"

if [[ ! -d "${CHALLENGE_DIR}" ]]; then
    echo "Error: challenge dir does not exist '${CHALLENGE_DIR}'." >&2
    exit 1
fi

if [[ -d "${REPRO_CHROME_DIR}" ]]; then
    echo "Error: dir already exists '${REPRO_CHROME_DIR}'." >&2
    exit 1
fi
if [[ -d "${REPRO_EXPLOIT_DIR}" ]]; then
    echo "Error: dir already exists '${REPRO_EXPLOIT_DIR}'." >&2
    exit 1
fi

source "${KCTF_CTF_DIR}/kctf/activate"

kctf chal create --template repro-chrome --challenge-dir "${REPRO_CHROME_DIR}" "repro-chrome"
kctf chal create --template repro-exploit --challenge-dir "${REPRO_EXPLOIT_DIR}" "repro-exploit"

function on_exit() {
    echo "Trying to delete kctf challenges"
    kubectl delete challenge/repro-chrome || true
    kubectl delete challenge/repro-exploit || true
    echo "Trying to delete directory ${REPRO_CHROME_DIR}"
    rm -R "${REPRO_CHROME_DIR}" || true
    echo "Trying to delete directory ${REPRO_EXPLOIT_DIR}"
    rm -R "${REPRO_EXPLOIT_DIR}" || true
    if [[ ! -z "${NC_OUT}" ]]; then
        rm "${NC_OUT}" 2>/dev/null || true
    fi

    deactivate >/dev/null 2>&1
}
trap on_exit EXIT

ln -s "${CHALLENGE_DIR}/challenge/Dockerfile" "${REPRO_CHROME_DIR}/challenge/Dockerfile"
ln -s "${CHALLENGE_DIR}/challenge/version" "${REPRO_CHROME_DIR}/challenge/version"
ln -s "${CHALLENGE_DIR}/challenge/nsjail.cfg" "${REPRO_CHROME_DIR}/challenge/nsjail.cfg"
rm "${REPRO_EXPLOIT_DIR}/challenge/exploit.tar.gz"
ln -s "${EXPLOIT_PATH}" "${REPRO_EXPLOIT_DIR}/challenge/exploit.tar.gz"

pushd "${REPRO_EXPLOIT_DIR}"
  kctf chal start
popd

pushd "${REPRO_CHROME_DIR}"
  kctf chal start
  kubectl wait --for=jsonpath='{.status.status}'=Running challenge/repro-exploit
  kubectl wait --for=jsonpath='{.status.status}'=Running challenge/repro-chrome

  PORT_FORWARD_OUT_FILE=$(mktemp)
  kctf chal debug port-forward > "${PORT_FORWARD_OUT_FILE}" 2>&1 &
  PORT_FORWARD_PID=$!
  echo "Started port forward with PID: ${PORT_FORWARD_PID}"
  PORT=""
  for i in {1..10}; do
      PORT=$(grep "Forwarding from" "${PORT_FORWARD_OUT_FILE}" | sed -E 's/.*:([0-9]+).*/\1/')
      if [[ -n "${PORT}" ]]; then
          break
      fi
      sleep 1
  done
  if [[ -z "${PORT}" ]]; then
      echo "Error: Could not parse port from command output after 10 seconds." >&2
      echo "--- Full output from kctf command ---" >&2
      cat "${PORT_FORWARD_OUT_FILE}" >&2
      rm "${PORT_FORWARD_OUT_FILE}"
      exit 1
  fi
  rm "${PORT_FORWARD_OUT_FILE}"
popd

TRIES=10
TIMEOUT_SECONDS=300
SLEEP_SECONDS=5
MAX_LOOP=$(( TIMEOUT_SECONDS / SLEEP_SECONDS ))
FLAG_REGEX='v8CTF\{.*\}'

success_cnt=0
for ((i = 0 ; i < ${TRIES} ; i++ )); do
    NC_OUT=$(mktemp)
    nc localhost "${PORT}" > "${NC_OUT}"  2>&1 &
    NC_PID=$!

    for ((j = 0 ; j < ${MAX_LOOP} ; j++ )); do
        FLAG="$(grep --only-matching --max-count 1 --no-filename -E "${FLAG_REGEX}" "${NC_OUT}" || true)"
        if [[ ! -z "${FLAG}" ]]; then
            break;
        fi
        sleep "${SLEEP_SECONDS}"
    done
    kill -SIGTERM ${NC_PID} || true
    rm "${NC_OUT}"

    REAL_FLAG="$(kubectl get secret v8ctf-flag -o=jsonpath='{.data.flag}' | base64 -d)"
    if [[ "${FLAG}" == "${REAL_FLAG}" ]]; then
        echo "Try $i: success (${FLAG})"
        success_cnt="$(( success_cnt + 1 ))"
    else
        if [[ ! -z "${FLAG}" ]]; then
            echo "Got an invalid flag: ${FLAG} (real flag: ${REAL_FLAG})" >&2
        fi
        echo "Try $i: fail"
    fi
done

echo "success rate: ${success_cnt} / ${TRIES}"

#timeout --foreground "${TIMEOUT_SECONDS}s" tail --follow -n +1 | grep --only-matching --max-count 1 --no-filename -E "${FLAG_REGEX}"

#if timeout --foreground "${TIMEOUT_SECONDS}s" nc localhost "${PORT}" 2>&1 | grep --only-matching --max-count 1 --no-filename -E "${FLAG_REGEX}"; then
#    echo "success"
#else
#    echo "fail"
#fi
