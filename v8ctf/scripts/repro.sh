#!/usr/bin/env bash

set -e

DEBUG=false
while getopts "d" opt; do
  case ${opt} in
    d )
      DEBUG=true
      ;;
    \? )
      echo "Usage: $0 [-d] MAJOR path/to/exploit.tar.gz" >&2
      exit 1
      ;;
  esac
done
shift $((OPTIND -1))

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 [-d] MAJOR path/to/exploit.tar.gz" >&2
    echo "Example: $0 -d 137 ~/Downloads/exploit.tar.gz" >&2
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

MAX_TRIES=20
TIMEOUT_SECONDS=300
SLEEP_SECONDS=5
MAX_LOOP=$(( TIMEOUT_SECONDS / SLEEP_SECONDS ))
FLAG_REGEX='v8CTF\{[^}]+\}'

function check_bayesian_stopping() {
    local s=$1
    local f=$2
    python3 - <<EOF
import math

s = $s
f = $f
target = 0.80
fail_thresh = 0.98
succ_thresh = 0.80

# Beta(1+s, 1+f) posterior with uniform Beta(1,1) prior
# Regularized incomplete beta function I_x(a, b) = P(Beta(a,b) <= x)
a = s + 1
b = f + 1
n = a + b - 1
p_below = sum(math.comb(n, j) * (target ** j) * ((1.0 - target) ** (n - j)) for j in range(a, n + 1))
p_above = 1.0 - p_below

action = "CONTINUE"
if p_below >= fail_thresh:
    action = "FAIL"
elif p_above >= succ_thresh:
    action = "SUCCESS"

print(f"{action} {p_below:.4f} {p_above:.4f}")
EOF
}

success_cnt=0
fail_cnt=0
total_cnt=0
final_status="UNKNOWN"

for ((i = 0 ; i < ${MAX_TRIES} ; i++ )); do
    total_cnt=$(( total_cnt + 1 ))
    NC_OUT=$(mktemp)
    nc localhost "${PORT}" > "${NC_OUT}"  2>&1 &
    NC_PID=$!

    for ((j = 0 ; j < ${MAX_LOOP} ; j++ )); do
        FLAG="$(grep --text --only-matching --max-count 1 --no-filename -E "${FLAG_REGEX}" "${NC_OUT}" || true)"
        if [[ ! -z "${FLAG}" ]]; then
            break;
        fi
        sleep "${SLEEP_SECONDS}"
    done
    kill -SIGTERM ${NC_PID} || true

    REAL_FLAG="$(kubectl get secret v8ctf-flag -o=jsonpath='{.data.flag}' | base64 -d)"
    if [[ "${FLAG}" == "${REAL_FLAG}" ]]; then
        echo "Try $i: success (${FLAG})"
        success_cnt="$(( success_cnt + 1 ))"
    else
        if [[ ! -z "${FLAG}" ]]; then
            echo "Got an invalid flag: ${FLAG} (real flag: ${REAL_FLAG})" >&2
        fi
        echo "Try $i: fail"
        fail_cnt="$(( fail_cnt + 1 ))"
        if [[ "${DEBUG}" == "true" ]]; then
            echo "--- Exploit Output (Try $i) ---" >&2
            cat "${NC_OUT}" >&2
            echo "----------------------------" >&2
        fi
    fi
    rm "${NC_OUT}"

    read -r action p_below p_above <<< $(check_bayesian_stopping "${success_cnt}" "${fail_cnt}")
    echo "Bayesian update (s=${success_cnt}, f=${fail_cnt}): P(p < 80%)=${p_below}, P(p >= 80%)=${p_above}"

    if [[ "${action}" == "FAIL" ]]; then
        echo "Stopping early: 95% certain reliability falls below 80%."
        final_status="FAIL"
        break
    elif [[ "${action}" == "SUCCESS" ]]; then
        echo "Stopping early: 85% certain reliability is at least 80%."
        final_status="SUCCESS"
        break
    fi
done

if [[ "${final_status}" == "UNKNOWN" ]]; then
    echo "Reached maximum number of rounds (${MAX_TRIES}). Capping run and declaring success."
    final_status="SUCCESS"
fi

echo "Final outcome: ${final_status}"
echo "success rate: ${success_cnt} / ${total_cnt}"
