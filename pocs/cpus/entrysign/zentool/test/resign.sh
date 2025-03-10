#!/bin/bash
# Copyright 2025 Google LLC
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

source testing.sh

declare tmpfile=$(mktemp)

for ucode in ../data/*.bin; do
    if ! ${zentool} --quiet verify ${ucode}; then
        logmsg "SKIPPED: %s" "${ucode##*/}"
        continue
    fi
    ${zentool} --output=${tmpfile} edit --hdr-revinc ${ucode}
    if ${zentool} --quiet verify ${tmpfile}; then
        logerr "ERR: verify %s" "${ucode##*/}"
        exit 1
    fi
    ${zentool} resign ${tmpfile}
    ${zentool} --quiet verify ${tmpfile}
    logmsg "OK: signature %s" "${ucode##*/}"
done

rm -f ${tmpfile}
