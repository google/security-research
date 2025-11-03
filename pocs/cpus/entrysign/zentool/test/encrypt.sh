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
    if ${zentool} print ${ucode} | grep -qP '^Encrypted:.*true'; then
        ${zentool} --output=${tmpfile} decrypt ${ucode}
        if cmp --silent ${ucode} ${tmpfile}; then
            logerr "ERR: decrypt %s" "${ucode##*/}"
            exit 1
        fi
        ${zentool} --output=${tmpfile} encrypt ${tmpfile}
    else
        ${zentool} --output=${tmpfile} encrypt ${ucode}
        if cmp --silent ${ucode} ${tmpfile}; then
            logerr "ERR: encrypt %s" "${ucode##*/}"
            exit 1
        fi
        ${zentool} --output=${tmpfile} decrypt ${tmpfile}
    fi
    cmp --silent ${ucode} ${tmpfile}
    logmsg "OK: crypt %s" "${ucode##*/}"
done

rm -f ${tmpfile}
