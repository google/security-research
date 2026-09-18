#!/bin/bash
set -e

TRY_ID="$1"

if [[ "$RELEASE_ID" == android* ]]; then
    SCRIPT="repro_android.sh"
elif [[ "$RELEASE_ID" == hardened* ]]; then
    SCRIPT="repro_hardened.sh"
else
    SCRIPT="repro_old.sh"
fi

SCRIPT_DIR="$(dirname "$(realpath "$0")")"
exec bash "$SCRIPT_DIR/$SCRIPT" "$TRY_ID"
