#!/bin/sh
# ./build.sh          sign config/lineageos.json's compiled release with LINEAGEOS_SECRETS_DIR
# ./build.sh prepare  sync, extract vendor files and compile only (operator pre-warm)
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
"$root/install-dependencies.sh"
exec python3 "$root/build.py" "$@"
