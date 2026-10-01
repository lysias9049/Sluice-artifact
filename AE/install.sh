#!/usr/bin/env bash
set -euo pipefail
AE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$AE_ROOT/run.py" ]]; then
    AE_RUNNER="$AE_ROOT/run.py"
elif [[ -f "$AE_ROOT/rwg-artifact-sp2027/AE/run.py" ]]; then
    AE_RUNNER="$AE_ROOT/rwg-artifact-sp2027/AE/run.py"
elif [[ -f "AE/run.py" ]]; then
    AE_RUNNER="AE/run.py"
else
    echo "Extract the artifact archive next to this script, or run from the extracted root." >&2
    exit 1
fi
exec python3 "$AE_RUNNER" build "$@"
