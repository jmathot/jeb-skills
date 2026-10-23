#!/usr/bin/env bash
# Offline by default. Live costs require --live --revision REVISION.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python="$here/../jeb-import/scripts/venv/bin/python"
[ -x "$python" ] || python="$(command -v python3)"
args=()
while [ $# -gt 0 ]; do
  case "$1" in
    --python) [ $# -ge 2 ] || { echo '--python requires a path' >&2; exit 2; }; python="$2"; shift 2 ;;
    *) args+=("$1"); shift ;;
  esac
done
exec "$python" "$here/run.py" "${args[@]}"
