#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$SCRIPT_DIR/venv/bin/python"
if [ ! -x "$PYTHON" ]; then
    echo "Run bash \"$SCRIPT_DIR/setup.sh\" --viz first." >&2
    exit 1
fi
exec "$PYTHON" "$SCRIPT_DIR/visualize.py" "$@"
