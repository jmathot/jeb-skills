#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$SCRIPT_DIR/venv/bin/python"
if [ ! -x "$PYTHON" ]; then
    echo "Create the shared environment first:"
    echo "python3 -m venv \"$SCRIPT_DIR/venv\""
    echo "\"$SCRIPT_DIR/venv/bin/pip\" install -r \"$SCRIPT_DIR/requirements.txt\""
    exit 1
fi
exec "$PYTHON" "$SCRIPT_DIR/import_project.py" "$@"
