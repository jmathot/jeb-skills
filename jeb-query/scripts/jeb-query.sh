#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$SCRIPT_DIR/../../jeb-import/scripts/venv/bin/python"

if [ ! -x "$PYTHON" ]; then
    echo "Error: venv not found at $PYTHON"
    echo "Run the jeb-import skill's one-time setup step first."
    exit 1
fi

exec "$PYTHON" "$SCRIPT_DIR/agent_interface.py" "$@"
