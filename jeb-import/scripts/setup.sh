#!/usr/bin/env bash
# Explicit setup only. Never downloads or calls an embedding model.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/setup_environment.py" "$@"
