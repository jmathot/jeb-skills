#!/usr/bin/env bash
# Install standalone OpenCode skills. No plugin registration or package downloads.
set -euo pipefail
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SOURCE_DIR/scripts/install_skills.py" "$@"
