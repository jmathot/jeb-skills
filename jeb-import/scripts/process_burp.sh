#!/bin/bash
# Compatibility alias for <jeb-import skill dir>/jeb (import, rebuild, status, abandon, export).
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../jeb" "$@"
