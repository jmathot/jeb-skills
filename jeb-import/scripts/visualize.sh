#!/usr/bin/env bash
# Compatibility alias for <jeb-import skill dir>/jeb viz.
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../jeb" viz "$@"
