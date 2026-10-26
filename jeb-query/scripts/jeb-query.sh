#!/bin/bash
# Compatibility alias for <jeb-query skill dir>/jeb.
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../jeb" "$@"
