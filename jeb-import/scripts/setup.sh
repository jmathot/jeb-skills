#!/usr/bin/env bash
# Compatibility alias for <jeb-import skill dir>/jeb setup. Never downloads or calls a model.
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../jeb" setup "$@"
