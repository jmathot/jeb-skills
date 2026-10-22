#!/usr/bin/env bash
# Install the J.E.B.E.D.I.A.H. OpenCode V2 plugin; never downloads embedding models.
# Usage: ./install.sh [--copy] [--force] [--skip-deps] [embedding options]
#   --copy          copy instead of linking the checkout
#   --force         back up conflicting plugin/agent entries before replacement
#   --skip-deps     use already installed dependencies AND a prebuilt dist/
#   --preset        ollama-embeddinggemma2 | litellm-gemini-embedding-2 |
#                   litellm-qwen3-embedding-8b
#   --provider      OpenCode provider ID (LiteLLM defaults to litellm)
#   --base-url      explicit Ollama server or LiteLLM API base URL
#   --model         Ollama tag or LiteLLM gateway alias
#   --model-revision  pinned LiteLLM deployment revision (required for LiteLLM)
#   --api-key-env   name of an environment variable containing the gateway key
# OPENCODE_CONFIG_DIR overrides ${XDG_CONFIG_HOME:-$HOME/.config}/opencode.
# Python dependencies are prepared lazily on first tool use, not at host startup.
set -euo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
MODE=symlink FORCE=0 SKIP_DEPS=0
options=()
while [ $# -gt 0 ]; do
    case "$1" in
        --copy) MODE=copy; shift ;;
        --force) FORCE=1; shift ;;
        --skip-deps) SKIP_DEPS=1; shift ;;
        --preset|--provider|--base-url|--model|--model-revision|--api-key-env)
            [ $# -gt 1 ] && [ -n "$2" ] || { echo "Missing value for $1" >&2; exit 2; }
            options+=("$1" "$2"); shift 2 ;;
        -h|--help) sed -n '2,/^set -euo/{/^#/s/^# \{0,1\}//p;}' "$0"; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

command -v node >/dev/null || { echo 'Node 22.18+ is required.' >&2; exit 1; }
node -e 'const [major, minor] = process.versions.node.split(".").map(Number); if (major < 22 || (major === 22 && minor < 18)) { console.error("Node 22.18+ required"); process.exit(1) }'
command -v opencode >/dev/null || { echo 'OpenCode V2.1.3+ is required.' >&2; exit 1; }
version="$(opencode --version)"
node -e 'const m = process.argv[1].match(/(?:^|[^0-9])v?(\d+)\.(\d+)\.(\d+)/); if (!m || +m[1] !== 2 || +m[2] < 1 || (+m[2] === 1 && +m[3] < 3)) { console.error("OpenCode V2.1.3+ required"); process.exit(1) }' "$version"
python3 -c 'import sys; assert sys.version_info >= (3, 10), "Python 3.10+ required"'

CONFIG_DIR="${OPENCODE_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/opencode}"
mkdir -p "$CONFIG_DIR"
CONFIG_DIR="$(cd "$CONFIG_DIR" && pwd -P)"
PLUGIN_TARGET="$CONFIG_DIR/packages/jebediah"
AGENT_TARGET="$CONFIG_DIR/agents/jebediah.md"
REGISTRATION_TARGET="$PLUGIN_TARGET"
if [ "$MODE" = symlink ]; then REGISTRATION_TARGET="$SOURCE_DIR"; fi
case "$PLUGIN_TARGET/" in "$SOURCE_DIR/"*) echo 'Cannot install inside the source checkout.' >&2; exit 1 ;; esac

# Refuse ambiguous double-loading from the old automatic-discovery installation.
if [ -e "$CONFIG_DIR/plugins/jebediah" ] || [ -L "$CONFIG_DIR/plugins/jebediah" ]; then
    echo "Legacy plugin exists at $CONFIG_DIR/plugins/jebediah. Move it out of plugins/ before installing (do not delete an unfamiliar directory)." >&2
    exit 1
fi
preflight() {
    local source="$1" target="$2"
    if [ -L "$target" ] && [ "$(readlink "$target")" = "$source" ] && [ "$MODE" = symlink ]; then return; fi
    if { [ -e "$target" ] || [ -L "$target" ]; } && [ "$FORCE" -ne 1 ]; then
        echo "Conflict at $target. --force backs it up before replacement." >&2; exit 1
    fi
}
preflight "$SOURCE_DIR" "$PLUGIN_TARGET"
preflight "$SOURCE_DIR/agents/jebediah.md" "$AGENT_TARGET"

lock="$CONFIG_DIR/.jeb-install.lock"
mkdir "$lock" 2>/dev/null || { echo "Another installation holds $lock; check it before removing a stale lock." >&2; exit 1; }
stage="" committed=0
changed_targets=() target_backups=()
cleanup() {
    local status=$? i target backup
    set +e
    if [ "$committed" -ne 1 ]; then
        for ((i=${#changed_targets[@]}-1; i>=0; i--)); do
            target="${changed_targets[$i]}"; backup="${target_backups[$i]}"
            # These are only entries placed by this invocation; originals have
            # already been moved to the corresponding backup.
            rm -rf -- "$target"
            if [ -n "$backup" ]; then mv "$backup" "$target"; fi
        done
    fi
    if [ -n "$stage" ]; then rm -rf -- "$stage"; fi
    rmdir "$lock"
    exit "$status"
}
trap cleanup EXIT

if [ "$SKIP_DEPS" -ne 1 ]; then
    command -v npm >/dev/null || { echo 'npm is required (or preinstall dependencies and use --skip-deps).' >&2; exit 1; }
    npm --prefix "$SOURCE_DIR" ci --ignore-scripts
    npm --prefix "$SOURCE_DIR" run build
fi
[ -f "$SOURCE_DIR/dist/index.js" ] || { echo 'Build output is missing. Run npm ci --ignore-scripts and npm run build first.' >&2; exit 1; }
node "$SOURCE_DIR/scripts/install-config.mjs" check "$CONFIG_DIR" "$REGISTRATION_TARGET" "${options[@]}"
mkdir -p "$CONFIG_DIR/packages" "$CONFIG_DIR/agents"

stage="$(mktemp -d "$CONFIG_DIR/packages/.jeb-install.XXXXXX")"
if [ "$MODE" = copy ]; then
    mkdir "$stage/package"
    tar -C "$SOURCE_DIR" --exclude=.git --exclude=engine/.venv --exclude='engine/.venv.lock' --exclude=tests/.work --exclude='tests/.ts-build.*' --exclude=node_modules --exclude=__pycache__ -cf - . | tar -C "$stage/package" -xf -
    if [ "$SKIP_DEPS" -ne 1 ]; then npm --prefix "$stage/package" ci --ignore-scripts --omit=dev; fi
fi
cp "$SOURCE_DIR/agents/jebediah.md" "$stage/agent.md"
place() {
    local source="$1" target="$2" backup=""
    if [ -L "$target" ] && [ "$(readlink "$target")" = "$source" ] && [ "$MODE" = symlink ]; then return; fi
    if [ -e "$target" ] || [ -L "$target" ]; then
        backup="$target.backup.$(date +%s).$$"
        mv "$target" "$backup"
        echo "Backed up $target to $backup"
    fi
    changed_targets+=("$target")
    target_backups+=("$backup")
    if [ "$MODE" = symlink ]; then ln -s "$source" "$target"; else mv "$source" "$target"; fi
}
if [ "$MODE" = symlink ]; then
    place "$SOURCE_DIR" "$PLUGIN_TARGET"
    place "$SOURCE_DIR/agents/jebediah.md" "$AGENT_TARGET"
else
    place "$stage/package" "$PLUGIN_TARGET"
    place "$stage/agent.md" "$AGENT_TARGET"
fi
node "$SOURCE_DIR/scripts/install-config.mjs" write "$CONFIG_DIR" "$REGISTRATION_TARGET" "${options[@]}"
committed=1
echo "Installed J.E.B.E.D.I.A.H. at $PLUGIN_TARGET"
echo 'Restart OpenCode if needed, then select the jebediah primary agent.'
echo 'Python dependencies are installed on first tool use. No embedding models were downloaded or called.'
echo 'See README.md for the three presets, manual model checks, and removal instructions.'
