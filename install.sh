#!/usr/bin/env bash
# Install the J.E.B.E.D.I.A.H. OpenCode v2 plugin.
#
# Symlinks this repo into OpenCode's plugin directory and the agent definition into
# its agent directory, so the plugin loads in every engagement project and the
# J.E.B.E.D.I.A.H. agent is Tab-selectable. The plugin auto-bootstraps its Python
# engine venv on first load, so this script does not build it.
#
# Usage: ./install.sh [--copy] [--force]
#   --copy    copy files instead of symlinking (symlink is the default so repo
#             updates take effect without reinstalling).
#   --force   replace an existing plugin/agent entry even if it is a real file/dir.
#
# Override the config location with OPENCODE_CONFIG_DIR (default:
# ${XDG_CONFIG_HOME:-$HOME/.config}/opencode).

set -euo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${OPENCODE_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/opencode}"
PLUGIN_DIR="$CONFIG_DIR/plugins"
AGENT_DIR="$CONFIG_DIR/agents"

MODE="symlink"
FORCE=0
for arg in "$@"; do
    case "$arg" in
        --copy) MODE="copy" ;;
        --force) FORCE=1 ;;
        -h|--help) sed -n '2,/^set -euo/{/^#/s/^# \{0,1\}//p;}' "$0"; exit 0 ;;
        *) echo "Unknown option: $arg" >&2; exit 2 ;;
    esac
done

PLUGIN_TARGET="$PLUGIN_DIR/jebediah"
AGENT_TARGET="$AGENT_DIR/jebediah.md"
AGENT_SOURCE="$SOURCE_DIR/agents/jebediah.md"

mkdir -p "$PLUGIN_DIR" "$AGENT_DIR"

# Place a single source at a target path, honoring --copy / --force.
install_entry() {
    local src="$1" dest="$2" label="$3"
    if [ -L "$dest" ]; then
        rm "$dest"                       # replace any existing symlink
    elif [ -e "$dest" ]; then
        if [ "$FORCE" -eq 1 ]; then
            rm -rf "$dest"
        else
            echo "✗ $label already exists at $dest (not a symlink). Re-run with --force to replace it." >&2
            exit 1
        fi
    fi

    if [ "$MODE" = "copy" ]; then
        cp -R "$src" "$dest"
        echo "✓ copied $label → $dest"
    else
        ln -s "$src" "$dest"
        echo "✓ linked $label → $dest"
    fi
}

echo "Installing J.E.B.E.D.I.A.H. from $SOURCE_DIR"
echo "OpenCode config dir: $CONFIG_DIR"
echo

install_entry "$SOURCE_DIR" "$PLUGIN_TARGET" "plugin"
install_entry "$AGENT_SOURCE" "$AGENT_TARGET" "agent"

echo
# Prerequisite checks (warnings only; the plugin reports the real error if used
# before these are satisfied).
if ! command -v python3 >/dev/null 2>&1; then
    echo "⚠ python3 not found on PATH — the engine venv cannot be bootstrapped."
fi

MODEL="embeddinggemma:latest"
if command -v ollama >/dev/null 2>&1; then
    if ollama list 2>/dev/null | grep -q "${MODEL%%:*}"; then
        echo "✓ Ollama model $MODEL present"
    else
        echo "… pulling Ollama model $MODEL"
        ollama pull "$MODEL" || echo "⚠ could not pull $MODEL; run 'ollama pull $MODEL' manually."
    fi
else
    echo "⚠ ollama not found on PATH — install it and run 'ollama pull $MODEL'."
fi

echo
echo "Done. Restart OpenCode, then select J.E.B.E.D.I.A.H. with Tab."
echo "On first load the plugin builds its Python engine venv (one-time)."
echo "Add plugin options from opencode.jsonc to your opencode.json(c) to tune the RAG."
