#!/bin/bash
# Install the jeb-import and jeb-query skills, and the J.E.B.E.D.I.A.H.
# agent, into the OpenCode config directory.

set -e

# Define paths
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENCODE_SKILL_DIR="${HOME}/.config/opencode/skill"
OPENCODE_AGENT_DIR="${HOME}/.config/opencode/agent"
AGENT_FILENAME="J.E.B.E.D.I.A.H..md"

# Skills to install
SKILLS=("jeb-import" "jeb-query")

echo "Installing OpenCode skills..."
echo "Source directory: $SOURCE_DIR"
echo "Target directory: $OPENCODE_SKILL_DIR"
echo ""

# Create target directory if it doesn't exist
mkdir -p "$OPENCODE_SKILL_DIR"

# Copy each skill
for skill in "${SKILLS[@]}"; do
    source_path="$SOURCE_DIR/$skill"
    target_path="$OPENCODE_SKILL_DIR/$skill"
    
    if [ ! -d "$source_path" ]; then
        echo "❌ Error: Source skill directory not found: $source_path"
        exit 1
    fi
    
    echo "Installing $skill..."
    
    # Update sources while preserving the installed environment and local files.
    mkdir -p "$target_path/scripts"
    cp "$source_path/SKILL.md" "$target_path/SKILL.md"
    for file in "$source_path"/scripts/*; do
        [ -f "$file" ] || continue
        cp "$file" "$target_path/scripts/"
    done
    echo "  ✓ $skill installed successfully"
done

# The agent is what the user switches to with Tab; it carries the pentesting
# methodology that must not live in the vector index.
echo "Installing the J.E.B.E.D.I.A.H. agent..."
mkdir -p "$OPENCODE_AGENT_DIR"
if [ -f "$OPENCODE_AGENT_DIR/jebediah.md" ]; then
    rm "$OPENCODE_AGENT_DIR/jebediah.md"
fi
cp "$SOURCE_DIR/agent/$AGENT_FILENAME" "$OPENCODE_AGENT_DIR/$AGENT_FILENAME"
echo "  ✓ agent installed to $OPENCODE_AGENT_DIR/$AGENT_FILENAME"

echo ""
echo "✓ All skills installed successfully!"
echo ""
echo "Skills are now available at:"
for skill in "${SKILLS[@]}"; do
    echo "  - $OPENCODE_SKILL_DIR/$skill"
done
echo ""
echo "Switch to the J.E.B.E.D.I.A.H. agent in OpenCode with the Tab key."
