#!/bin/bash
# Install jeb-import and jeb-query skills to OpenCode config directory

set -e

# Define paths
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENCODE_SKILL_DIR="${HOME}/.config/opencode/skill"

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
    
    # Remove existing skill if it exists
    if [ -d "$target_path" ]; then
        echo "  Removing existing installation at $target_path"
        rm -rf "$target_path"
    fi
    
    # Copy the skill directory
    cp -r "$source_path" "$target_path"
    echo "  ✓ $skill installed successfully"
done

echo ""
echo "✓ All skills installed successfully!"
echo ""
echo "Skills are now available at:"
for skill in "${SKILLS[@]}"; do
    echo "  - $OPENCODE_SKILL_DIR/$skill"
done
