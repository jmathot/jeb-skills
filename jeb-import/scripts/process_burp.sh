#!/bin/bash
set -e

# Resolve the directory this script lives in, so it can be invoked from anywhere.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$SCRIPT_DIR/venv/bin/python"

usage() {
    echo "Usage: $0 <burp_export_xml> [project_dir]"
    echo ""
    echo "  <burp_export_xml>  Path to the Burp Suite XML export."
    echo "  [project_dir]      Directory where intermediate JSON and chroma_db"
    echo "                     are written. Defaults to the current directory."
    exit 1
}

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    usage
fi

INPUT_XML="$1"
# Project directory: explicit 2nd arg, else current working directory.
PROJECT_DIR="${2:-$PWD}"

if [ ! -f "$INPUT_XML" ]; then
    echo "Error: input XML not found: $INPUT_XML"
    exit 1
fi

if [ ! -x "$PYTHON" ]; then
    echo "Error: venv not found at $PYTHON"
    echo "Create it once with:"
    echo "  python3 -m venv \"$SCRIPT_DIR/venv\""
    echo "  \"$SCRIPT_DIR/venv/bin/pip\" install -r \"$SCRIPT_DIR/requirements.txt\""
    exit 1
fi

mkdir -p "$PROJECT_DIR"

# get filename without extension and directory
BASENAME=$(basename "$INPUT_XML")
BASENAME="${BASENAME%.*}"

PARSED_JSON="$PROJECT_DIR/parsed_${BASENAME}.json"
WEBCODE_JSON="$PROJECT_DIR/webcode_${BASENAME}.json"
CHUNKS_JSON="$PROJECT_DIR/chunks_${BASENAME}.json"
CODECHUNKS_JSON="$PROJECT_DIR/codechunks_${BASENAME}.json"
DB_PATH="$PROJECT_DIR/chroma_db"

echo "Project directory: $PROJECT_DIR"
echo "Step 1: Ingesting $INPUT_XML..."
"$PYTHON" "$SCRIPT_DIR/ingest.py" "$INPUT_XML" -o "$PARSED_JSON" --webcode-output "$WEBCODE_JSON"

echo "Step 2: Chunking $PARSED_JSON..."
"$PYTHON" "$SCRIPT_DIR/chunker.py" "$PARSED_JSON" -o "$CHUNKS_JSON"

echo "Step 3: Embedding $CHUNKS_JSON into ChromaDB collection 'burp_traffic' at $DB_PATH..."
"$PYTHON" "$SCRIPT_DIR/vector_store.py" "$CHUNKS_JSON" --db-path "$DB_PATH" --collection burp_traffic

echo "Step 4: Extracting web application code from $WEBCODE_JSON..."
"$PYTHON" "$SCRIPT_DIR/code_extractor.py" "$WEBCODE_JSON" -o "$CODECHUNKS_JSON"

echo "Step 5: Embedding $CODECHUNKS_JSON into ChromaDB collection 'web_code' at $DB_PATH..."
"$PYTHON" "$SCRIPT_DIR/vector_store.py" "$CODECHUNKS_JSON" --db-path "$DB_PATH" --collection web_code

echo "Processing complete! Data stored in $PROJECT_DIR"
