#!/bin/bash
set -e

# Resolve the directory this script lives in, so it can be invoked from anywhere.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$SCRIPT_DIR/venv/bin/python"

usage() {
    echo "Usage: $0 [--auth-cookies NAME[,NAME...]] [--no-auto-detect-auth-cookies] <burp_export_xml> [project_dir]"
    echo ""
    echo "  --auth-cookies                 Additional authentication/session cookie names."
    echo "  --no-auto-detect-auth-cookies  Disable automatic login-cookie detection (on by default)."
    echo "  <burp_export_xml>              Path to the Burp Suite XML export."
    echo "  [project_dir]                  Directory where intermediate JSON and chroma_db"
    echo "                                 are written. Defaults to the current directory."
    exit 1
}

AUTH_COOKIE_ARGS=()
AUTO_DETECT_FLAG=()
POSITIONAL=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        --auth-cookies)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                echo "Error: --auth-cookies requires at least one cookie name"
                usage
            fi
            AUTH_COOKIE_ARGS+=("$2")
            shift 2
            ;;
        --auth-cookies=*)
            if [ -z "${1#*=}" ]; then
                echo "Error: --auth-cookies requires at least one cookie name"
                usage
            fi
            AUTH_COOKIE_ARGS+=("${1#*=}")
            shift
            ;;
        --no-auto-detect-auth-cookies)
            AUTO_DETECT_FLAG=(--no-auto-detect-auth-cookies)
            shift
            ;;
        --help|-h)
            usage
            ;;
        --*)
            echo "Error: unknown option: $1"
            usage
            ;;
        *)
            POSITIONAL+=("$1")
            shift
            ;;
    esac
done

if [ "${#POSITIONAL[@]}" -lt 1 ] || [ "${#POSITIONAL[@]}" -gt 2 ]; then
    usage
fi

INPUT_XML="${POSITIONAL[0]}"
PROJECT_DIR="${POSITIONAL[1]:-$PWD}"

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

BASENAME=$(basename "$INPUT_XML")
BASENAME="${BASENAME%.*}"

PARSED_JSON="$PROJECT_DIR/parsed_${BASENAME}.json"
ANNOTATED_JSON="$PROJECT_DIR/annotated_${BASENAME}.json"
STRUCTURE_JSON="$PROJECT_DIR/structure_${BASENAME}.json"
BEHAVIOR_JSON="$PROJECT_DIR/behavior_${BASENAME}.json"
DB_PATH="$PROJECT_DIR/chroma_db"

echo "Project directory: $PROJECT_DIR"
echo "Step 1/5: Parsing $INPUT_XML ..."
"$PYTHON" "$SCRIPT_DIR/parse.py" "$INPUT_XML" -o "$PARSED_JSON"

echo "Step 2/5: Normalising + annotating (SPA/boilerplate/security passes) ..."
NORMALIZE_ARGS=("$PARSED_JSON" -o "$ANNOTATED_JSON")
for auth_cookies in "${AUTH_COOKIE_ARGS[@]}"; do
    NORMALIZE_ARGS+=(--auth-cookies "$auth_cookies")
done
NORMALIZE_ARGS+=("${AUTO_DETECT_FLAG[@]}")
"$PYTHON" "$SCRIPT_DIR/normalize.py" "${NORMALIZE_ARGS[@]}"

echo "Step 3/5: Building the 'structure' collection (site map + entities + semantic segments) ..."
"$PYTHON" "$SCRIPT_DIR/build_structure.py" "$ANNOTATED_JSON" -o "$STRUCTURE_JSON"
"$PYTHON" "$SCRIPT_DIR/vector_store.py" "$STRUCTURE_JSON" --db-path "$DB_PATH" --collection structure

echo "Step 4/5: Building the 'behavior' collection (distinct behaviors + semantic segments) ..."
"$PYTHON" "$SCRIPT_DIR/build_behavior.py" "$ANNOTATED_JSON" -o "$BEHAVIOR_JSON"
"$PYTHON" "$SCRIPT_DIR/vector_store.py" "$BEHAVIOR_JSON" --db-path "$DB_PATH" --collection behavior

echo "Step 5/5: Done. The 'attacks' collection is created on demand by"
echo "          jeb-query's record-attack during active testing."
echo ""
echo "Processing complete! Data stored in $PROJECT_DIR"
