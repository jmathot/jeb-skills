# J.E.B.E.D.I.A.H. (John's Extension for Burpsuite Export Data Ingestion And Handling)

## Project Overview
This project provides a Retrieval-Augmented Generation (RAG) framework designed specifically to ingest, parse, and structure exported Burp Suite XML data. The goal is to provide an AI agent with a highly efficient, token-optimized context window of HTTP traffic so it can identify security vulnerabilities, with a focus on minimizing context usage, high accuracy, and persistence between sessions.

## Architecture & Features

The framework consists of a robust pipeline that processes raw Burp traffic into queryable, context-rich embeddings:

### Phase 1: Ingestion & Filtering (`ingest.py`)
- **Purpose**: Parses Burp Suite XML exports, decodes base64 request/response bodies, drops token-heavy/useless headers (while retaining security headers like CSP and X-Frame-Options), minifies HTML in the *traffic* documents, and filters out binary data.
- **Web-code retention**: In addition to the lean traffic documents, ingest keeps **one deduplicated copy (by content hash) of every HTML/JS/CSS artifact** and writes it to `webcode_<name>.json`. This is the raw client-side application code, retained in full.
- **Deduplication**: Deduplicates traffic by `(method, normalized_url, body_hash)` and client-side code by content hash (recording every URL an artifact appeared at).
- **Output**: `parsed_<name>.json` (lean traffic) and `webcode_<name>.json` (full web-app code corpus).

### Phase 2: Chunking & Structuring (`chunker.py`)
- **Purpose**: Consumes the output of Phase 1 and structures it into individual Request/Response pairs. Generates rich metadata for hybrid search.
- **Advanced Metadata Extraction**: 
  - `auth_role`: Parses Base64 JWT tokens or cookies to determine if the requester is `admin`, `authenticated`, or `anonymous`.
  - `authenticated`: A generic boolean that is `true` when the request carries credentials — an Authorization header, a curated session/auth cookie name, a JWT-shaped cookie value, or a custom API-key header (`x-api-key`, etc.). Works across targets and aids in finding broken access control.
  - `status_code` & `resp_len`: Numeric copies of status/response length that support ChromaDB range filters (e.g. `status_code >= 500`, large responses).
  - `status_class`, `host`, `scheme`, `port`, `req_content_type`, `file_ext`, `param_count`: Lean scalar fields for scoping and filtering.
  - `is_static`: Flags static assets (js/css/image/font) so they can be filtered out to reduce noise.
  - `cookies` & `body_params`: Extracts cookie names and POST body parameters (JSON and Form-urlencoded) for parameter mapping.
  - `referer` & `cors_wildcard`: Captures user flow and loose CORS policies.
  - `time` & `responselength`: Captures response sizing and (UTC string) timestamp details.
- **Output**: `chunks_<name>.json`

### Phase 2b: Web Application Code Extraction (`code_extractor.py`)
- **Purpose**: Turns the deduplicated `webcode_<name>.json` corpus into tag/structure-aware chunks so the client-side code is a first-class analysis target.
- **HTML** is split at tag boundaries: each `<script>` (inline and external ref), `<form>` (action/method/inputs), inline event handlers (`onclick`, …), and the residual DOM skeleton become their own chunks.
- **External JS** is classified **first-party vs vendor/minified**. First-party code is chunked by function/size and embedded; vendor/minified bundles (jQuery, React, `*.min.js`, …) are stored **store-only** (`embed: false`) — retrievable by id but excluded from semantic search to avoid noise and embedding cost.
- **Hunting metadata** per chunk: `content_kind: web_code`, `code_type`, `has_secrets` (API keys/tokens/JWTs/private keys), `dom_sinks` (`innerHTML`, `eval`, `document.write`, …), `endpoints` (referenced URLs/paths), plus `source_url(s)`, `chunk_index`/`total_chunks`.
- **Output**: `codechunks_<name>.json`

### Phase 3: Vector Storage (`vector_store.py`)
- **Purpose**: Embeds the structured documents using a local Ollama embedding model (`embeddinggemma:latest`). Leverages ChromaDB to allow both semantic search and metadata filtering. Serializes metadata arrays into strings. Includes retry/backoff on transient embedding failures.
- **Two collections**: traffic is embedded into `burp_traffic`; web-app code into `web_code` (via `--collection`). Store-only chunks (`embed: false`) are persisted with a fixed placeholder vector so they remain fetchable by id without polluting search.
- **Per-project isolation**: The ChromaDB is always co-located with the project's chunks file (or an explicit `--db-path`), so **each project keeps its own database** and traffic from separate projects is never mixed.

### Phase 4: Agent Interface (`agent_interface.py`, in the `jeb-query` skill)
- **Purpose**: Connects the agent to the ChromaDB instance. This query script lives
  in the `jeb-query` skill (`jeb-query/scripts/agent_interface.py`) but is run with
  this skill's shared venv python.
- **Functions**: 
  - `search_traffic_summary()`: Search by semantic query, returning lightweight summaries. Auto-detects `web_code` vs traffic documents and shapes the summary accordingly (surfacing `code_type`, `has_secrets`, `dom_sinks`, `endpoints`). Select the collection with `--collection {burp_traffic,web_code}`.
  - `get_full_traffic(id)`: Deep dive into the full headers and raw body (or full code chunk) of a specific document using its Document ID.

## Setup & Usage

All scripts live in the `scripts/` directory. Intermediate data (`parsed_*.json`,
`chunks_*.json`) and the `chroma_db/` directory are written to the **project
directory** (your current working directory by default), never into the skill folder.

### Prerequisites
Make sure you have Python 3 installed. You must have [Ollama](https://ollama.com/)
running locally with the `embeddinggemma:latest` model pulled.

Create the one-time virtual environment inside `scripts/` (shared across projects):

```bash
python3 -m venv scripts/venv
scripts/venv/bin/pip install -r scripts/requirements.txt
```

### Running the Pipeline

Run the entire pipeline with the bash wrapper. It can be invoked from anywhere; all
output lands in the project directory (the current directory by default, or an
explicit second argument):

```bash
scripts/process_burp.sh path/to/your/burp_export.xml [project_dir]
```

### Querying the Database

Querying is handled by the **`jeb-query`** skill, whose `agent_interface.py` is run
with this skill's shared venv python. Run from the project directory (so `./chroma_db`
resolves to that project), or pass `--db-path <project_dir>/chroma_db` explicitly:

```bash
PY=~/.config/opencode/skill/jeb-import/scripts/venv/bin/python
AGENT=~/.config/opencode/skill/jeb-query/scripts/agent_interface.py

# Get summaries of traffic matching a concept
"$PY" "$AGENT" --db-path ./chroma_db --query "shopping cart checkout"

# Filter with metadata, including numeric range operators
"$PY" "$AGENT" --db-path ./chroma_db \
  --query "server error" --where '{"status_code": {"$gte": 500}}'

# Deep dive into a specific request ID
"$PY" "$AGENT" --db-path ./chroma_db --id <document_id>
```

### Hunting in Client-Side Code

The client-side application code lives in the separate `web_code` collection. Query it
to find DOM XSS sinks, hardcoded secrets, and hidden endpoints:

```bash
# Semantic search over the web-app code
"$PY" "$AGENT" --db-path ./chroma_db \
  --collection web_code --query "auth token handling"

# Only chunks that matched a secret regex
"$PY" "$AGENT" --db-path ./chroma_db \
  --collection web_code --query "api key" --where '{"has_secrets": true}'

# Potential DOM XSS sinks
"$PY" "$AGENT" --db-path ./chroma_db \
  --collection web_code --query "user input to DOM" --where '{"dom_sinks": {"$ne": ""}}'

# Read a full code chunk by id
"$PY" "$AGENT" --db-path ./chroma_db \
  --collection web_code --id <document_id>
```
