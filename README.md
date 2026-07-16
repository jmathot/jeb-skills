# J.E.B.E.D.I.A.H.

John's Extension for Burpsuite Export Data Ingestion And Handling — a local RAG
framework that turns a Burp Suite XML export into a per-project vector database
for mapping a web app and hunting vulnerabilities.

## Features

- **Three collections**
  - `structure` — site map: one node per `(host, method, endpoint_template)`
    with ids normalised (`/products/{id}`), plus a per-host `auth_model` node
    showing which cookies are set vs consumed where.
  - `behavior` — one doc per distinct request/response; near-duplicates collapse
    to a representative with an `instance_count`.
  - `attacks` — results of active testing, logged while hunting.
- **Distilled embeddings** — vectors are built from a compact, value-suppressed
  summary (method, templated path, parameter names, response schema, security
  features). Raw HTTP is stored for deep-dive and substring search, so repeated
  headers/cookies never pollute retrieval.
- **Security context** — auth mechanism, cookie names + Set-Cookie flags, missing
  security headers, CORS posture, JWT alg/claims, cross-site origin, CSRF tokens.
- **Content-aware access control** — flags genuine anonymous data access and
  separates it from "200 OK login page" soft auth walls.
- **Response-aware** — handles JSON APIs, server-rendered pages (shared
  boilerplate removed), and SPA shells.
- **Filtering** — semantic query, metadata filters, and `--where-document`
  substring search over raw headers/cookies.
- **Visualization** — interactive HTML map of the vector space with diagnostics.

## Requirements

- Python 3
- [Ollama](https://ollama.com/) running locally with `embeddinggemma:latest` pulled

## Setup

    python3 -m venv ~/.config/opencode/skill/jeb-import/scripts/venv
    ~/.config/opencode/skill/jeb-import/scripts/venv/bin/pip install \
      -r ~/.config/opencode/skill/jeb-import/scripts/requirements.txt

## Import

    ~/.config/opencode/skill/jeb-import/scripts/process_burp.sh \
      path/to/burp_export.xml [project_dir]

Writes intermediate JSON and a `chroma_db/` into the project directory.

## Query

    PY=~/.config/opencode/skill/jeb-import/scripts/venv/bin/python
    AGENT=~/.config/opencode/skill/jeb-query/scripts/agent_interface.py

    # Broken access control: endpoints that return real data anonymously
    "$PY" "$AGENT" --db-path ./chroma_db --collection structure \
      --where '{"anon_allowed": true}'

    # Semantic behavior search + metadata filter
    "$PY" "$AGENT" --db-path ./chroma_db --query "server error" \
      --where '{"status_code": {"$gte": 500}}'

    # Substring search over raw headers/cookies
    "$PY" "$AGENT" --db-path ./chroma_db --query "cross origin" \
      --where-document '{"$contains": "Access-Control-Allow-Origin: *"}'

    # Deep-dive, pivot, and log a finding
    "$PY" "$AGENT" --db-path ./chroma_db --id <id>
    "$PY" "$AGENT" --db-path ./chroma_db --similar-to <id>
    "$PY" "$AGENT" --db-path ./chroma_db --record-attack --vuln-class SQLi \
      --endpoint https://app/rest/search --method POST --param q \
      --payload "' OR 1=1--" --status 500 --verdict vulnerable --severity high

See the `jeb-query` skill for the full filterable-field reference.

## Visualize

    ~/.config/opencode/skill/jeb-import/scripts/venv/bin/pip install \
      -r ~/.config/opencode/skill/jeb-import/scripts/requirements-viz.txt
    ~/.config/opencode/skill/jeb-import/scripts/venv/bin/python \
      ~/.config/opencode/skill/jeb-import/scripts/visualize.py \
      --db-path ./chroma_db --collection all --out vector_space.html
