# J.E.B.E.D.I.A.H.

John's Extension for Burpsuite Export Data Ingestion And Handling — a local RAG
framework that turns a Burp Suite XML export into a per-project vector database
for mapping a web app and hunting vulnerabilities.

## Features

- **Three collections, canonical + semantic docs together**
  - `structure` — site map: one node per `(scheme, host, port, method, endpoint_template)`
    with ids normalised (`/products/{id}`), a per-origin `auth_model` node
    showing which cookies are set vs consumed where, and `entity` nodes
    correlating endpoints that share a response/request-body data shape
    (e.g. a `POST` that edits a user and the `GET` that reads it back).
  - `behavior` — one doc per distinct request/response; near-duplicates collapse
    to a representative with an `instance_count`.
  - `attacks` — results of active testing, logged while hunting.
  - `structure` and `behavior` also hold protocol-aware semantic child vectors
    (`granularity: "segment"`, vs. `"parent"` for canonical docs) for route,
    response, and access/session retrieval; results resolve back to the
    canonical parent id.
- **Cross-endpoint correlation** — an exact-match identifier index
  (`identifier <value>`) finds every document, in any collection, that
  referenced a given id/uuid/hash value — the instance-level counterpart to
  `entity` nodes' structural (same-shape) correlation.
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
- **Hybrid retrieval** — semantic child search plus SQLite FTS5 lexical search,
  reciprocal-rank fusion, endpoint diversity, score/distance thresholds,
  `top_k`, and cumulative retrieval `top_p` selection.
- **Filtering** — named metadata facet flags (`--anon`, `--status`, `--param`,
  `--cors-open`, …) and `--contains` substring search over canonical raw
  headers/cookies, applied before final result selection.
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

The current schema uses explicit cosine distance and semantic child collections.
Delete an older project's `chroma_db/` before its first import with this version.
Re-imports under the current schema only re-embed documents whose content changed.

## Query

    JQ=~/.config/opencode/skill/jeb-query/scripts/jeb-query.sh

    # Everything about one endpoint, in one call: parameters, auth posture,
    # cookies, headers, CORS, neighbouring routes, entity links, and the raw
    # request/response of a representative exchange.
    "$JQ" endpoint /api/orders
    "$JQ" endpoint https://app/api/orders/42        # ids normalise to the template

    # The site map, and how sessions work
    "$JQ" map
    "$JQ" map --kind auth_model

    # Hybrid search, or a pure metadata filter when you give no words
    "$JQ" search "password reset token" --method POST
    "$JQ" search --in structure --anon               # anonymous access to real data
    "$JQ" search --status '>=500' --param q
    "$JQ" search --contains "Access-Control-Allow-Origin: *"

    # Pivots
    "$JQ" get <id>                                   # collection auto-detected
    "$JQ" similar <id>
    "$JQ" identifier 42                              # same record, any endpoint

    # Findings
    "$JQ" record-attack --vuln-class SQLi --endpoint https://app/api/search \
      --method GET --param q --payload "' OR 1=1--" --status 500 \
      --verdict vulnerable --severity high
    "$JQ" attacks --vuln-class SQLi

Every command prints one JSON object with `count`, results, `notes` and `next`;
`next` names the follow-up commands with real ids already filled in.

Sizing is one flag: `--depth quick|normal|deep` (or `--limit N`). If a search
returns nothing, `fallback` carries the closest matches with the relevance
cutoff disabled.

`structure` and `behavior` index **protocol structure only** — methods, path
templates, parameter names, statuses, content types, auth roles and mechanisms,
cookies, missing security headers, CORS, JWT claims. They hold no vulnerability
vocabulary, so terms like `sqli` or `ssrf` are stripped from a search and
reported in `rejected_terms`. Vulnerability classes live in `attacks` as
`vuln_class`. Hunt by structural signal instead — see the `jeb-query` skill, and
the signal table in the J.E.B.E.D.I.A.H. agent.

## The J.E.B.E.D.I.A.H. agent

`install-skills.sh` also installs an OpenCode agent to
`~/.config/opencode/agent/jebediah.md`. Switch to it with the **Tab** key.

It carries the pentesting methodology: start from `endpoint` whenever a route is
named, map vulnerability classes onto the structural signals the index actually
holds, correlate by entity and identifier, and record every test result — including
the negative ones.

## Visualize

    ~/.config/opencode/skill/jeb-import/scripts/venv/bin/pip install \
      -r ~/.config/opencode/skill/jeb-import/scripts/requirements-viz.txt
    ~/.config/opencode/skill/jeb-import/scripts/venv/bin/python \
      ~/.config/opencode/skill/jeb-import/scripts/visualize.py \
      --db-path ./chroma_db --collection all --color-by collection \
      --out vector_space.html

The v4 visualizer includes canonical and semantic segment documents (distinguished
by the `granularity` metadata field within each collection), collection
schema/metric reporting, representation coverage, orphan detection, parent-child
cosine-distance analysis, and cluster diagnostics. Use `--collection canonical`
or `--collection segments` for focused views.
