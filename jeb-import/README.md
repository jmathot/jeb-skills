# J.E.B.E.D.I.A.H. (John's Extension for Burpsuite Export Data Ingestion And Handling)

## Project Overview
J.E.B. is a Retrieval-Augmented Generation (RAG) framework that ingests exported
Burp Suite XML and maps a web application into vector space so an AI agent can
reason about it and predict likely attacks — with a focus on **low context cost,
high signal, and cross-endpoint/attack context** (cookies, headers, auth flow),
and persistence between sessions.

## The v2 idea: search distilled, store raw

The core problem in v1 was embedding noise: each vector was built from the full
request+response **including headers and cookies**, so repeated `Cookie` /
`Authorization` / `Set-Cookie` blocks dominated the space and unrelated endpoints
looked similar.

v2 separates **what is searched** from **what is stored**. Every document is
vectorised from a distilled, *value-suppressed* `embed_text` (method, templated
path, parameter *names*, response schema/summary, and a compact security clause of
cookie/header *features* — never their values). The raw HTTP is kept verbatim as
the retrieval document, so nothing is lost for deep-dive and for
`--where-document` substring filtering over real headers/cookies.

## Three collections

1. **`structure`** — the site map. One node per `(host, method, endpoint_template)`
   with volatile path segments normalised (`/rest/products/1` → `/rest/products/{id}`),
   plus one synthetic **`auth_model`** node per host that summarises which cookies
   are set vs consumed where, the token type, and the app-wide missing-header
   posture. Endpoints/pages/actions carry `anon_allowed`, `authenticated_ever`,
   `param_names`, `produces`, `cookies_set/sent`, `security_headers_missing`,
   `cors`, and `example_ids` linking to behaviors.
2. **`behavior`** — one doc per **distinct behavior**. Near-duplicate instances
   (e.g. `/products/1..500`) collapse to a representative + `instance_count`; the
   collapse key includes status, auth role, and response schema so security-
   relevant variations never merge. Metadata carries lean functional scalars plus
   compact security features (`auth_role`, `auth_mechanism`, `cookie_names`,
   `set_cookies`, `cookie_issues`, `security_headers_missing`, `cors`, `jwt`,
   `redirect_location`).
3. **`attacks`** — results of active testing, written during hunting by
   `jeb-query`'s `record-attack` (payload, response, verdict, severity, evidence,
   and a link back to the source behavior).

## Pipeline

`parse → normalize → build_structure → embed → build_behavior → embed`

- **`parse.py`** — parse/decode/split/dedupe; retain broad raw headers (only
  browser-hint noise stripped).
- **`distill.py`** — pure library: endpoint templating, parameter/credential/
  JWT/cookie/header feature extraction, the response-type router (API schema / MPA
  page / SPA shell / static / redirect), boilerplate helpers, and the
  `embed_text` + `summary` formatters.
- **`normalize.py`** — corpus passes (SPA-shell collapse, per-host MPA boilerplate
  subtraction), per-item annotation, and per-host auth-model aggregation.
- **`build_structure.py` / `build_behavior.py`** — emit `{id, embed_text,
  page_content, metadata}` chunks.
- **`vector_store.py`** — embed `embed_text` (embeddinggemma via Ollama), store
  `page_content` as the document; stamp the collection's `embedding_scheme`.

Each project keeps its **own** `chroma_db/` co-located with its data, so traffic
from separate projects is never mixed.

## Setup

Prerequisites: Python 3, and [Ollama](https://ollama.com/) running locally with
`embeddinggemma:latest` pulled. Create the one-time venv:

```bash
python3 -m venv scripts/venv
scripts/venv/bin/pip install -r scripts/requirements.txt
```

## Running the pipeline

```bash
scripts/process_burp.sh path/to/burp_export.xml [project_dir]
```
Outputs `parsed_*.json`, `annotated_*.json`, `structure_*.json`, `behavior_*.json`
and `chroma_db/` into the project directory (current directory by default).

## Querying

Handled by the **`jeb-query`** skill (`agent_interface.py`), run with this skill's
venv. Highlights:

```bash
PY=~/.config/opencode/skill/jeb-import/scripts/venv/bin/python
AGENT=~/.config/opencode/skill/jeb-query/scripts/agent_interface.py

# Map the app / find anonymously-reachable endpoints
"$PY" "$AGENT" --db-path ./chroma_db --collection structure \
  --query "sensitive endpoint" --where '{"anon_allowed": true}'

# Behavior search + numeric range
"$PY" "$AGENT" --db-path ./chroma_db --query "server error" \
  --where '{"status_code": {"$gte": 500}}'

# Substring over raw headers (CORS wildcard, cookie flags, …)
"$PY" "$AGENT" --db-path ./chroma_db --query "cross origin" \
  --where-document '{"$contains": "Access-Control-Allow-Origin: *"}'

# Deep dive, pivot, and record a finding
"$PY" "$AGENT" --db-path ./chroma_db --id <id>
"$PY" "$AGENT" --db-path ./chroma_db --similar-to <id> --n-results 10
"$PY" "$AGENT" --db-path ./chroma_db --record-attack --vuln-class SQLi \
  --endpoint https://app/rest/search --method POST --param q \
  --payload "' OR 1=1--" --status 500 --verdict vulnerable --severity high
```

See the `jeb-query` skill for the full filterable-field reference per collection.

## Visualizing the vector space

`visualize.py` renders the embeddings as a self-contained interactive HTML scatter
(UMAP by default, PCA fallback) with optimization diagnostics — a nearest-neighbour
distance histogram, a tightest-cluster / near-duplicate report, and inter-collection
separation stats — so you can see where the distillation can be tuned.

```bash
scripts/venv/bin/pip install -r scripts/requirements-viz.txt
scripts/venv/bin/python scripts/visualize.py \
  --db-path ./chroma_db --collection all --color-by doc_kind --out vector_space.html
```
