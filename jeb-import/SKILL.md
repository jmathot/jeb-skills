---
name: jeb-import
description: Import step for J.E.B. — parse, distill, and embed a Burp Suite XML export into a per-project ChromaDB with three collections (structure, behavior, attacks). USE WHEN the user asks to process, ingest, import, vectorize, or embed a new Burp Suite XML export (or new traffic data) into the database. For searching/querying an already-populated database, use the jeb-query skill instead.
---

# J.E.B. — Import / Ingestion Pipeline (v2)

This skill turns a Burp Suite XML export into a queryable, per-project ChromaDB.
Once import is complete, use the **`jeb-query`** skill to search the database.

The v2 design fixes embedding noise by **separating what is searched from what is
stored**: every document is vectorised from a distilled, *value-suppressed*
`embed_text` (no raw headers, cookie jars, or tokens), while the raw HTTP is kept
as the retrieval document for deep-dive and `--where-document` substring filters.

When the user asks you to process, ingest, or vectorize a new export, follow these
steps:

1. Locate the input XML file provided by the user.
2. Ensure the one-time virtual environment exists (only needed the first time). This
   venv is shared with the `jeb-query` skill:
   ```bash
   SKILL_DIR=~/.config/opencode/skill/jeb-import/scripts
   test -x "$SKILL_DIR/venv/bin/python" || {
     python3 -m venv "$SKILL_DIR/venv"
     "$SKILL_DIR/venv/bin/pip" install -r "$SKILL_DIR/requirements.txt"
   }
   ```
   Prerequisite: [Ollama](https://ollama.com/) must be running locally with the
   `embeddinggemma:latest` model pulled (embedding is done via Ollama).
3. Run the all-in-one pipeline wrapper. It can be called from anywhere; all
   intermediate data and the ChromaDB are written to the **project directory**
   (the current working directory by default, or an explicit second argument):
   ```bash
   ~/.config/opencode/skill/jeb-import/scripts/process_burp.sh <path_to_burp_xml> [project_dir]
   ```
   This produces `parsed_<name>.json`, `annotated_<name>.json`,
   `structure_<name>.json`, `behavior_<name>.json`, and `chroma_db/` inside the
   project directory — never inside the skill folder.

## Pipeline stages

`process_burp.sh` runs, in sequence:

1. **`parse.py`** — parse the Burp XML, decode base64, split request/response,
   dedupe by `(method, normalized_url, body_hash)`, and retain **broad raw
   headers** (only browser-hint noise like `sec-ch-ua*` / `sec-fetch-*` is
   stripped; headers are never embedded, so fidelity here powers attack analysis).
2. **`normalize.py`** — corpus passes + per-item annotation:
   - **SPA-shell collapse**: an HTML body served at many routes (or near-empty with
     a JS mount point) collapses to a single per-host shell node.
   - **MPA boilerplate subtraction**: per host, DOM text blocks appearing on >50%
     of pages (min 5 pages) are treated as template chrome and removed.
   - **response router**: JSON/XML → key-schema + error/message strings + a few
     sample scalars; HTML → title/headings/forms/links; static/redirect/empty →
     minimal markers.
   - **value-suppressed security features**: auth mechanism, cookie names, JWT
     alg + claim names, Set-Cookie flags, missing security headers, CORS posture,
     cross-site Origin, CSRF token presence.
   - **content-aware access classification**: each response is labelled
     `data` / `auth_wall` / `shell` / `denied` so a "200 OK that returns the
     login page" (soft auth wall) is not mistaken for anonymous access. Uses
     per-host login-page fingerprints, login-form/keyword heuristics, JSON
     `unauthorized`/`authenticated:false` envelopes, and an anon-vs-authenticated
     differential.
   - **auth-model aggregation**: per host, which cookies are set vs consumed where.
3. **`build_structure.py`** → the **`structure`** collection.
4. **`vector_store.py --collection structure`** — embed it.
5. **`build_behavior.py`** → the **`behavior`** collection.
6. **`vector_store.py --collection behavior`** — embed it.

The `attacks` collection starts empty and is written during hunting by
`jeb-query`'s `record-attack`.

## The three collections

- **`structure`** — the site map. One node per `(host, method, endpoint_template)`
  (volatile path segments normalised to `{id}`/`{uuid}`/`{hash}`/…), plus one
  synthetic `auth_model` node per host. Carries `node_kind` (page/endpoint/action/
  auth_model), `param_names`, `produces`, `status_codes`, `authenticated_ever`,
  `anon_allowed` (anon received real data — content-aware), `anon_soft_denied`,
  `access_control` (`open-data`/`soft-auth-wall`/`enforced`/`unknown`),
  `auth_mechanisms`, `cookies_sent`, `cookies_set`, `security_headers_missing`,
  `cors`, `instance_count`, `example_ids`.
- **`behavior`** — one doc per **distinct behavior** (collapse key includes
  status, auth role, and response schema so security-relevant variations never
  merge). Raw HTTP is the retrieval document. Carries lean functional scalars plus
  compact security features: `auth_role`, `auth_mechanism`, `cookie_names`,
  `set_cookies`, `cookie_issues`, `security_headers_missing`, `cors`,
  `redirect_location`, `jwt`, `instance_count`.
- **`attacks`** — results of active testing (see `jeb-query`).

> For the **full filterable-field reference** and all query commands, see the
> **`jeb-query`** skill.

## Visualizing the vector space (optional, standalone)

To inspect the embedding space and spot where distillation can be tuned, use the
standalone `visualize.py` (viz-only deps — install once on demand):
```bash
~/.config/opencode/skill/jeb-import/scripts/venv/bin/pip install -r \
  ~/.config/opencode/skill/jeb-import/scripts/requirements-viz.txt

~/.config/opencode/skill/jeb-import/scripts/venv/bin/python \
  ~/.config/opencode/skill/jeb-import/scripts/visualize.py \
  --db-path ./chroma_db --collection all --color-by doc_kind --out vector_space.html
```
It writes a self-contained interactive HTML scatter (UMAP by default, PCA
fallback) plus diagnostics: a nearest-neighbour distance histogram (a spike near
0 = residual near-duplicates to tighten), a tightest-cluster / near-duplicate
report, and inter-collection separation stats.

## Notes

- Embeddings use embeddinggemma's asymmetric prompts via the shared
  `embedding.py`: the corpus is embedded with the document prompt and each
  collection is stamped with an `embedding_scheme` so `jeb-query` embeds queries
  with the matching prompt.
- Re-running against the same `project_dir` upserts by id; already-embedded docs
  are skipped. To **rebuild** cleanly (e.g. after a pipeline change), delete the
  project's `chroma_db/` first.
- If a collection ends up empty, confirm Ollama is running and
  `embeddinggemma:latest` is pulled (`ollama pull embeddinggemma:latest`).
