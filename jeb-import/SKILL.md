---
name: jeb-import
description: Import step for J.E.B. — parse, distill, and embed a Burp Suite XML export into a per-project ChromaDB with three collections (structure, behavior, attacks), including cross-endpoint entity correlation and an identifier index. USE WHEN the user asks to process, ingest, import, vectorize, or embed a new Burp Suite XML export (or new traffic data) into the database. For searching/querying an already-populated database, use the jeb-query skill instead.
---

# J.E.B. — Import / Ingestion Pipeline (v4)

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
   and retain **broad raw headers** (only browser-hint noise like `sec-ch-ua*` /
   `sec-fetch-*` is stripped; headers are never embedded, so fidelity here
   powers attack analysis). No dedup at this stage — every item is kept, even
   exact repeats of the same method/URL/body, because a *different* response
   to an identical request (race conditions, non-deterministic authz, rate
   limiting) is itself a real finding. Oversized bodies prefer schema-aware
   JSON/XML pruning over a hard cut; when that's not applicable, both the head
   and the tail of the body are kept (not just the head) so trailing content
   like stack traces isn't lost. Binary bodies are replaced with a
   `sha256+length` marker (not just discarded), so the identifier index (below)
   can still catch the same file being served from two different paths.
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
   - **auth-model aggregation**: per origin, which cookies are set vs consumed where.
   - **identifier extraction**: id/uuid/hash-shaped values from URL path segments
     and JSON fields named like an identifier (`id`, `*_id`, `uuid`, `guid`),
     kept as exact `(field, value)` pairs — never templated, never embedded —
     for the cross-endpoint identifier index (see below).
3. **`build_structure.py`** → the **`structure`** collection: one node per
   `(scheme, host, port, method, endpoint_template)`, one synthetic `auth_model`
   node per origin, and one synthetic **`entity`** node per data shape shared by
   2+ distinct endpoints (see "Entity correlation" below) — plus protocol-aware
   identity/posture/auth_model semantic segments, all in the same output.
4. **`vector_store.py --collection structure`** — embed it.
5. **`build_behavior.py`** → the **`behavior`** collection: one doc per distinct
   behavior, plus its route/response/security semantic segments, all in the
   same output.
6. **`vector_store.py --collection behavior`** — embed it.

Every embedded document is also indexed in project-local SQLite FTS5 for hybrid
semantic + exact-term retrieval, and any extracted identifier `(field, value)`
pairs are written to a companion exact-match SQLite table. Collections use
explicit cosine distance.

The `attacks` collection starts empty and is written during hunting by
`jeb-query`'s `record-attack`.

## The three collections

- **`structure`** — the site map. One node per `(scheme, host, port, method, endpoint_template)`
  (volatile path segments normalised to `{id}`/`{uuid}`/`{hash}`/…), plus one
  synthetic `auth_model` node per origin and one synthetic `entity` node per
  cross-endpoint data shape. Carries `node_kind` (page/endpoint/action/
  auth_model/entity), `param_names`, `produces`, `status_codes`, `authenticated_ever`,
  `anon_allowed` (anon received real data — content-aware), `anon_soft_denied`,
  `access_control` (`open-data`/`soft-auth-wall`/`enforced`/`unknown`),
  `auth_mechanisms`, `cookies_sent`, `cookies_set`, `security_headers_missing`,
  `cors`, `instance_count`, `example_ids`, `entity_ids` (which entity node(s)
  this route's request/response shape belongs to).
- **`behavior`** — one doc per **distinct behavior** (collapse key includes
  status, auth role, and response schema so security-relevant variations never
  merge). Raw HTTP is the retrieval document. Carries lean functional scalars plus
  compact security features: `auth_role`, `auth_mechanism`, `cookie_names`,
  `set_cookies`, `cookie_issues`, `security_headers_missing`, `cors`,
  `redirect_location`, `jwt`, `instance_count`.
- **`attacks`** — results of active testing (see `jeb-query`).

Each of `structure` and `behavior` also holds semantic **segment** documents
(a `granularity: "segment"` metadata field, vs. `"parent"` for the canonical
docs above) — protocol-aware child vectors whose `parent_id` points back to a
canonical document. They're queried automatically as part of retrieval and are
not deep-dive targets themselves.

### Entity correlation (cross-endpoint)

A response/request-body JSON or XML key-schema is hashed at ingest time
(`resp_schema_sig` / `req_schema_sig`). Unlike the behavior-collapse key (which
uses this hash only to keep variations *within one endpoint* from merging),
`build_structure.py` also groups schemas **across every endpoint in the app**:
any schema seen at 2+ distinct `(method, endpoint_template)` pairs — as a
response shape, a request-body shape, or one endpoint's request matching
another's response — becomes one `entity` node listing every `produced_by` /
`consumed_by` route. This is how the system recognizes, e.g., that
`POST /users/edit`'s request body and `GET /users/{id}`'s response describe
the same "user" object. Near-identical (but not exactly equal) schemas are
recorded as lower-confidence `related` matches via key-set Jaccard overlap.
For **instance**-level proof (same record, not just same shape), see
`jeb-query`'s `--identifier` lookup, backed by the identifier index above.

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
  --db-path ./chroma_db --collection all --color-by collection --out vector_space.html
```
It writes a self-contained interactive HTML scatter (UMAP by default, PCA
fallback) plus diagnostics: a nearest-neighbour distance histogram (a spike near
0 = residual near-duplicates to tighten), collection schema/metric reporting,
semantic representation coverage, orphan detection, child-to-parent distance,
tightest clusters, and inter-collection separation. Use `--collection canonical`
or `--collection segments` to isolate either layer; segment-only views default to
coloring by `representation`.

## Notes

- Embeddings use embeddinggemma's asymmetric prompts via the shared
  `embedding.py`: the corpus is embedded with the document prompt and each
  collection is stamped with an `embedding_scheme` so `jeb-query` embeds queries
  with the matching prompt.
- Re-running against the same `project_dir` hashes embedding text, stored content,
  and metadata; unchanged documents are skipped and changed documents refreshed.
- v4 folds `structure_segments`/`behavior_segments` into `structure`/`behavior`
  (a `granularity` metadata field replaces the separate collections) and adds
  entity nodes + the identifier index. A v3 `chroma_db/` has no `granularity`
  field on its documents, so v4's queries would silently return nothing against
  it — delete an older project's `chroma_db/` before its first v4 import.
- If a collection ends up empty, confirm Ollama is running and
  `embeddinggemma:latest` is pulled (`ollama pull embeddinggemma:latest`).
