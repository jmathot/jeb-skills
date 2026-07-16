---
name: jeb-import
description: Import step for J.E.B. — parse, chunk, extract web-app code from, and embed a Burp Suite XML export into a per-project ChromaDB. USE WHEN the user asks to process, ingest, import, vectorize, or embed a new Burp Suite XML export (or new traffic data) into the database. For searching/querying an already-populated database, use the jeb-query skill instead.
---

# J.E.B. — Import / Ingestion Pipeline

This skill turns a Burp Suite XML export into a queryable, per-project ChromaDB.
Once import is complete, use the **`jeb-query`** skill to search the database.

When the user asks you to process, ingest, or vectorize a new Burp Suite XML export
(or new traffic data), follow these steps:

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
3. Run the all-in-one processing pipeline wrapper script. It can be called from
   anywhere; all intermediate data and the ChromaDB directory are written to the
   **project directory** (the current working directory by default, or an explicit
   second argument):
   ```bash
   ~/.config/opencode/skill/jeb-import/scripts/process_burp.sh <path_to_burp_xml> [project_dir]
   ```
   This produces `parsed_<name>.json`, `webcode_<name>.json`, `chunks_<name>.json`,
   `codechunks_<name>.json`, and `chroma_db/` inside the project directory — never
   inside the skill folder.
4. This script runs, in sequence: `ingest.py` (parse + filter traffic **and** retain
   one deduplicated copy of all HTML/JS/CSS), `chunker.py` (structure traffic), the
   first `vector_store.py` (embed traffic into the **`burp_traffic`** collection),
   `code_extractor.py` (chunk the web-app code by tag/structure), and a second
   `vector_store.py` (embed the code into a separate **`web_code`** collection). The
   ChromaDB is always co-located with the project's chunks file, so **each project
   keeps its own isolated database** and data from separate projects is never mixed.

## What gets produced

The database holds **two collections**, each with its own metadata schema:

- **`burp_traffic`** — one document per request/response pair (lean, HTML minified).
  Carries scalar/numeric fields for hybrid search and filtering, including: `url`,
  `endpoint`, `host`, `scheme`, `port`, `method`, `status`/`status_code`/`status_class`,
  `url_params`, `cookies`, `body_params`, `param_count`, `req_content_type`,
  `mimetype`, `file_ext`, `is_static`, `referer`, `cors_wildcard`, `auth_role`,
  `authenticated`, `time`, `responselength`/`resp_len`.
- **`web_code`** — the deduplicated client-side application code (HTML, inline +
  external JS, forms, event handlers), chunked by tag/structure. Carries hunting
  fields including: `content_kind`, `code_type`, `host`/`source_url(s)`,
  `url_count`, `chunk_index`/`total_chunks`, `has_secrets`, `dom_sinks`,
  `endpoints`/`endpoint_count`, `embed`. Store-only vendor/minified bundles are kept
  with `embed: false` (fetchable by id, excluded from semantic search).

> For the **full filterable-field reference** (types, range operators, example
> `--where` filters) and all query commands, see the **`jeb-query`** skill.

## Notes

- Embeddings use embeddinggemma's **asymmetric prompts**: the whole corpus is
  embedded with the document prompt (via the shared `scripts/embedding.py` helper),
  and each collection is stamped with an `embedding_scheme` so `jeb-query` embeds
  queries with the matching prompt. This improves retrieval relevance automatically.
- Re-running the pipeline against the same `project_dir` upserts into the existing
  `chroma_db/`; already-embedded documents are skipped by id. To **upgrade an older
  database** built before the prefixed embedding scheme, re-import into a **fresh**
  `chroma_db` directory (skipped ids would otherwise keep their old vectors).
- If Step 5 reports 0 documents in `web_code`, confirm Ollama is running and the
  `embeddinggemma:latest` model is pulled (`ollama pull embeddinggemma:latest`).
