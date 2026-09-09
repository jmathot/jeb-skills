---
name: jeb-import
description: Import step for J.E.B. — parse, distill, and embed a Burp Suite XML export into a per-project ChromaDB with three collections (structure, behavior, attacks), including cross-endpoint entity correlation and an identifier index. USE WHEN the user asks to process, ingest, import, vectorize, or embed a new Burp Suite XML export (or new traffic data) into the database. For searching/querying an already-populated database, use the jeb-query skill instead.
---

# J.E.B. — Import / Ingestion Pipeline (v4)

This skill turns a Burp Suite XML export into a queryable, per-project ChromaDB.
Once import is complete, use the **`jeb-query`** skill to search the database.

When the user asks you to process, ingest, or vectorize a new export:

1. Locate the input XML file provided by the user.
2. Run the all-in-one pipeline wrapper. It can be called from anywhere; all
   intermediate data and the ChromaDB are written to the **project directory**
   (the current working directory by default, or an explicit second argument):
   ```bash
    ~/.config/opencode/skill/jeb-import/scripts/process_burp.sh [--auth-cookies NAME[,NAME...]] <path_to_burp_xml> [project_dir]
   ```
   This produces `parsed_<name>.json`, `annotated_<name>.json`,
   `structure_<name>.json`, `behavior_<name>.json`, and `chroma_db/` inside the
   project directory — never inside the skill folder.
   - **First use only:** if it errors that the venv is missing, run the two
     setup commands the error prints (creates a venv shared with `jeb-query`
     and installs `requirements.txt`), then re-run the command above.
   - Prerequisite: [Ollama](https://ollama.com/) must be running locally with
     the `embeddinggemma:latest` model pulled (embedding is done via Ollama).

## Pipeline stages

`process_burp.sh` runs, in sequence: `parse.py` → `normalize.py` →
`build_structure.py` → `vector_store.py --collection structure` →
`build_behavior.py` → `vector_store.py --collection behavior`. You never invoke
these individually — just run `process_burp.sh` as shown above. A few of their
internal behaviors explain fields you'll see later when querying with
`jeb-query`:

- **Raw headers are kept, not embedded.** `parse.py` retains broad raw headers
  (only browser-hint noise like `sec-ch-ua*`/`sec-fetch-*` is stripped) for
  `jeb-query`'s `--contains` substring search, even though headers never
  go into the embedding text.
- **Content-aware access classification.** `normalize.py` labels each response
  `data` / `auth_wall` / `shell` / `denied` so a "200 OK that returns the login
  page" (a soft auth wall) is never mistaken for real anonymous access. This is
  what powers `jeb-query`'s `anon_allowed` / `access_control` fields.
- **Identifier extraction.** `normalize.py` pulls id/uuid/hash-shaped values from
  URL path segments and identifier-named JSON fields (`id`, `*_id`, `uuid`,
  `guid`) into an exact-match index — this is what `jeb-query`'s `identifier`
  looks up.

Every embedded document is also indexed in project-local SQLite FTS5 for hybrid
semantic + exact-term retrieval. Collections use explicit cosine distance.

The `attacks` collection starts empty and is written during hunting by
`jeb-query`'s `record-attack`.

> See the **`jeb-query`** skill for the full collection schema, field
> reference, and all query commands.

## Notes

- Re-running against the same `project_dir` is cheap and safe: unchanged
  documents are skipped and only changed ones are re-embedded.
- v4 folds `structure_segments`/`behavior_segments` into `structure`/`behavior`
  (a `granularity` metadata field replaces the separate collections) and adds
  entity nodes + the identifier index. A v3 `chroma_db/` has no `granularity`
  field on its documents, so v4's queries would silently return nothing against
  it — delete an older project's `chroma_db/` before its first v4 import.
- If a collection ends up empty, confirm Ollama is running and
  `embeddinggemma:latest` is pulled (`ollama pull embeddinggemma:latest`).
