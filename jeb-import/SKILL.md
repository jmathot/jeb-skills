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
    ~/.config/opencode/skill/jeb-import/scripts/process_burp.sh [--auth-cookies NAME[,NAME...]] [--no-auto-detect-auth-cookies] <path_to_burp_xml> [project_dir]
   ```
   This produces `parsed_<name>.json`, `annotated_<name>.json`,
   `structure_<name>.json`, `behavior_<name>.json`, and `chroma_db/` inside the
   project directory — never inside the skill folder.
   - **First use only:** if it errors that the venv is missing, run the two
     setup commands the error prints (creates a venv shared with `jeb-query`
     and installs `requirements.txt`), then re-run the command above.
   - Prerequisite: [Ollama](https://ollama.com/) 0.11.10 or newer must be
     running locally with the `embeddinggemma:latest` model pulled. J.E.B. uses
     EmbeddingGemma's full 768-dimensional output and its 2,048-token context.
     Embedding calls intentionally allow up to 60 minutes for slow local hosts.

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
- **Full analysis, bounded evidence.** Textual request and response bodies are
  decoded before classification and schema/identifier extraction. Stored raw
  evidence is bounded to 64 KiB per body, with structured previews or head/tail
  text retained for larger bodies; gzip, deflate, and Brotli are supported.
- **Dynamic variants survive collapse.** Canonical behavior documents still
  summarize repeated traffic, but materially different request/response shapes
  are retained as raw variant children and surfaced by endpoint/search results.
- **Content-aware access classification.** `normalize.py` labels each response
  `data` / `auth_wall` / `shell` / `denied` so a "200 OK that returns the login
  page" (a soft auth wall) is never mistaken for real anonymous access. This is
  what powers `jeb-query`'s `anon_allowed` / `access_control` fields.
- **Identifier extraction.** `normalize.py` pulls id/uuid/hash-shaped values from
  URL path segments and identifier-named JSON fields (`id`, `*_id`, `uuid`,
  `guid`) into an exact-match index — this is what `jeb-query`'s `identifier`
  looks up.
- **Auto-detected login cookies.** `normalize.py` watches for a POST to a
  login-like path whose response is not a 4xx/5xx and doesn't itself look
  like another login/auth-wall page, and registers any cookie it sets as an
  authentication cookie for the rest of the run — no `--auth-cookies` flag
  needed in the common case. Pass `--no-auto-detect-auth-cookies` to disable
  this and rely solely on manually-specified `--auth-cookies` names.

Every embedded document is also indexed in project-local SQLite FTS5 for hybrid
semantic + exact-term retrieval. Collections use explicit cosine distance.

The `attacks` collection starts empty and is written during hunting by
`jeb-query`'s `record-attack`.

> See the **`jeb-query`** skill for the full collection schema, field
> reference, and all query commands.

## Notes

- The normal usage is one capture and one disposable `chroma_db` per project.
  After this skill's schema or embedding profile changes, delete `chroma_db/`
  and re-import the original Burp export; old databases are not migrated.
- Re-running an unchanged capture against the same current-profile database
  skips unchanged documents.
- If a collection ends up empty, confirm Ollama is running and
  `embeddinggemma:latest` is pulled (`ollama pull embeddinggemma:latest`).
