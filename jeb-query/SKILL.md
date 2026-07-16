---
name: jeb-query
description: Query step for J.E.B. — hunt for vulnerabilities and analyze Burp traffic and client-side web code stored in a per-project ChromaDB. USE WHEN searching/querying an already-imported Burp database, hunting vulns, semantic search over HTTP traffic, filtering requests by metadata, hunting DOM XSS sinks / secrets / hidden endpoints in web_code, or deep-diving a specific request/response by id. To first parse and embed a Burp XML export, use the jeb-import skill.
---

# J.E.B. — Query / Hunting Interface

This skill queries a ChromaDB that was populated by the **`jeb-import`** skill. If the
database does not exist yet, run `jeb-import` first.

Queries use this skill's `agent_interface.py` script, run with the shared venv that
was created by (and lives in) the `jeb-import` skill folder:

```
PY=~/.config/opencode/skill/jeb-import/scripts/venv/bin/python
AGENT=~/.config/opencode/skill/jeb-query/scripts/agent_interface.py
```

**Always query the database belonging to the project you are working on.** Run these
commands **from the project directory** so `./chroma_db` resolves to that project's own
database, or pass `--db-path <project_dir>/chroma_db` explicitly. Data from separate
projects is never mixed.

The database holds two collections, selected with `--collection`:
- `burp_traffic` (default) — one document per request/response pair.
- `web_code` — client-side application code (HTML/inline+external JS, forms, handlers).

### Embedding scheme (retrieval quality)

Databases built by the current `jeb-import` are stamped with a prefixed embedding
scheme: the corpus is embedded with embeddinggemma's document prompt, and queries
are embedded with the matching **query prompt** — `search result` for
`burp_traffic`, `code retrieval` for `web_code`. This asymmetric prompting
noticeably improves relevance and is applied automatically.

If you query an **older database built before this scheme**, the tool detects the
missing stamp, prints a one-line note to stderr, and falls back to raw query text
(so results are never worse than before). To unlock the improved retrieval, re-run
`jeb-import` into a **fresh** `chroma_db` directory.

### Reading results

Every search/similar result now includes a `distance` (lower = closer match; use
it to gauge relevance before deep-diving) and a `snippet` of the matched document.
Control snippet size with `--snippet-len N` (default `200`; `0` disables snippets).

---

## 1. Search traffic (semantic + metadata filter)

Pull lightweight summaries of traffic matching a concept. Filter the vector search with
ChromaDB metadata filters via `--where`.

```bash
~/.config/opencode/skill/jeb-import/scripts/venv/bin/python \
  ~/.config/opencode/skill/jeb-query/scripts/agent_interface.py \
  --db-path ./chroma_db \
  --query "<semantic search query>" --where '{"method": "POST", "auth_role": "admin"}'
```

This returns a list of summaries. Pay special attention to **Broken Access Control**
signals — an `authenticated: false` request receiving a `2xx` on a sensitive endpoint,
or a low-privilege `auth_role` reaching privileged endpoints — as well as interesting
`body_params` (SQLi/XSS targets) and `cors_wildcard` status.

Numeric fields (`status_code`, `resp_len`, `port`, `param_count`) support range
operators. Example — server-side errors with large bodies (potential stack traces /
info disclosure):

```bash
~/.config/opencode/skill/jeb-import/scripts/venv/bin/python \
  ~/.config/opencode/skill/jeb-query/scripts/agent_interface.py \
  --db-path ./chroma_db \
  --query "server error stack trace" \
  --where '{"$and": [{"status_code": {"$gte": 500}}, {"resp_len": {"$gte": 5000}}]}'
```

Use `{"is_static": false}` to exclude js/css/image noise from *traffic* searches. This
does not hide client-side code from analysis — the actual HTML/JS is retained and
searchable in the separate `web_code` collection (below); filtering `is_static` here
only trims redundant static-asset request/response pairs.

### `burp_traffic` filterable fields
- `url` (string): The full URL
- `endpoint` (string): The URL path (e.g., `/rest/user/login`)
- `host` (string): The request hostname (useful for multi-host scoping)
- `scheme` (string): `http` or `https` (flag plaintext traffic)
- `port` (int): The destination port
- `method` (string): HTTP method (`GET`, `POST`, etc.)
- `status` (string): HTTP response status code as text (`200`, `404`, etc.)
- `status_code` (int): Numeric status code — supports range filters (e.g. `{"status_code": {"$gte": 500}}`)
- `status_class` (string): Status bucket (`2xx`, `3xx`, `4xx`, `5xx`)
- `url_params` (string): Comma-separated list of URL query parameters
- `cookies` (string): Comma-separated list of cookie names sent in the request
- `body_params` (string): Comma-separated list of body parameters (from JSON or Form-Data)
- `param_count` (int): Total number of URL + body parameters
- `req_content_type` (string): Request Content-Type media type (e.g. `application/json`, `multipart/form-data`)
- `mimetype` (string): The response mimetype (e.g., `html`, `script`, `json`)
- `file_ext` (string): File extension of the endpoint (e.g. `php`, `json`, `js`)
- `is_static` (boolean): `true` for static assets (js/css/image/font) — filter these out to reduce noise
- `referer` (string): The Referer header from the request
- `cors_wildcard` (boolean): `true` if `Access-Control-Allow-Origin: *` is in the response
- `auth_role` (string): Parsed from JWT or session (`admin`, `authenticated`, `anonymous`)
- `authenticated` (boolean): `true` if the request carries credentials (Authorization header, a session/auth cookie, a JWT-shaped cookie value, or a custom API-key header)
- `time` (string): UTC timestamp of the request from Burp Suite (not numeric)
- `responselength` (string): Length of the response in bytes as text
- `resp_len` (int): Numeric response length — supports range filters (e.g. find large responses)

---

## 2. Hunt in client-side code (`--collection web_code`)

This is where DOM XSS sinks, hardcoded secrets, and hidden/undocumented endpoints live:

```bash
~/.config/opencode/skill/jeb-import/scripts/venv/bin/python \
  ~/.config/opencode/skill/jeb-query/scripts/agent_interface.py \
  --db-path ./chroma_db --collection web_code \
  --query "authentication token handling" --where '{"has_secrets": true}'
```

Useful `web_code` filters:
- `{"dom_sinks": {"$ne": ""}}` — potential DOM XSS
- `{"code_type": "form"}` — input surfaces
- `{"code_type": "inline_js"}` — inline scripts

### `web_code` filterable fields
- `content_kind` (string): always `web_code`
- `code_type` (string): `html`, `inline_js`, `external_js`, `vendor_js`, `script_ref`, `form`, `event_handler`, or `css`
- `host` / `source_url` (string): where the artifact was served from
- `source_urls` (string) / `url_count` (int): every URL this exact code appeared at
- `chunk_index` / `total_chunks` (int): position within the source artifact
- `has_secrets` (boolean): regex hit for API keys / tokens / private keys / JWTs
- `dom_sinks` (string): comma-separated DOM-XSS sinks found (`innerHTML`, `eval`, `document.write`, `postMessage`, …)
- `endpoints` (string) / `endpoint_count` (int): URLs/paths referenced in the code
- `embed` (boolean): `false` for store-only vendor/minified bundles (retrievable by `id` but excluded from semantic search)

---

## 3. Deep dive / recall by id

When you spot a suspicious or interesting document from a summary list, grab its `id`
and fetch the complete headers and raw body (traffic) or full code chunk (`web_code`):

```bash
# Traffic request/response
~/.config/opencode/skill/jeb-import/scripts/venv/bin/python \
  ~/.config/opencode/skill/jeb-query/scripts/agent_interface.py \
  --db-path ./chroma_db --id <document_id>

# Full web_code chunk (use the matching collection)
~/.config/opencode/skill/jeb-import/scripts/venv/bin/python \
  ~/.config/opencode/skill/jeb-query/scripts/agent_interface.py \
  --db-path ./chroma_db --collection web_code --id <document_id>
```

Use this to confirm vulnerabilities by reading the raw HTTP request/response text or the
complete source code chunk.

---

## 4. Find similar documents (`--similar-to <id>`)

Once you find one interesting document — a confirmed IDOR request, an auth-bypass
candidate, a secret-bearing JS chunk — pivot to everything that *looks like it* by
its stored vector. This is the embedding-native "show me more like this" primitive:

```bash
# Requests semantically similar to a known-interesting one
~/.config/opencode/skill/jeb-import/scripts/venv/bin/python \
  ~/.config/opencode/skill/jeb-query/scripts/agent_interface.py \
  --db-path ./chroma_db --similar-to <document_id> --n-results 10

# Similar client-side code chunks (matching collection), filtered
~/.config/opencode/skill/jeb-import/scripts/venv/bin/python \
  ~/.config/opencode/skill/jeb-query/scripts/agent_interface.py \
  --db-path ./chroma_db --collection web_code \
  --similar-to <document_id> --where '{"dom_sinks": {"$ne": ""}}'
```

The seed document is automatically excluded from its own results. `--similar-to`
honours `--where`, `--n-results`, and `--snippet-len`. Note: store-only chunks
(vendor/minified/CSS, `embed: false`) share a placeholder vector, so running
`--similar-to` on one of them is meaningless and prints a warning.
