---
name: jeb-query
description: Query step for J.E.B. — hunt for vulnerabilities across a Burp capture mapped into three ChromaDB collections (structure, behavior, attacks). USE WHEN searching/querying an already-imported Burp database, hunting vulns, mapping the site/endpoints, semantic search over request/response behavior, filtering by metadata or raw header/cookie substrings, recording attack results, or deep-diving a specific doc by id. To first parse and embed a Burp XML export, use the jeb-import skill.
---

# J.E.B. — Query / Hunting Interface (v2)

This skill queries a ChromaDB populated by the **`jeb-import`** skill. If the
database does not exist yet, run `jeb-import` first.

```
PY=~/.config/opencode/skill/jeb-import/scripts/venv/bin/python
AGENT=~/.config/opencode/skill/jeb-query/scripts/agent_interface.py
```

**Always query the database belonging to the project you are working on.** Run
from the project directory so `./chroma_db` resolves to that project's DB, or pass
`--db-path <project_dir>/chroma_db`. Data from separate projects is never mixed.

## The three collections (`--collection`)

- **`structure`** — the site map: endpoint templates, pages, actions, and one
  per-host `auth_model` node. Start here to understand the app and to find
  broken-access-control candidates.
- **`behavior`** (default) — one doc per distinct request/response behavior.
- **`attacks`** — results of your active testing, written by `record-attack`.

## How search works

The vector is a distilled, value-suppressed summary of each doc; the stored
document is the **raw HTTP** (behavior/attacks) or a readable node report
(structure). So:
- semantic `--query` matches concepts (incl. a security clause: cookies, missing
  headers, CORS, cross-site origin, JWT alg),
- `--where` filters metadata facets (equality / `$in` / numeric ranges),
- `--where-document` substring-matches the **raw** headers/cookies/body.

Every result includes a `distance` (lower = closer) and a `summary` snippet.

---

## 1. Map the app (`--collection structure`)

```bash
"$PY" "$AGENT" --db-path ./chroma_db --collection structure \
  --query "authentication and account management"
```
Read the per-host **auth model** node (`--where '{"node_kind":"auth_model"}'`) to
see which cookies are set vs consumed where, the token type, and the app-wide
missing-header posture.

**Broken access control** — endpoints reachable without credentials:
```bash
"$PY" "$AGENT" --db-path ./chroma_db --collection structure \
  --query "admin or sensitive endpoint" --where '{"anon_allowed": true}'
```

### `structure` filterable fields
- `doc_kind` (str): always `structure`
- `node_kind` (str): `page` | `endpoint` | `action` | `auth_model`
- `host`, `endpoint_template`, `method` (str)
- `param_names` (str, csv), `produces` (str, csv content types)
- `status_codes` (str, csv), `path_depth` (int), `instance_count` (int)
- `authenticated_ever` (bool), `anon_allowed` (bool)
- `auth_mechanisms` (str, csv), `cookies_sent` (str, csv), `cookies_set` (str, csv)
- `security_headers_missing` (str, csv), `cors` (str: `*`/`reflected`/`null`/`specific`)
- `is_static` (bool), `example_ids` (str, csv — behavior ids to pivot into)

---

## 2. Hunt behavior (`--collection behavior`, default)

```bash
"$PY" "$AGENT" --db-path ./chroma_db \
  --query "password reset token in response" --where '{"method": "POST"}'
```

Numeric fields support ranges — server errors with large bodies:
```bash
"$PY" "$AGENT" --db-path ./chroma_db --query "server error stack trace" \
  --where '{"$and": [{"status_code": {"$gte": 500}}, {"resp_len": {"$gte": 5000}}]}'
```

Filter on **raw** header/cookie text with `--where-document` (substring, case
sensitive):
```bash
# CORS wildcard responses
"$PY" "$AGENT" --db-path ./chroma_db --query "cross origin api" \
  --where-document '{"$contains": "Access-Control-Allow-Origin: *"}'

# Session cookies without SameSite
"$PY" "$AGENT" --db-path ./chroma_db --query "session cookie" \
  --where-document '{"$contains": "Set-Cookie"}'
```

Use `{"is_static": false}` to drop js/css/image noise.

### `behavior` filterable fields
- `doc_kind` (str): always `behavior`
- `host`, `endpoint_template`, `method` (str)
- `status_code` (int, ranges), `resp_len` (int, ranges)
- `param_names` (str, csv), `param_count` (int)
- `req_content_type`, `resp_content_type` (str)
- `is_static` (bool), `instance_count` (int), `time` (str)
- `authenticated` (bool), `auth_role` (str), `auth_mechanism` (str:
  `cookie-session`/`bearer-jwt`/`bearer-opaque`/`basic`/`api-key-header`/`custom-header`/`none`)
- `cookie_names` (str, csv — sent), `set_cookies` (str, csv — name+flags)
- `cookie_issues` (str, csv — e.g. `SID:no-httponly,no-samesite`)
- `security_headers_missing` (str, csv), `cors` (str, e.g. `* creds`)
- `jwt` (str, e.g. `alg=none;claims=sub,role,exp`), `redirect_location` (str)

> Compact csv fields (`cookie_issues`, `security_headers_missing`, …) support
> equality / `$in` only. For precise substring matching, use `--where-document`
> against the raw HTTP.

---

## 3. Deep dive / recall by id (`--id`)

```bash
"$PY" "$AGENT" --db-path ./chroma_db --collection behavior --id <document_id>
```
Returns the full metadata and the raw request/response (or the node report for
`structure`). Use `example_ids` from a `structure` node to jump to its behaviors.

## 4. Find similar (`--similar-to <id>`)

```bash
"$PY" "$AGENT" --db-path ./chroma_db --similar-to <document_id> --n-results 10
```
Nearest neighbours by stored vector — the "more like this" pivot. Honours
`--where`, `--where-document`, `--n-results`.

## 5. Record an attack result (`--record-attack`)

After actively testing a request, persist the outcome to the `attacks`
collection so it is searchable and remembered across sessions:
```bash
"$PY" "$AGENT" --db-path ./chroma_db --record-attack \
  --vuln-class SQLi --endpoint "https://app/rest/products/search" --method GET \
  --param q --payload "' OR 1=1--" --status 500 --verdict vulnerable \
  --severity high --source-id <behavior_id> \
  --evidence "SQLSyntaxErrorException" \
  --request-file req.txt --response-file resp.txt
```
Verdicts: `vulnerable` | `not_vulnerable` | `inconclusive`. Query them back with
`--collection attacks --query "..."` or `--where '{"verdict":"vulnerable"}'`.

### `attacks` filterable fields
- `doc_kind` (str): always `attack`
- `vuln_class`, `verdict`, `severity` (str)
- `host`, `endpoint_template`, `method`, `param` (str)
- `status_code` (int), `source_behavior_id` (str), `payload` (str), `tool` (str), `time` (str)
