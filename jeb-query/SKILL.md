---
name: jeb-query
description: Query step for J.E.B. — hunt for vulnerabilities across a Burp capture mapped into three ChromaDB collections (structure, behavior, attacks). USE WHEN searching/querying an already-imported Burp database, hunting vulns, mapping the site/endpoints, semantic search over request/response behavior, filtering by metadata or raw header/cookie substrings, correlating endpoints that share a data structure or an identifier value, recording attack results, or deep-diving a specific doc by id. To first parse and embed a Burp XML export, use the jeb-import skill.
---

# J.E.B. — Query / Hunting Interface (v4)

This skill queries a ChromaDB populated by the **`jeb-import`** skill. If the
database does not exist yet, run `jeb-import` first.

Every command below starts with the same fixed prefix — run it exactly as shown,
in full, every time; do not shorten it or store it in a variable, since a shell
variable set in one command is **not** available in the next command:
```
~/.config/opencode/skill/jeb-query/scripts/jeb-query.sh
```

**Always query the database belonging to the project you are working on.** Run
from the project directory so `./chroma_db` resolves to that project's DB, or pass
`--db-path <project_dir>/chroma_db`. Data from separate projects is never mixed.

## The three collections (`--collection`)

- **`structure`** — the site map: endpoint templates, pages, actions, and one
  per-origin `auth_model` node. Start here to understand the app and to find
  broken-access-control candidates.
- **`behavior`** (default) — one doc per distinct request/response behavior.
- **`attacks`** — results of your active testing, written by `record-attack`.

## How search works

- semantic `--query` matches route, response, and access concepts,
- lexical retrieval recovers exact endpoints, parameters, and protocol terms,
- `--where` filters metadata facets (equality / `$in` / numeric ranges),
- `--where-document` substring-matches the **raw** HTTP (behavior/attacks) or
  the node report text (structure).

Always wrap the entire `--where`/`--where-document` JSON value in single quotes
(as in every example below), even for a one-field filter. Results are ranked by
a fused `score` (higher = better).

### Retrieval controls

- `--candidate-k 40`: candidates requested from each retrieval path.
- `--top-k 8` (alias `--n-results`): hard maximum returned results.
- `--max-distance`: maximum dense cosine distance. Defaults are collection-specific.
- `--min-score 0.0`: minimum normalized fused relevance score from 0 to 1.
- `--top-p 0.90`: return the smallest ranked prefix covering 90% of available
  relevance mass, after `--min-results` is satisfied. This is deterministic
  retrieval selection, not an LLM generation sampling parameter.
- `--min-results 3`: minimum result floor before `top_p` can stop selection.
- `--max-per-endpoint 2`: diversity limit per `(host, endpoint_template)`.

The defaults above are fine for most searches — leave them out unless tuning
precision or recall. Push `--candidate-k`/`--top-k`/`--top-p` up for broader
recall, down for tighter precision:
```bash
~/.config/opencode/skill/jeb-query/scripts/jeb-query.sh \
  --db-path ./chroma_db --query "password reset token" \
  --candidate-k 30 --top-k 5 --top-p 0.80 --min-score 0.35
```

---

## 1. Map the app (`--collection structure`)

```bash
~/.config/opencode/skill/jeb-query/scripts/jeb-query.sh \
  --db-path ./chroma_db --collection structure \
  --query "authentication and account management"
```
Read the per-origin **auth model** node (`--where '{"node_kind":"auth_model"}'`) to
see which cookies are set vs consumed where, the token type, and the app-wide
missing-header posture.

**Broken access control** — endpoints reachable without credentials:
```bash
~/.config/opencode/skill/jeb-query/scripts/jeb-query.sh \
  --db-path ./chroma_db --collection structure \
  --query "admin or sensitive endpoint" --where '{"anon_allowed": true}'
```

`anon_allowed: true` means an anonymous request actually **received application
data** (real broken access control) — it is content-aware, so a "200 OK that
returns the login page" (a *soft auth wall*) is **not** flagged. Those are marked
`access_control: soft-auth-wall` instead. Find soft walls (endpoints that are
protected but answer 200 with a login/deny page) separately:
```bash
~/.config/opencode/skill/jeb-query/scripts/jeb-query.sh \
  --db-path ./chroma_db --collection structure \
  --where '{"access_control": "soft-auth-wall"}'
```
`anon_matches_auth: true` on a behavior doc is the strongest signal: the anon
response matched the authenticated response byte-for-structure.

**Correlate endpoints that share a data structure** — find every route reading
or writing the same underlying object (e.g. does anything else touch the "user"
that `POST /users/edit` writes?). Every `structure` route node carries
`entity_ids`, pointing at synthetic `node_kind: "entity"` nodes built by
grouping every endpoint's response/request-body JSON/XML key-schema across the
**whole app** (not just within one route). Query the entity directly, or pivot
from a route's `entity_ids`:
```bash
~/.config/opencode/skill/jeb-query/scripts/jeb-query.sh \
  --db-path ./chroma_db --collection structure \
  --where '{"node_kind": "entity"}' --query "user"
```
An entity node's `produced_by`/`consumed_by` list every `METHOD endpoint_template`
that returns/writes that shape — e.g. `produced_by: GET /users/{id}` and
`consumed_by: POST /users/edit` means both touch the same record shape. This is
**structural** correlation (same/overlapping fields), confidence boosted by
`related` fuzzy matches (Jaccard-overlapping key sets) noted in the entity's
`page_content` when schemas are close but not identical. For **instance-level**
proof that two requests touched the *same record* (not just the same shape), use
`--identifier` (§6) to match on an actual id/uuid value shared between them.

### `structure` filterable fields
- `doc_kind` (str): always `structure`
- `node_kind` (str): `page` | `endpoint` | `action` | `auth_model` | `entity`
- `scheme`, `host`, `endpoint_template`, `method` (str), `port` (int)
- `param_names` (str, csv), `produces` (str, csv content types)
- `status_codes` (str, csv), `path_depth` (int), `instance_count` (int)
- `authenticated_ever` (bool), `anon_allowed` (bool — anon received real data)
- `anon_soft_denied` (bool — anon got a 200 login/deny surrogate)
- `access_control` (str): `open-data` (real BAC) | `soft-auth-wall` | `enforced`
  (saw 401/403) | `unknown`
- `auth_mechanisms` (str, csv), `cookies_sent` (str, csv), `cookies_set` (str, csv)
- `security_headers_missing` (str, csv), `cors` (str: `*`/`reflected`/`null`/`specific`)
- `is_static` (bool), `example_ids` (str, csv — behavior ids to pivot into)
- `entity_ids` (str, csv — on a route node: which `entity` node(s) its
  request/response shape belongs to)
- `schema_sig`, `identifier_field`, `produced_by`, `consumed_by` (str — on
  `node_kind: "entity"` nodes only; see above)

---

## 2. Hunt behavior (`--collection behavior`, default)

```bash
~/.config/opencode/skill/jeb-query/scripts/jeb-query.sh \
  --db-path ./chroma_db \
  --query "password reset token in response" --where '{"method": "POST"}'
```

Numeric fields support ranges — server errors with large bodies:
```bash
~/.config/opencode/skill/jeb-query/scripts/jeb-query.sh \
  --db-path ./chroma_db --query "server error stack trace" \
  --where '{"$and": [{"status_code": {"$gte": 500}}, {"resp_len": {"$gte": 5000}}]}'
```

Filter on **raw** header/cookie text with `--where-document` (substring, case
sensitive):
```bash
# CORS wildcard responses
~/.config/opencode/skill/jeb-query/scripts/jeb-query.sh \
  --db-path ./chroma_db --query "cross origin api" \
  --where-document '{"$contains": "Access-Control-Allow-Origin: *"}'

# Session cookies without SameSite
~/.config/opencode/skill/jeb-query/scripts/jeb-query.sh \
  --db-path ./chroma_db --query "session cookie" \
  --where-document '{"$contains": "Set-Cookie"}'
```

Use `{"is_static": false}` to drop js/css/image noise.

### `behavior` filterable fields
- `doc_kind` (str): always `behavior`
- `scheme`, `host`, `endpoint_template`, `method` (str), `port` (int)
- `status_code` (int, ranges), `resp_len` (int, ranges)
- `param_names` (str, csv), `param_count` (int)
- `req_content_type`, `resp_content_type` (str)
- `is_static` (bool), `instance_count` (int), `time` (str)
- `access_class` (str): `data` | `auth_wall` | `shell` | `denied` | `redirect` |
  `empty` | `static` — what the response actually delivered
- `anon_matches_auth` (bool — anon response matched the authenticated one)
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
~/.config/opencode/skill/jeb-query/scripts/jeb-query.sh \
  --db-path ./chroma_db --collection behavior --id <document_id>
```
Returns the full metadata and the raw request/response (or the node report for
`structure`). Use `example_ids` from a `structure` node to jump to its behaviors.

## 4. Find similar (`--similar-to <id>`)

```bash
~/.config/opencode/skill/jeb-query/scripts/jeb-query.sh \
  --db-path ./chroma_db --similar-to <document_id> --n-results 10
```
Nearest neighbours by the canonical stored vector — the "more like this" pivot. Honours
`--where`, `--where-document`, `--n-results`.

## 5. Record an attack result (`--record-attack`)

After actively testing a request, persist the outcome to the `attacks`
collection so it is searchable and remembered across sessions. **Required:
`--vuln-class` and `--endpoint`. Every other flag below is optional**
(`--verdict` defaults to `inconclusive`).
```bash
~/.config/opencode/skill/jeb-query/scripts/jeb-query.sh \
  --db-path ./chroma_db --record-attack \
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

## 6. Correlate by identifier value (`--identifier`)

Entity nodes (§1) prove two endpoints share a data *shape*; `--identifier` proves
they touched the same *record*. It's an exact-match lookup across every
collection for a concrete id/uuid/hash value seen in a URL path segment or a
JSON field named like an identifier (`id`, `*_id`, `uuid`, `guid`):
```bash
~/.config/opencode/skill/jeb-query/scripts/jeb-query.sh \
  --db-path ./chroma_db --identifier 42
```
Returns every `{id, collection, field}` hit, regardless of `--collection` —
e.g. a `behavior` doc for `GET /users/42` and another for `POST /users/edit`
whose body contained `"user_id": "42"`. Pivot into each with `--id <id>
--collection <collection>` to read the full raw request/response. This is the
concrete version of the "does this POST edit the same user this GET returned"
question: matching `entity_ids` says probably (same shape); a matching
`--identifier` says yes (same record) — strong evidence for chaining an
IDOR/BOLA test (edit as one user, read back via the other endpoint to confirm
impact).
