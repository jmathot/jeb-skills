---
name: jeb-query
description: Query step for J.E.B. — investigate a specific endpoint or URL from an imported Burp Suite capture, map the site, search request/response behavior, correlate endpoints by data shape or identifier value, and record or recall findings by vulnerability class. USE WHEN asked to look at an endpoint or path, map an app, find endpoints reachable anonymously, inspect cookies/headers/auth/CORS, chase an id across endpoints, or log an attack result. To first parse and embed a Burp XML export, use the jeb-import skill.
---

# J.E.B. — Query / Hunting Interface (v4)

Queries a ChromaDB built by the **`jeb-import`** skill. If the database does not
exist yet, run `jeb-import` first.

Every command starts with this prefix. Run it in full every time — a shell
variable set in one command is **not** available in the next:
```
~/.config/opencode/skill/jeb-query/scripts/jeb-query.sh
```

Run from the project directory so `./chroma_db` resolves to that project's
database, or pass `--db-path <project_dir>/chroma_db`. Projects never mix.

## Pick your command

| Situation | Command |
|---|---|
| The user named an endpoint, path or URL | `endpoint /api/orders` |
| You want the site map | `map` |
| You are describing behavior in words | `search "password reset token"` |
| You want a filtered list, no words | `search --in structure --anon` |
| You have a document id | `get <id>` |
| You want more like this document | `similar <id>` |
| You have a concrete id/uuid value | `identifier 42` |
| You finished testing something | `record-attack --vuln-class ... --endpoint ...` |
| You want findings you already logged | `attacks --vuln-class SQLi` |

Every command prints one JSON object with `count`, `results`/`matches`, `notes`
and `next`. Read `next` — it names the follow-up commands with real ids in them.

## What is NOT in the index

`structure` and `behavior` store **protocol structure only**: methods, path
templates, parameter names, status codes, content types, auth roles and
mechanisms, cookie names and flags, missing security headers, CORS posture, JWT
alg and claims.

They contain **no vulnerability names**. Never put words like `sqli`,
`xss`, `ssrf`, `idor`, `csrf`, `rce` or `vulnerability` into `search` — they are
stripped before the query runs and reported back in `rejected_terms`. To
investigate a vulnerability, search for its *structural signal* (a parameter
name, a 500 status, an anonymous 200) or start from `endpoint`. Vulnerability
classes exist only in `attacks`, as the `vuln_class` field.

---

## 1. `endpoint <path|url>` — start here

```bash
~/.config/opencode/skill/jeb-query/scripts/jeb-query.sh endpoint /api/orders
```
Accepts `/api/orders`, `/api/orders/42` or `https://app/api/orders?limit=10` —
concrete ids are normalised to the stored template automatically.

You get back: every matching route with its parameters, auth posture, cookies
sent and set, missing security headers and CORS; the origin's **auth model**;
sub-paths and sibling routes; **entity links** to routes sharing the same data
shape; the behavior documents it was seen in; and the **raw request/response**
of one representative exchange.

Flags: `--host`, `--method`, `--depth quick|normal|deep`, `--no-raw`.

## 2. `map` — the site map

```bash
~/.config/opencode/skill/jeb-query/scripts/jeb-query.sh map
~/.config/opencode/skill/jeb-query/scripts/jeb-query.sh map --kind auth_model
```
`--kind` is `page`, `endpoint`, `action`, `auth_model` or `entity`.

## 3. `search [text]` — hybrid search, or a pure filter

```bash
# words: matched against route, response and access concepts
~/.config/opencode/skill/jeb-query/scripts/jeb-query.sh search "password reset token" --method POST

# no words: a pure metadata filter
~/.config/opencode/skill/jeb-query/scripts/jeb-query.sh search --in structure --anon
~/.config/opencode/skill/jeb-query/scripts/jeb-query.sh search --status '>=500' --param q
~/.config/opencode/skill/jeb-query/scripts/jeb-query.sh search --contains "Access-Control-Allow-Origin: *"
```

`--in structure|behavior|attacks` (default `behavior`). Static js/css/image
noise is excluded automatically; pass `--include-static` to keep it.

Filters: `--host`, `--method`, `--path`, `--status 500|'>=500'|500-599|5xx`,
`--anon`, `--auth`, `--param`, `--cookie`, `--missing-header csp`, `--cors-open`,
`--contains`, `--kind`, `--access-control`, `--access-class`,
`--anon-matches-auth`, `--cookie-issues`, `--jwt`.

Sizing: `--depth quick|normal|deep` (default `normal`), or `--limit N`. If a
search returns nothing, read `fallback` — those are the closest matches with the
relevance cutoff disabled — or retry with `--loose`.

**Access control.** `--anon` on `structure` means an anonymous request actually
**received application data** (real broken access control). A "200 OK that
returns the login page" is not flagged; find those with
`--access-control soft-auth-wall`. On `behavior`, `--anon-matches-auth` is the
strongest signal: the anonymous response matched the authenticated one.

## 4. `get <id>` / `similar <id>`

```bash
~/.config/opencode/skill/jeb-query/scripts/jeb-query.sh get <id>
~/.config/opencode/skill/jeb-query/scripts/jeb-query.sh similar <id> --limit 10
```
`get` returns full metadata plus the raw request/response (or the node report for
`structure`). The collection is detected from the id — you never need to say it.

## 5. `identifier <value>` — same record, different endpoint

```bash
~/.config/opencode/skill/jeb-query/scripts/jeb-query.sh identifier 42
```
Every document, in any collection, that referenced that concrete id/uuid/hash —
in a URL path segment or a JSON field named `id`, `*_id`, `uuid` or `guid`.
Entity links (from `endpoint`) prove two routes share a data *shape*;
`identifier` proves they touched the same *record*. That pairing is the evidence
for an IDOR/BOLA chain: write through one route, read it back through the other.

## 6. `record-attack` / `attacks`

Log every active test, including the ones that found nothing.
```bash
~/.config/opencode/skill/jeb-query/scripts/jeb-query.sh record-attack \
  --vuln-class SQLi --endpoint "https://app/api/search" --method GET \
  --param q --payload "' OR 1=1--" --status 500 --verdict vulnerable \
  --severity high --source-id <behavior_id> --evidence "SQLSyntaxErrorException" \
  --request-file req.txt --response-file resp.txt
```
Required: `--vuln-class`, `--endpoint`. Verdicts: `vulnerable` |
`not_vulnerable` | `inconclusive` (default).

```bash
~/.config/opencode/skill/jeb-query/scripts/jeb-query.sh attacks --vuln-class SQLi
~/.config/opencode/skill/jeb-query/scripts/jeb-query.sh attacks --verdict vulnerable
```

---

## Field reference

**`structure`** — `node_kind` (`page`|`endpoint`|`action`|`auth_model`|`entity`),
`scheme`, `host`, `port`, `endpoint_template`, `method`, `param_names` (csv),
`produces`, `status_codes`, `path_depth`, `instance_count`,
`authenticated_ever`, `anon_allowed`, `anon_soft_denied`, `access_control`
(`open-data`|`soft-auth-wall`|`enforced`|`unknown`), `auth_mechanisms`,
`cookies_sent`, `cookies_set`, `security_headers_missing`, `cors`, `is_static`,
`example_ids`, `entity_ids`. Entity nodes add `schema_sig`, `identifier_field`,
`produced_by`, `consumed_by`.

**`behavior`** — `scheme`, `host`, `port`, `endpoint_template`, `method`,
`status_code`, `resp_len`, `param_names`, `param_count`, `req_content_type`,
`resp_content_type`, `is_static`, `instance_count`, `time`, `access_class`
(`data`|`auth_wall`|`shell`|`denied`|`redirect`|`empty`|`static`|`other`),
`anon_matches_auth`, `authenticated`, `auth_role`, `auth_mechanism`,
`req_features` (`origin-cross-site`, `csrf-token`, `custom-auth-header`,
`host=…`), `cookie_names`, `set_cookies`, `cookie_issues`,
`security_headers_missing`, `cors`, `jwt`, `redirect_location`.

**`attacks`** — `vuln_class`, `verdict`, `severity`, `host`,
`endpoint_template`, `method`, `param`, `status_code`, `source_behavior_id`,
`payload`, `tool`, `time`.

> `cors` is stored as the bare posture on `structure` (`*`, `reflected`, `null`,
> `specific`) but with a `" creds"` suffix on `behavior` when credentials are
> allowed. Use `--cors-open`, which matches every permissive spelling in both.
