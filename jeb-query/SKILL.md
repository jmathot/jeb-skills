---
name: jeb-query
description: Investigate a Burp Suite capture imported with jeb-import, for web pentesting. Look up an endpoint, map the site, check auth/CORS/cookie posture, traverse the knowledge graph, correlate identifiers, and record or recall findings.
---

# JEB — query

Every command goes through this skill's launcher: `<skill-dir>/jeb`, which is
`~/.config/opencode/skills/jeb-query/jeb` in a default install. **Below, `jeb` means
that full path**; there is no `jeb` on PATH. Always pass `--project-dir DIR` (the
engagement directory), or `--db-path DB`, not both.

## Typical session

```bash
jeb endpoint https://app.example/api/orders/42 --project-dir DIR   # a named route: start here
jeb map --node-type route --project-dir DIR                        # no target yet: list routes
jeb graph <id> --project-dir DIR                                   # what it connects to
jeb get <id> --project-dir DIR                                     # the full record or exchange
jeb record-attack --project-dir DIR ...                            # after every test
```

## Output

- One JSON object per command, with `command`, `count`, `results` and `next`.
- `next` holds up to three ready-to-run commands with real ids and your project
  selection. Prefer them over composing a new query; fill any `<placeholder>` first.
- Results are a **brief view**: internal and default-valued keys are left out, and
  so are false flags (a missing flag means false). `--full` shows every stored field,
  `get` always does, and `--pretty` indents the JSON.
- Errors are JSON with `error` (usage errors add `help`). Exit 2 means bad usage, 1
  means the query failed. A failed query is not evidence of absence.

## What the graph holds

| `--node-type` | What it is |
|---|---|
| `route` | One per host + method + path template: protocol facts only, nothing from a body |
| `behavior` | A route's response layer: the same facts plus the distilled body (JSON fields; HTML title, headings, forms, visible text) |
| `origin` | A host's session/auth model: mechanisms, cookies set vs. consumed |
| `data_object` | A schema seen at two or more routes, linking readers and writers |
| `posture` | Missing headers / CORS shared by several routes |
| `section` / `form` | Page sections and explicit input surfaces |

To find a page by its content, search `--node-type behavior` (or `section`/`form`).

## Commands

| Need | Command | Useful flags |
|---|---|---|
| Everything about one route | `jeb endpoint <path-or-url>` | `--host`, `--method`, `--no-raw`, `--raw-chars N` |
| Site structure | `map --node-type route` (or `origin`, `data_object`) | `--kind page\|action\|endpoint`, `--limit`, `--offset` |
| Semantic search | `search "password reset form" --node-type behavior` | `--loose`, `--depth quick\|normal\|deep` |
| Filter observed records | `search --status '>=500' --param q` | filters below |
| Literal text | `search --contains "access-control-allow-origin: *"` | `--in exchanges` for full source |
| Read any id | `get <id>` | `--original` (base64 HTTP) |
| Supporting observations | `evidence <behavior_id>` | `--signal content\|schema` |
| More like this | `similar <id>` | `--limit` |
| Graph neighbours | `graph <id>` | `--rel HAS_BEHAVIOR`, `--direction in\|out\|both`, `--hops 1\|2` |
| Where a value appears | `identifier <value>` | `--limit`, `--offset` |
| Recorded findings | `attacks` | `--vuln-class`, `--verdict`, `--path` |
| Index and capture state | `status` | |

Filters for `map`/`search`/`attacks`: facets `--host`, `--path`, `--method`,
`--status`, `--param`, `--cookie`, `--missing-header`, `--kind`, `--access-control`,
`--access-class`; booleans `--anon`, `--auth`, `--anon-matches-auth`, `--cors-open`,
`--cookie-issues`, `--jwt`, `--include-static`. Invalid values are rejected with the
valid list. Read `references/retrieval.md` for filter values, depth budgets, cutoffs
and source-exchange search.

## Interpret carefully

- The database records what was observed, not what exists. Client-named routes with
  `observed=false` are leads.
- Searching for vulnerability names (`sqli`, `xss`, ...) strips those terms
  (`rejected_terms`). Search the structural signal; vulnerability classes live only
  in `attacks`.
- Credential presence is not successful authentication. `--anon` means no recognized
  credential, and public data alone is not a vulnerability.
- `anon_matches_auth` means identical response bodies with and without credentials;
  it does not prove the credentials were accepted. Schema matches are weaker.
- CORS `matches-origin` is one equality observation, not proven reflection.
- Equal identifier values and entity links are leads, not proof of the same record.
  Identifier extraction is sampled, so a miss is not proof of absence.
- An empty search is not absence: read `fallback`, retry with `--loose`, and check
  `notes`, `index_state` and `incomplete_captures`.

## Findings

```bash
jeb record-attack --project-dir DIR --vuln-class SQLi --endpoint https://app.example/api/search \
  --method GET --param q --payload "'" --status 500 --verdict inconclusive \
  --source-id <behavior-id> --evidence "Database error in response" \
  --request-file req.txt --response-file resp.txt --event-id <retry-key>
```

Record every test, including `not_vulnerable` ones (verdicts: `vulnerable`,
`not_vulnerable`, `inconclusive`). `--event-id` makes retries idempotent. If a
profile-mismatch or rebuild note appears, run the jeb-import `rebuild` command it
gives. Never delete the database.
