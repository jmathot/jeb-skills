---
name: jeb-query
description: Investigate an imported Burp capture. Look up endpoints, map the app, inspect HTTP/auth/CORS behavior, traverse the knowledge graph, correlate identifiers, and record or recall findings from a project-local Chroma database. Use jeb-import first for new Burp XML.
---

# J.E.B. — query

Every command goes through this skill's launcher: `<skill-dir>/jeb`, which is
`~/.config/opencode/skills/jeb-query/jeb` in a default install.

```bash
~/.config/opencode/skills/jeb-query/jeb endpoint https://app.example/api/orders/42
```

- Run from the engagement project, or pass `--project-dir DIR` (or `--db-path DB`, not
  both), before or after the command.
- Embedding settings and credentials come from the project and OpenCode; nothing else
  needs configuring.
- Every command prints one JSON object with `command`, `count`, `results` and `next`.
  Errors are JSON with `error` and a nonzero exit; a failed query is not evidence of
  absence.

## Commands

| Need | Command | Useful flags |
|---|---|---|
| Everything about one route | `endpoint <path-or-url>` | `--host`, `--method`, `--no-raw`, `--raw-chars N` |
| Site structure | `map --node-type route` (or `origin`, `data_object`) | `--kind page\|action\|endpoint`, `--host`, `--limit`, `--offset` |
| Semantic search | `search "password reset form" --node-type behavior` | `--loose`, `--depth quick\|normal\|deep` |
| Filter observed records | `search --status '>=500' --param q` | filters below |
| Literal text | `search --contains "access-control-allow-origin: *"` | `--in exchanges` for full source |
| Read any id | `get <id>` | `--original` (base64 HTTP) |
| Supporting observations | `evidence <behavior_id>` | `--signal content\|schema` |
| More like this | `similar <id>` | `--limit` |
| Graph neighbours | `graph <id>` | `--rel HAS_BEHAVIOR`, `--direction in\|out\|both`, `--hops 1\|2` |
| Where a value appears | `identifier <value>` | `--limit`, `--offset` |
| Recorded findings | `attacks` | `--vuln-class`, `--verdict`, `--path` |
| Record a finding | `record-attack --vuln-class SQLi --endpoint <abs-url> ...` | see below |

Filters for `map`/`search`/`attacks`:
- facets: `--host`, `--path`, `--method`, `--status`, `--param`, `--cookie`,
  `--missing-header`, `--kind`, `--access-control`, `--access-class`;
- booleans: `--anon`, `--auth`, `--anon-matches-auth`, `--cors-open`, `--cookie-issues`,
  `--jwt`, `--include-static`.

Invalid values are rejected with the valid list. Read `references/retrieval.md` for
filter values, depth budgets, cutoffs and source-exchange search.

## Follow `next`

`next` holds ready-to-run shell commands with real ids filled in, using the same
project selection you passed. Prefer them over composing a new query. Fill any
`<placeholder>` first.

## Interpret carefully

- The database records what was observed, not what exists. Client-named routes with
  `observed=false` are leads.
- Route nodes carry protocol facts, not page content. To find a form, heading or
  visible text, search `--node-type behavior` (or `section`/`form`).
- Searching graph text for vulnerability names (`sqli`, `xss`, ...) removes those
  terms (`rejected_terms`). Search the structural signal instead. Vulnerability
  classes live only in `attacks`.
- Credential presence is not successful authentication. `--anon` means no recognized
  credential, and public data alone is not a vulnerability.
- `anon_matches_auth` means identical response bodies with and without credentials.
  It does not prove the credentials were accepted. Schema matches are weaker.
- CORS `matches-origin` is one equality observation, not proven reflection.
- Equal identifier values, and entity links, are leads, not proof of the same record.
  Identifier extraction is sampled, so a miss is not proof of absence.
- An empty search is not absence: read `fallback`, retry with `--loose`, and check
  `notes`, `index_state` and `incomplete_captures`.

## Findings

```bash
jeb record-attack --vuln-class SQLi --endpoint https://app.example/api/search \
  --method GET --param q --payload "'" --status 500 --verdict inconclusive \
  --source-id <behavior-id> --evidence "Database error in response" \
  --request-file req.txt --response-file resp.txt --event-id <retry-key>
```

- Record every test, including `not_vulnerable` ones. Verdicts are `vulnerable`,
  `not_vulnerable` and `inconclusive`.
- `--event-id` makes retries idempotent.
- If a profile mismatch or rebuild note appears, run the jeb-import `rebuild` command
  it gives. Never delete the database.
