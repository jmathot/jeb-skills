---
name: jeb-query
description: Investigate endpoints, map an app, inspect HTTP/auth/CORS behavior, correlate identifier evidence, and record or recall findings from a project-local Chroma database. Use jeb-import first for new Burp XML traffic.
---

# J.E.B. — Chroma Query Interface

Run each command with the complete installed script path:

```bash
~/.config/opencode/skills/jeb-query/scripts/jeb-query.sh endpoint https://app.example/api/orders/42
```

Run from the engagement project, or supply `--project-dir /path/to/project`
or `--db-path /path/to/chroma_db` (not both). Use this skill's actual base directory
instead of the default paths below when installed elsewhere. Embedding settings
are inherited from the project's import selections; no settings file or exports
are needed. OpenCode provider credentials are resolved privately only when needed.
Batch/retrieval/depth defaults are configured through `jeb-import` switches and
inherited from Chroma; legacy JEB environment overrides are ignored. An execution-only
`--opencode-server URL` (or `--no-opencode-server`) selects the API server without
changing the saved project defaults. It uses the OpenCode CLI's normal authentication.
The source repository is not the engagement data directory.

## Commands

| Need | Command |
|---|---|
| Named endpoint or URL | `endpoint <path-or-url>` |
| Site map | `map --limit 50 --offset 0` |
| Search concepts | `search "password reset email" --method POST` |
| Filter observed records | `search --status '>=500' --param q` |
| Literal preview substring | `search --contains "access-control-allow-origin: *"` |
| Exact identifier evidence | `identifier 42 --limit 50 --offset 0` |
| Read an observation or document | `get <id>` |
| Supporting observations | `evidence <behavior_id> --limit 50 --offset 0` |
| Supporting content comparisons | `evidence <behavior_id> --signal content` |
| Related semantic documents | `similar <id>` |
| Typed graph neighbors | `graph <id> --direction both --hops 1 --limit 50` |
| Recorded findings | `attacks --vuln-class SQLi` |

## Retrieval semantics

Semantic search uses the project's selected embedding backend and Chroma cosine
distance only. There is no lexical
search, BM25, RRF, `top_p`, or normalized confidence score. Results resolve
segments/variants to their canonical parents and include the matching IDs and
representations. Lower `distance` is closer; it does not establish relevance or
security impact by itself.

Use `--depth quick|normal|deep` or `--limit N`. Defaults:

| Depth | Candidates | Maximum results | Response preview characters |
|---|---:|---:|---:|
| quick | 20 | 5 | 0 |
| normal | 40 | 8 | 2,000 |
| deep | 120 | 25 | 8,000 |

`--loose` disables the distance cutoff. Empty searches can contain `fallback`
matches with that cutoff disabled, while retaining metadata/content constraints.
`candidate_limit_reached` warns that semantic candidate selection may limit recall.
Candidates expand adaptively up to 1,000 when filtering leaves too few eligible
parents. Diagnostics report the final candidate budget and post-filter rejections.
Metadata-only listings page the collection fully and return `total`, `complete`,
`offset`, and `has_more`. Use `--offset` only for listings without search text.
`complete` describes enumeration, not capture coverage or import consistency;
always check `incomplete_captures`, `index_state`, and `notes`.

Filters: `--host`, `--method` (repeatable), `--path`, `--status`, `--param`,
`--cookie`, `--missing-header`, `--anon`, `--auth`, `--cors-open`, `--kind`,
`--access-control`, `--access-class`, `--anon-matches-auth`, `--cookie-issues`,
`--jwt`, `--contains`. `--in graph|attacks` selects semantic scope;
`--node-type route|behavior|origin|data_object|posture|section|form` narrows graph
search/listing. The old `structure` and `behavior` collections require rebuild
through `jeb-import`. Graph nodes have typed edges (for example `HAS_BEHAVIOR`,
`RETURNS`, `CONTAINS`, `SUBMITS_TO`, `CALLS`); `graph --rel` filters a relation.
Static assets are excluded by default; add `--include-static` when relevant.
Collection-incompatible facets are rejected. Cookie names match exactly, including
case, rather than by substring.

`--contains` is case-sensitive and searches canonical/variant previews, not every
original exchange byte. Reconstructed header names are lowercase. Source evidence
is accessible through `exchange_id` or identifier hits. `get <exchange_id>` includes
decoded HTTP, capture ID, source item position, and comparison evidence references.
Add `--original` to include original HTTP base64; it is omitted by default.

For text outside retained representative previews:

```bash
~/.config/opencode/skills/jeb-query/scripts/jeb-query.sh search --in exchanges \
  --host app.example --contains "SQLSyntaxError"
```

Source scope supports host/method/path and exact metadata filters, not semantic
query words. Full reconstructed decoded HTTP is scanned in small pages, excluding
failed/abandoned captures. `evidence <behavior_id>` pages supporting observations;
optional `--signal content|schema` selects positive comparisons. Source metadata
includes up to five counterpart IDs and the total match count for each signal.

`endpoint`, graph, metadata listings, identifiers and evidence do not call the
embedding backend. `similar` uses an existing vector. Full URLs constrain scheme,
host, and port. Endpoint reports include origin-specific auth models (an array),
entity links, behavior examples,
variants, and a bounded raw preview. `--no-raw` omits the preview. Raw size fields
are character counts; body/header omissions and stored-preview truncation are
separately labeled.

## Interpret observations carefully

- Credential presence is not successful authentication. `credential_present` and
  `auth_state` are explicit; `authenticated`/`authenticated_ever` remain legacy
  names for recognized credential presence.
- `--anon` means no recognized credential. On route nodes, decoded data must also
  have been observed. Public data alone is not a vulnerability.
- `anon_matches_auth` compares full response-body hashes at the same URL and
  request-body hash with credential-bearing traffic. It does not confirm that
  those credentials were accepted. `anon_schema_matches_credentialed` is weaker.
- Undecodable responses have an unknown access outcome.
- CORS `matches-origin` records one equality observation, not arbitrary origin
  reflection. `--cors-open` selects wildcard/null observations.
- Entity links represent common shapes. Equal identifier values are leads to
  inspect, not proof of identical records across services or accounts.
- Identifier extraction is bounded/sampled; a missing hit is not proof of absence.

Structural searches should describe protocol signals. Vulnerability jargon is
removed with explicit `rejected_terms` and `screening_action` fields. The `attacks`
collection is exempt: it records vulnerability classes supplied during testing.

## Findings

```bash
~/.config/opencode/skills/jeb-query/scripts/jeb-query.sh record-attack \
  --vuln-class SQLi --endpoint https://app.example/api/search --method GET \
  --param q --payload "'" --status 500 --verdict inconclusive \
  --source-id <behavior-id> --evidence "Database error in response" \
  --request-file req.txt --response-file resp.txt
```

Required: `--vuln-class`, absolute `--endpoint` URL. Verdicts: `vulnerable`,
`not_vulnerable`, `inconclusive`. Include method and raw evidence. Findings have
unique event IDs. Optional `--event-id <caller-key>` makes retries idempotent;
different inputs with the same key are rejected. A saved finding whose identifier
write fails still returns its ID with `identifier_state: pending`; project rebuild
repairs it. `attacks` sorts newest-first before pagination. Rebuilds preserve finding
IDs and structured inputs. Legacy free-form evidence remains readable and can be
marked `legacy-unstructured` when automatic identifier repair is unavailable.

Every successful command returns one JSON object with `command`, `count`, and
`next`. Follow-up hints are quoted executable shell commands with the selected
database preserved, not plugin tool calls. Fill any explicit `<placeholder>`
before execution. Operational errors return JSON `error` and a nonzero exit status. Missing
evidence must not be inferred from a failed query. If a profile mismatch is
reported, preserve the database and run `process_burp.sh rebuild [project_dir]`.

## Searching page content

Route nodes carry protocol facts, not response bodies. To find a form, heading,
table, hydration payload, or visible text use `search "words" --node-type behavior`
or section/form nodes. JavaScript bundles contribute extracted endpoint/library/
credential-shape facts and source-map/module relationships, not arbitrary text
chunks. Client-named routes with `observed=false` are leads, not captured endpoints.

The Gemma-2 distance cutoff is calibrated only for that model. Qwen and Gemini
default to no cutoff; do not apply Gemma thresholds to another model. Distilled
text is sent to the selected remote backend for semantic search and finding
recording. Confirm authorized remote processing through `jeb-import` first.
