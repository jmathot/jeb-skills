# Retrieval details and filter values

## Semantic search

- Search uses the project's selected embedding backend and Chroma cosine distance, and
  nothing else: no lexical search, BM25, RRF, `top_p` or confidence score.
- Lower `distance` is closer. It does not establish relevance or security impact.
- Results resolve segments and variants to their canonical parent, and include the IDs
  and representations that matched.

| `--depth` | Candidates | Max results | Raw preview chars | Neighbours per result | Endpoint variants |
|---|---:|---:|---:|---:|---:|
| quick | 20 | 5 | 0 | 0 | 0 |
| normal (default) | 40 | 8 | 2,000 | 3 | 3 |
| deep | 120 | 25 | 8,000 | 6 | 48 |

`--limit N` overrides the result count. Projects may override these defaults
through jeb-import. A truncated list reports its full size (`neighbors_total`,
`variants_total`).

## Result views

- The default brief view keeps every key an agent acts on, in a fixed order (`id`,
  `node_type`, `node_kind`, `method`, `host`, `endpoint_template`, status, `distance`,
  `summary`, then the rest alphabetically).
- It leaves out internal or redundant keys (`doc_kind`, `route_kind`, `path_depth`,
  `param_count`, legacy `authenticated`, digests, `capture_id`), the defaults
  `scheme=https`, `port=443` and `observed=true`, and empty values.
- False flags are left out, so a missing flag means false. The exceptions are
  `anon_allowed`, `complete` and `credential_present`, which are always shown.
- `--full` shows every stored field. `get` always shows the full record. `--pretty`
  indents the JSON.

**Cutoff and candidates**
- `--loose` disables the distance cutoff.
- An empty result can carry `fallback` matches with the cutoff disabled. Metadata and
  content constraints still apply to them.
- Candidates expand adaptively, up to the candidate ceiling (1,000 by default), when
  filtering leaves too few eligible parents.
- `candidate_limit_reached` warns that candidate selection may have limited recall.
- Diagnostics report the final candidate budget and the post-filter rejections.

The Gemma-2 cutoff is calibrated only for that model. Qwen and Gemini have no
default cutoff.

## Listings and completeness

- `map`, `attacks` and filter-only `search` page through the whole collection and
  return `total`, `complete`, `offset` and `has_more`.
- Use `--offset` only without search text.
- `complete` describes the enumeration only, not capture coverage. Always check
  `incomplete_captures`, `index_state` and `notes`.

## Filter values

| Flag | Values / meaning | Applies to |
|---|---|---|
| `--node-type` | `route`, `behavior`, `origin`, `data_object`, `posture`, `section`, `form` | graph |
| `--kind` | route: `page` (GET HTML), `action` (POST/PUT/PATCH/DELETE), `endpoint`; others: `origin`/`auth_model` (origin nodes), `entity` (data objects), `posture`, `section`, `form` | graph |
| `--access-control` | `open-data`, `soft-auth-wall`, `enforced`, `unknown` | route nodes |
| `--access-class` | `data`, `denied`, `auth_wall`, `redirect`, `static`, `shell`, `empty`, `unknown`, `other` | behavior nodes |
| `--missing-header` | `csp`, `hsts`, `xfo`, `xcto`, `referrer-policy`, `permissions-policy` | graph |
| `--status` | `500`, `>=500`, `500-599`, `5xx` | graph, attacks |
| `--method`, `--param`, `--cookie` | repeatable; cookie names match exactly, including case | graph (method also attacks/exchanges) |
| `--anon` / `--auth` | no recognized credential / credential present | graph |
| `--anon-matches-auth`, `--cors-open`, `--cookie-issues`, `--jwt` | boolean facets | graph |
| `--vuln-class`, `--verdict`, `--severity` | finding fields | attacks |
| `--host` | exact host | `map`, `search`, `similar`, `attacks`, `endpoint` |
| `--path` | path, or a full URL, matched by origin and template | `map`, `search`, `similar`, `attacks` (`endpoint` takes the path as its target) |

- Collection-incompatible facets are rejected with an error.
- Static assets are excluded unless `--include-static` is given.
- `graph --rel` takes a relation name, e.g. `HAS_ROUTE`, `HAS_BEHAVIOR`, `RETURNS`,
  `ACCEPTS`, `CONTAINS`, `SUBMITS_TO`, `CALLS`, `LINKS_TO`, `TARGETS`. `--hops` is 1 or 2.

## Literal text and source exchanges

- `--contains` is case-sensitive, and searches the canonical and variant previews, not
  every original byte. Reconstructed header names are lowercase.
- For text beyond the previews, scan the full decoded source exchanges, using exact
  filters only (no query words):

  ```bash
  jeb search --project-dir DIR --in exchanges --host app.example --contains "SQLSyntaxError"
  ```

  This skips failed and abandoned captures.
- `get <exchange_id>` returns the decoded HTTP, capture ID, source position and
  comparison references. Add `--original` for the original base64.
- `evidence <behavior_id> [--signal content|schema]` pages the supporting
  observations. Each one lists up to five counterpart IDs per signal, plus the total.

## Endpoint reports

- `endpoint` never calls the embedding backend, and neither do `map`, `graph`,
  `identifier`, `evidence` or filter-only listings. `similar` reuses a stored vector.
- A full URL constrains scheme, host and port.
- Reports include, per origin:
  - auth models (an array), entity links (`related_by_entity`) and neighbours;
  - behavior examples with `req_features`, `access_class` and `redirect_location`;
  - variants, and a bounded raw request/response.
- `--no-raw` omits the raw preview, and `--raw-chars N` sizes it. Size fields count
  characters, and omissions and truncation are labelled separately.

## Findings

- `record-attack` requires `--vuln-class` and an absolute `--endpoint` URL. Verdicts:
  `vulnerable`, `not_vulnerable`, `inconclusive` (the default).
- Optional fields: `--method`, `--param`, `--payload`, `--status`, `--severity`,
  `--source-id`, `--evidence`, `--tool`, `--request[-file]`, `--response[-file]`.
- `--event-id KEY` makes retries idempotent. Reusing a key with different inputs is
  rejected.
- If the identifier write fails, the finding is still saved and reported with
  `identifier_state: pending`; a project rebuild repairs it.
- `attacks` lists newest first. Rebuilds keep finding IDs.

Recording a finding embeds its summary, so it is sent to the selected backend.
