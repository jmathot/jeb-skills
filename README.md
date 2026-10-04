# J.E.B.E.D.I.A.H.

John's Extension for Burpsuite Export Data Ingestion And Handling: a local,
Chroma-only RAG system for investigating Burp Suite XML captures.

This repository is an **OpenCode v2 plugin**. It bundles a Python engine (Chroma
vector store + Ollama EmbeddingGemma embeddings) and exposes it as native `jeb`
tools, plus the **J.E.B.E.D.I.A.H.** primary agent. Engagement captures and
databases live in a separate project directory, never in this repo.

## Design

- **Semantic discovery:** Ollama EmbeddingGemma vectors, explicit cosine distance,
  protocol-aware route/response/session segments, and canonical-parent results.
- **Exact queries:** Chroma metadata filtering, literal document substring filters,
  and identifier equality lookup. No application-managed SQLite sidecar, FTS5,
  BM25, reciprocal-rank fusion, or lexical index.
- **Cumulative imports:** captures and source observations remain in Chroma;
  structure and behavior summaries are derived across retained captures.
- **Evidence:** bounded reconstructed previews for browsing; full decoded text and
  original HTTP bytes (base64) retained in source observations.
- **Findings:** durable attack events with unique IDs and newest-first listing.
  Rebuilding derived indexes preserves finding evidence and IDs.
- **Origin-aware navigation:** scheme, hostname, port, method, and route template
  distinguish endpoints; entity links retain origin-qualified routes.

### Chroma collections

| Collection | Records |
|---|---|
| `structure` | Endpoint, auth-model, entity summaries and semantic segments |
| `behavior` | Canonical behavior summaries, segments, and raw variants |
| `attacks` | Recorded testing events and evidence |
| `captures` | Source digest, configuration, processing version, import state |
| `exchanges` | Capture-scoped observations, source item position, full evidence |
| `identifiers` | Exact value/field/source-document associations |

The three lookup collections use fixed one-dimensional vectors and metadata
lookups; they never call Ollama. Chroma may use SQLite internally; this
application only manages Chroma collections and APIs.

## Install

Requirements: Python 3.10+, and Ollama 0.11.10+ with `embeddinggemma:latest`
pulled.

Run the install script, which symlinks the plugin and agent into OpenCode's
config directory (so the agent works in any engagement project) and pulls the
embedding model:

```bash
./install.sh
```

Options: `--copy` to copy instead of symlink, `--force` to replace an existing
entry, and `OPENCODE_CONFIG_DIR=...` to override the config location (default
`${XDG_CONFIG_HOME:-$HOME/.config}/opencode`). The equivalent manual steps:

```bash
ln -s "$(pwd)" ~/.config/opencode/plugins/jebediah
ln -s "$(pwd)/agents/jebediah.md" ~/.config/opencode/agents/jebediah.md
ollama pull embeddinggemma:latest
```

On first load the plugin **auto-bootstraps** the Python engine: it creates
`engine/.venv`, installs `engine/requirements.txt` + `engine/requirements-viz.txt`,
and warns (without failing) if Ollama or the embedding model is missing. The
bootstrap is idempotent — later loads are a no-op unless the requirement files
change. Restart OpenCode after linking; select **J.E.B.E.D.I.A.H.** with Tab.

The agent (`agents/jebediah.md`) is a separate OpenCode agent definition because a
plugin cannot create a primary agent; the plugin registers the tools it uses.

## Configuration

Set RAG hyperparameters as plugin `options` in `opencode.json(c)` (see
`opencode.jsonc` for a full example). Two tiers:

**Query-time — safe to change anytime:**

| Option | Effect |
|---|---|
| `maxDistance.{structure,behavior,attacks}` | Per-collection cosine distance cutoff (0–2). |
| `candidateCeiling` | Upper bound on adaptive candidate expansion. |
| `depth.{quick,normal,deep}.{candidateK,nResults,maxPerEndpoint,snippetLen,rawChars}` | Retrieval budget presets. |
| `ollamaTimeoutSeconds` | Embedding request timeout. |
| `embedBatchDocs` / `embedBatchChars` | Documents and characters per embedding request (default 32 / 48000). Tuning lever only — EmbeddingGemma throughput is per-document, so larger batches gain little. |

Semantic retrieval matches on the distilled `embed_text`, which spells protocol
facts in searchable words (`cors: wildcard, access-control-allow-origin * allows
any origin` rather than `cors: *`); `page_content` and `summary` keep the compact
operator shorthand. **An existing project built before this expansion needs
`jeb_import command=rebuild`** to benefit — findings and capture evidence are
preserved, and only documents whose text changed are re-embedded.

**Index-defining — changing any of these requires a rebuild** (`jeb import`
`command=rebuild`), because they change the recorded embedding profile and the
engine refuses queries against a mismatched database:

| Option | Default |
|---|---|
| `embeddingModel` | `embeddinggemma:latest` |
| `embeddingDimensions` | `768` |
| `embeddingScheme` | `embeddinggemma-v5-titled-768d` |
| `distanceMetric` | `cosine` |
| `ollamaUrl` | `http://localhost:11434/api/embeddings` |

The plugin warns on load when an index-defining option changed since last run.
Options are passed to the engine as `JEB_*` environment variables; omitted options
keep the engine defaults.

## Tools

All tools run against the current project directory (or pass `db_path` /
`project_dir`). Each returns one JSON object.

### `jeb_import`

Build or maintain a project's `chroma_db/`. Set `command`:

| command | arguments | notes |
|---|---|---|
| `import` | `xml_file`, `project_dir?`, `auth_cookies?`, `auto_detect?`, `rebuild?` | Streams Burp XML directly into Chroma; omitted options inherit saved project settings. |
| `rebuild` | `project_dir?` | Rebuild derived indexes from retained observations (no XML). Preserves finding IDs. |
| `status` | `project_dir?` | Report capture states and index state; run after an error. |
| `abandon` | `capture_id`, `project_dir?` | Exclude a failed/interrupted capture (evidence retained); rebuild afterward. |
| `export` | `project_dir?`, `collection`, `output` | Write one collection as NDJSON to a path that must not exist. |

### `jeb_query`

Investigate the capture. Set `command`:

| command | key arguments |
|---|---|
| `endpoint` | `target` (path or full URL) — the first move for any named route |
| `map` | `kind` (endpoint/auth_model/entity), `limit`, `offset` |
| `search` | `text` and/or filters; `collection` (`--in`), `depth`, `loose` |
| `get` | `target` (document/exchange id); `original` for raw base64 |
| `similar` | `target` (semantic document id) |
| `identifier` | `target` (exact value); `offset`, `limit` |
| `evidence` | `target` (behavior id); `signal` (content/schema) |
| `attacks` | list findings; `vuln_class`, `verdict`, `severity` |
| `record-attack` | `vuln_class`, `endpoint` (required); `method`, `param`, `payload`, `status`, `verdict`, `evidence`, `request`/`response`, `event_id` |

Filters accepted by `map`/`search`/`attacks`: `host`, `path`, `method[]`,
`status` (e.g. `>=500`), `param[]`, `cookie[]`, `missing_header[]`, `kind`,
`access_control`, `access_class`, `contains`, `anon`, `auth`, `cors_open`,
`include_static`, `anon_matches_auth`, `cookie_issues`, `jwt`.

Semantic search returns cosine `distance` (lower is closer, not a confidence
score), `matched_ids`, representations, and matching variants. `collection=exchanges`
with `contains` scans full decoded source HTTP. Structural collections hold
protocol facts only — search the structural signal, not the vulnerability name;
vulnerability jargon is stripped with explicit `rejected_terms`. Vulnerability
classes live only in `attacks` (via `record-attack`).

### `jeb_visualize`

Render an interactive HTML view: `mode` (`graph` = site map, `embedding`), `out`
(file path), optional `sample` (embedding mode), `db_path`.

## Interpreting access signals

Credential presence is not successful authentication; `credential_present` and
`auth_state` expose that distinction. `anon` means no recognized credential;
public data is not automatically a vulnerability. `anon_matches_auth` compares
full response hashes at the same URL and request body against credential-bearing
requests; the schema-match flag is weaker. Neither proves authorization failure.
CORS `matches-origin` records one equality observation, not arbitrary reflection.
Equal identifier values are correlation leads, not proof of shared records.

Check `incomplete_captures`, `index_state`, and `notes` before interpreting empty
or partial results. Never delete the database to repair a schema mismatch; rebuild
with `jeb_import command=rebuild` while retaining findings.

## Layout

```
src/            TypeScript plugin (Plugin.define → tools + agent sync + bootstrap)
agents/         J.E.B.E.D.I.A.H. agent definition
engine/import/  Python import/maintenance CLI (import_project.py + modules)
engine/query/   Python query CLI (agent_interface.py + modules)
engine/.venv/   auto-created on first load
```

## Testing

`tests/` holds a benchmark suite built on one committed Burp export. The capture
is generated, so its ground truth is known without running the engine:
`tests/make_capture.py` writes both `tests/capture.xml` (296 items, single
origin) and `tests/ground_truth.json` (routes, entities, identifiers, keyword
needles, and a graded semantic query set).

```bash
./tests/run.sh                    # all tiers against the cached import
./tests/run.sh --tier a           # one tier; repeatable
./tests/run.sh --fresh            # re-import first (see the caveat below)
./tests/run.sh --update-baseline  # re-record tier B metrics and tier C digests
```

| Tier | Measures | Fails on |
|---|---|---|
| **A** `bench_correctness.py` | Route set, node kinds, access-control classification, entity grouping and fuzzy `related` scores, auth model, identifier lookups, evidence round trip, findings, `next` hints against the schemas in `src/tools.ts` | any changed derived fact |
| **B** `bench_retrieval.py` | Recall@k, MRR, nDCG@k and precision over the graded query set at two depths; keyword `contains` against an independent decoder; vulnerability-jargon screening | a metric below its committed floor, oracle disagreement, or a screening change |
| **C** `bench_perf.py` | Phase timings, Chroma/Ollama/HTML-parse call counts, query latency percentiles against the process floor, peak RSS, `build_entities` scaling curve, and the bit-identical export gate | only the bit-identical gate; timings are reported, never gated |

The import is cached in `tests/.work/<capture-sha>/`, so tiers A and B reuse one
database and only tier C pays for a cold import.

**Changing the ingest path needs `--fresh`.** Feature extraction results are
persisted per observation as `_features` and a rebuild reuses them while
`FEATURE_VERSION` is unchanged, so edits to `parse.py` or to the feature
extraction in `distill.py` / `normalize.py` / `streaming.py` are invisible to a
rebuild-only run.

Every response carries a `next` list of follow-up calls in tool shorthand
(`jeb query command=get target=<id>`), produced by `engine/query/hints.py` — the
single formatter for those hints, so they cannot drift from the tool contract.
Tier A checks each hint against the tool schemas, which is what keeps them honest.
