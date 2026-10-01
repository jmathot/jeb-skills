# J.E.B.E.D.I.A.H.

John's Extension for Burpsuite Export Data Ingestion And Handling: a local,
Chroma-only RAG system for investigating Burp Suite XML captures.

This repository contains the OpenCode skills, agent definition, and supporting
scripts. Engagement captures and databases belong in a separate project directory.

## Design

- **Semantic discovery:** Ollama EmbeddingGemma vectors, explicit cosine distance,
  protocol-aware route/response/session segments, and canonical-parent results.
- **Exact queries:** Chroma metadata filtering, literal document substring filters,
  and identifier equality lookup. No application-managed SQLite sidecar, FTS5,
  BM25, reciprocal-rank fusion, or lexical index.
- **Cumulative imports:** captures and source observations remain in Chroma;
  structure and behavior summaries are derived across retained captures.
- **Evidence:** bounded reconstructed previews for browsing; full decoded text and
  original HTTP bytes (base64) retained in source observations. Identifier hits
  link directly to source evidence, including values absent from a preview.
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
lookups; they never call Ollama for embeddings. Chroma may itself use SQLite
internally; this application only manages Chroma collections and APIs.

## Install

Requirements: Python 3.10+, Ollama 0.11.10+ with `embeddinggemma:latest` pulled.
Dependency versions remain in `jeb-import/scripts/requirements.txt`; validate the
chosen dependency set in your deployment environment before pinning it.

```bash
./install-skills.sh
python3 -m venv ~/.config/opencode/skills/jeb-import/scripts/venv
~/.config/opencode/skills/jeb-import/scripts/venv/bin/pip install \
  -r ~/.config/opencode/skills/jeb-import/scripts/requirements.txt
ollama pull embeddinggemma:latest
```

Installation updates source files while preserving the installed virtual
environment. Restart OpenCode after installing updated skills or the agent.
Select **J.E.B.E.D.I.A.H.** with Tab.

## Import

```bash
~/.config/opencode/skills/jeb-import/scripts/process_burp.sh capture.xml /path/to/project
```

Optional flags:

- `--auth-cookies NAME[,NAME...]` — additional recognized credential cookies.
- `--no-auto-detect-auth-cookies` — disable origin-scoped login-cookie learning.
- `--rebuild` — rebuild incompatible derived collections and migrate finding
  embeddings through a temporary Chroma evidence backup.
- `--auto-detect-auth-cookies` — explicitly enable login-cookie learning.

Omitted configuration flags inherit saved project settings. Explicit cookie flags
replace the project's custom names (`--auth-cookies ''` clears them). Original
capture-import configuration remains intact. Retained captures skip parsing when
the parser version is current; current project indexes skip analysis.

### Streaming operations

```bash
~/.config/opencode/skills/jeb-import/scripts/process_burp.sh import capture.xml /path/to/project
~/.config/opencode/skills/jeb-import/scripts/process_burp.sh rebuild /path/to/project
~/.config/opencode/skills/jeb-import/scripts/process_burp.sh status /path/to/project
~/.config/opencode/skills/jeb-import/scripts/process_burp.sh abandon <failed_capture_id> /path/to/project
```

Normal import persists only Chroma data and its writer lock. No intermediate JSON
files are written in the cwd or temporary directories. XML parsing and storage
use small in-memory batches. Global analysis retains compact features and fetches
full HTTP one observation at a time; derived documents are emitted sequentially in
bounded embedding batches. Memory scales with compact features and the largest
individual exchange, not all retained raw bodies at once.

`rebuild` uses retained Chroma observations without XML. Failed/interrupted captures
are excluded until resumed; `abandon` retains their source evidence but explicitly
excludes them. Rebuild afterward. The legacy `capture.xml [project_dir]` wrapper
invocation continues to work.

Diagnostic export requires an explicit destination that does not already exist:

```bash
~/.config/opencode/skills/jeb-import/scripts/process_burp.sh export /path/to/project \
  --collection behavior --output /path/to/behavior.ndjson
```

The standalone parser/builders require `--output`; they are not normal import
stages. Reinstall updated definitions if an older installed wrapper still produces
parsed/annotated JSON files. Existing files are left untouched.

Observations have stable `(capture digest, source item index)` identities. For
aggregate counts, equal full parsed exchanges with equal timestamps are matched
across captures by occurrence ordinal. Repeats within one capture remain distinct;
observations without timestamps are retained independently. Coarse timestamps can
still make overlap ambiguous; raw capture membership remains available.

An OS-released lock permits one writer. Capture states are `parsing`, `ready`,
`failed`, and `abandoned`; project index state is separate. Queries report failed
captures and incomplete indexes because cross-collection updates are not atomic.

Unchanged embedding input reuses its existing vector even if metadata or evidence
changes. A bounded process-local cache reuses identical new inputs. The resolved
local model digest is recorded and checked; changing a model behind `latest`
requires rebuilding. Identifier extraction is versioned and incremental.

### Existing-project transition

Keep the original database and all source exports. Run the original captures
through `process_burp.sh --rebuild` to populate observation-backed storage.
Old derived records absent from retained observations are reconciled away;
reimport every capture whose history you want retained. Recorded attacks are
preserved, including their IDs. Original origins cannot be recovered reliably
from every legacy finding and may need manual correction.

An interrupted finding migration retains `attacks_rebuild_backup` inside Chroma;
resume with `rebuild`. Do not delete it or the database during migration.

`jeb_lexical.sqlite` is no longer read or written. It is deliberately left on
disk for external migration verification. Old intermediate JSON is likewise
left intact. The import scripts do not infer missing historical exchanges from
collapsed representative documents.

## Query

Run from the engagement project directory, or pass `--db-path /path/to/chroma_db`.

```bash
JQ=~/.config/opencode/skills/jeb-query/scripts/jeb-query.sh
"$JQ" endpoint https://app.example:8443/api/orders/42
"$JQ" map --limit 50 --offset 0
"$JQ" search "password reset email" --method POST
"$JQ" search --status '>=500' --param q
"$JQ" search --contains "access-control-allow-origin: *"
"$JQ" identifier 42 --limit 50 --offset 0
"$JQ" get <exchange-or-document-id>
"$JQ" get <exchange-id> --original
"$JQ" evidence <behavior-id> --signal content --limit 50 --offset 0
"$JQ" search --in exchanges --host app.example --contains "SQLSyntaxError"
"$JQ" similar <semantic-document-id>
```

Semantic search returns cosine `distance` (lower is closer), `matched_ids`,
representations, and matching variants. It does not return a confidence score.
Depth controls candidate/result/evidence budgets; `--loose` disables the distance
cutoff. Empty results may include closest eligible `fallback` candidates.
Candidates adaptively expand up to 1,000 when filtering leaves too few eligible
parents. Candidate limits can affect recall; exact metadata listings scan all pages and
return `total`, `complete`, `offset`, and `has_more`.

`--contains` searches canonical/variant previews by default. `--in exchanges`
searches full reconstructed decoded source HTTP, excluding failed/abandoned captures.
Use `get <exchange_id>` for full evidence; original base64 requires `--original`.
Reconstructed header names are lowercase; substring matching is case-sensitive.
Cookie-name filters use exact case-sensitive names. Collection-incompatible facets
are rejected. `evidence` pages source observations and comparison references instead
of duplicating unlimited evidence ID lists into semantic segments.

Vulnerability jargon in structural searches is removed with explicit
`rejected_terms`/`screening_action` output. Search protocol signals; use `attacks`
for recorded vulnerability classes.

```bash
"$JQ" record-attack --vuln-class SQLi --endpoint https://app.example/api/search \
  --method GET --param q --payload "'" --status 500 --verdict inconclusive \
  --evidence "Database error in response" --request-file req.txt --response-file resp.txt
"$JQ" attacks --vuln-class SQLi
```

Findings retain structured inputs. Optional `--event-id <caller-key>` makes retries
idempotent; different inputs with the same key are rejected. A saved finding whose
identifier indexing fails still returns its ID with `identifier_state: pending`.
Project rebuild repairs it. Legacy free-form findings remain readable and may be
marked `legacy-unstructured` when automatic identifier repair is unavailable.

### Interpreting access signals

Credential presence is not successful authentication. `credential_present` and
`auth_state` expose that distinction; legacy `authenticated` fields remain
credential-presence aliases. `--anon` means no recognized credential (`structure`
additionally requires observed decoded data). Public data is not automatically a
vulnerability. `anon_matches_auth` compares full response hashes at the same URL
and request-body hash against credential-bearing requests. The schema-match flag
is weaker. Neither proves authorization failure.

CORS `matches-origin` means one observed response matched the supplied Origin,
not that arbitrary reflection was established. Equal identifier values are
correlation leads, not proof of shared record identity across services.

## Visualize

Install `jeb-import/scripts/requirements-viz.txt` in the shared environment, then:

```bash
~/.config/opencode/skills/jeb-import/scripts/venv/bin/python \
  ~/.config/opencode/skills/jeb-import/scripts/visualize.py \
  --db-path ./chroma_db --mode graph --out site_map.html
```

Embedding mode supports `--sample N`; vectors are sampled before loading.
Sample diagnostics can omit parent/child counterparts and are labeled accordingly.
Lookup collections are excluded from semantic visualization.

## Verification

Runtime and retrieval evaluation are performed in the separate deployment
environment. No new test suite is supplied by this refactor. The pre-existing
`selftest.py` describes the previous interface and is retained as historical source;
its screening, raw-count, and error-contract assumptions need adapting externally.
