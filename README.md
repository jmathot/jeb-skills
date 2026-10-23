# J.E.B.E.D.I.A.H.

John's Extension for Burpsuite Export Data Ingestion And Handling: standalone
**OpenCode skills** for investigating Burp Suite XML captures with a local,
Chroma-only knowledge graph and selectable embeddings.

This branch is a skills collection, **not a plugin**. It needs no npm packages,
TypeScript build, native `jeb_*` tools, or plugin registration. The separate
`plugin` branch provides that packaging. Engagement captures and databases belong
in separate project directories, never in this repository.

## Install

Requirements: Python 3.10+ with venv/pip, OpenCode V2 for skills and provider reuse,
and a configured embedding backend.

```bash
bash install-skills.sh
bash ~/.config/opencode/skills/jeb-import/scripts/setup.sh --viz
```

The installer copies `jeb-import`, `jeb-query`, and the primary
`J.E.B.E.D.I.A.H.` agent into the OpenCode configuration directory. Select the
agent in OpenCode, or use either skill from another agent. Supporting commands are
resolved relative to each skill's installed base directory.

- Honors `OPENCODE_CONFIG_DIR`, then `${XDG_CONFIG_HOME:-$HOME/.config}/opencode`.
- Preserves OpenCode JSONC/configuration, installed environments, local files,
  unrelated plugins, and engagement databases.
- Preflights conflicts. `--force` backs up conflicting files instead of deleting them.
- Tracks installed file hashes so repeat installs update unchanged managed files
  but refuse to overwrite local edits without `--force`.
- Refuses symlink destinations rather than modifying another checkout indirectly.
- Setup is explicit, uses an OS-released lock and dependency readiness stamps,
  and retries after failures. `--viz` adds plotting dependencies.
- Neither installation nor setup downloads models or issues embedding requests.

For an existing installation without a file manifest, changed files count as
conflicts: inspect them, then use `bash install-skills.sh --force` to retain backups.
Legacy `agents/jebediah.md` is also backed up only with `--force` to avoid duplicate
agent definitions. Existing plugin installations are not automatically removed;
disable their registration separately if you only want the skills interface.

## Import using your OpenCode LiteLLM provider

No JEB settings file or environment-variable exports are required:

```bash
bash ~/.config/opencode/skills/jeb-import/scripts/process_burp.sh import \
  capture.xml /path/to/engagement \
  --embedding-provider litellm \
  --embedding-preset litellm-qwen3-embedding-8b \
  --embedding-model qwen/qwen3-embedding-8b \
  --embedding-revision YOUR-PINNED-DEPLOYMENT-REVISION
```

Run from the intended OpenCode project/configuration scope. `--embedding-provider`
names an existing provider; `--embedding-model` is its gateway alias, not necessarily
the upstream model ID. The Python launcher captures `opencode api` responses
privately and uses resolved endpoint settings, headers, and API-key credentials.
It never dumps provider/credential responses into the conversation.

Non-secret selections are saved in the existing Chroma `captures` metadata.
Later imports and queries inherit them. Provider-resolved endpoints, headers,
and secrets stay in memory and are not copied into Chroma or command arguments.
An endpoint/server URL explicitly supplied through a switch is a non-secret saved
selection; URLs containing credentials or query strings are rejected. There is no
JEB settings file, and skills neither read nor write `JEB_*` environment settings.

Provider authentication headers (including `X-API-Key`) and intentionally keyless
endpoints are supported. When a stored integration credential is needed, the
resolver uses the provider's integration ID and active API-key credential. OpenCode's current
public credential-list API returns **all stored secret values**; the launcher keeps
that response in process memory and selects only the matching active key. Missing
or ambiguous connections fail closed. OAuth/external credentials are not forwarded.
Public APIs are version-sensitive: connection errors require checking the provider
in OpenCode, not reading private credential files.

**Remote processing disclosure:** distilled capture text goes to the selected
LiteLLM gateway and its upstream. Obtain appropriate authorization and review
logging/retention. Standalone scripts use normal OpenCode shell permissions; they
cannot enforce the plugin's custom remote-embedding permission hook. Do not assume
an `edit` rule independently blocks database writes performed inside an allowed shell.

## Embedding switches

Use these on `import` or `rebuild`; omitted switches inherit project settings:

| Switch | Meaning |
|---|---|
| `--embedding-provider ID` | Reuse the selected OpenCode provider connection |
| `--embedding-preset NAME` | Model family, transport, and prompt scheme |
| `--embedding-model ALIAS` | Gateway alias or local Ollama tag |
| `--embedding-revision REVISION` | Required pinned LiteLLM deployment revision |
| `--embedding-dimensions N` | Exact requested/output dimensions |
| `--embedding-context-tokens N` | Lower the deployment's input budget |
| `--embedding-timeout SECONDS` | Positive HTTP timeout, default 120 |
| `--embedding-send-dimensions` / `--no-embedding-send-dimensions` | Include/omit LiteLLM's API dimension parameter |
| `--embedding-base-url URL` | Explicit endpoint; otherwise use the provider or local Ollama default |
| `--embedding-keep-alive DURATION` | Ollama residency duration, default `30m` |
| `--opencode-server URL` | Explicit OpenCode server for private/remote session provider lookup |
| `--embed-batch-docs N` / `--embed-batch-chars N` | Per-request batch limits, default 32 / 48000 |
| `--embed-workers N` | Concurrent embedding workers, default 2 |
| `--candidate-ceiling N` | Retrieval expansion ceiling, default 1000 |
| `--max-distance-graph VALUE` / `--max-distance-attacks VALUE` | Cosine cutoff in [0, 2], or `none` |
| `--depth-<quick\|normal\|deep>-<field> N` | Override one depth budget; fields below |

Depth fields: `candidate-k`, `n-results`, `max-per-endpoint`, `snippet-len`,
`raw-chars`. For example, `--depth-deep-candidate-k 200 --depth-normal-raw-chars 4000`.
Counts must be positive; snippet/raw character budgets may be zero. Runtime budget,
connection, and timeout changes do not require new vectors. `rebuild` still forces
derived rebuilding when explicitly requested.

Use `--no-embedding-provider`, `--no-embedding-base-url`, or `--no-opencode-server`
to clear a saved override. Query, status, export, and visualization also accept
`--opencode-server` / `--no-opencode-server` for an execution-only server override.
Authentication uses the OpenCode CLI's existing authentication context, never a JEB
password/key argument. Without a server switch, normal OpenCode service discovery
applies. An explicit base URL without a provider is suitable only for a keyless
endpoint; configure authenticated endpoints in OpenCode and select their provider.

| Preset | Native dimensions | Context budget | Formatting |
|---|---:|---:|---|
| `ollama-embeddinggemma2` | 768 | 8192 | Titled documents; `task: search result` queries |
| `litellm-gemini-embedding-2` | 3072 | 8192 | Same prefixes; no `task_type` parameter |
| `litellm-qwen3-embedding-8b` | 4096 | 32768 | English `Instruct:` / `Query:` for queries only |

New projects with no switches default to local Ollama at `localhost:11434` and
`embeddinggemma-2:latest`. Prepare the model manually with a compatible Ollama
release; old `embeddinggemma` is not equivalent. LiteLLM deployments must pin the
actual weights and disable cross-model fallbacks. JEB cannot detect an unreported
weight replacement behind an alias.

Selecting another preset resets inherited model/dimension/context/revision values.
Gemma supports 128/256/512/768 dimensions; Gemini 128–3072; Qwen 32–4096, subject to
endpoint support. Omitting the dimension parameter does not relax exact output
validation. Qwen serving must use correct last-token pooling and must not add a
second query instruction. Gemini must return one vector per input, not an aggregate.

The engine checks response cardinality/index order, finite nonzero exact-sized
vectors, L2 normalization, and conservative UTF-8 input budgets including prefixes.
No silent truncation, dimension slicing, redirect credential forwarding, or model
fallback. Models cannot be mixed even when their dimensions match.

Legacy `JEB_*` variables are ignored, including stale endpoint, key, header, model,
and tuning values. Replace them with the switches above. Prompt scheme is selected
by the preset and cosine distance is fixed, rather than exposed as environment
overrides. Connection secrets never define vector identity. Standard OS/OpenCode
variables used for installation, process lookup, or the CLI's own authentication
are not JEB engine configuration and remain under OpenCode/OS control.

## Investigate

```bash
bash ~/.config/opencode/skills/jeb-query/scripts/jeb-query.sh endpoint \
  https://app.example/api/orders/42 --project-dir /path/to/engagement
bash ~/.config/opencode/skills/jeb-query/scripts/jeb-query.sh search \
  "password reset email" --node-type behavior --project-dir /path/to/engagement
```

`--project-dir` selects `<project>/chroma_db`; alternatively use `--db-path`, not
both. Without either switch, commands use the current directory's `chroma_db`.

| Command | Purpose |
|---|---|
| `endpoint <path-or-url>` | First move for a named route: protocol facts, auth, related data, raw preview |
| `map --kind endpoint` / `map --kind auth_model` | Orient by route or session model |
| `search [text]` | Semantic discovery or exact metadata/substring filters |
| `graph <id> --direction both --hops 1` | Follow typed stored relationships, one or two hops |
| `get <id> [--original]` | Full document or source evidence, optional original base64 |
| `similar <id>` | Related documents using a stored vector |
| `identifier <value>` | Exact extracted value associations |
| `evidence <behavior-id> [--signal content\|schema]` | Paginated supporting observations |
| `attacks` / `record-attack` | Recall/record testing events with durable IDs and evidence |

Query responses are JSON with bounded previews, pagination/consistency diagnostics,
and quoted executable follow-up commands retaining the selected database. Fill any
explicit placeholders before executing. Operational failures return JSON errors
and nonzero status. Maintenance commands also print progress; `status` prints JSON.

Use `--in graph|attacks` for semantic scope; `--in exchanges --contains TEXT` scans
full decoded source HTTP without embedding. `--node-type` narrows graph searches.
Route nodes index protocol facts; behavior/section/form nodes carry page content.
Search observed signals, not vulnerability names. Distances indicate similarity,
not security impact. Gemma's calibrated 0.38 cutoff is not applied to Qwen/Gemini.
Configure custom retrieval and batching defaults with the import/rebuild switches
above; queries inherit those validated settings from the project automatically.

## Design and evidence

Six Chroma collections, no auxiliary SQL/FTS database, lexical search, BM25, or RRF:

| Collection | Contents |
|---|---|
| `graph` (embedded) | `origin`, `route`, `behavior`, `data_object`, `posture`, `section`, `form` nodes with one-hop context headers |
| `attacks` (embedded) | Durable testing events, supplied verdicts, and evidence |
| `captures` (lookup) | Source digests, import/index state, analysis and embedding selections |
| `exchanges` (lookup) | Full decoded and original base64 HTTP, capture provenance |
| `identifiers` (lookup) | Exact value/field/source associations |
| `edges` (lookup) | Typed relationships: `HAS_BEHAVIOR`, `RETURNS`, `CONTAINS`, `SUBMITS_TO`, `CALLS`, and more |

The graph includes bounded DOM-based sections, forms, hydration text/records,
JavaScript endpoint/library/credential-shape facts, module/source-map associations,
and external origins. Client-named stub routes are explicitly `observed=false`.
They are leads, not captured endpoints. High-cardinality and one-time values are
suppressed in embeddings; original evidence remains retained.

Imports are cumulative, streaming, writer-locked, and rebuildable from retained
observations. Compact features, on-demand body hydration, lookup batching, and
unchanged-vector reuse reduce memory/model cost. Status exposes the loss ledger
for derived summaries. Credential presence is not successful authentication; equal
identifiers or response shapes do not establish an authorization failure.

## Maintenance and migration

```bash
bash ~/.config/opencode/skills/jeb-import/scripts/process_burp.sh status /path/to/engagement
bash ~/.config/opencode/skills/jeb-import/scripts/process_burp.sh rebuild /path/to/engagement
bash ~/.config/opencode/skills/jeb-import/scripts/process_burp.sh export /path/to/engagement \
  --collection graph --output /path/to/graph.ndjson
bash ~/.config/opencode/skills/jeb-import/scripts/visualize.sh \
  --project-dir /path/to/engagement --mode graph --out /path/to/site-map.html
```

Export requires an unused destination. Visualization supports `graph` and
`embedding` modes without provider requests. Omitted import analysis settings
inherit; `--auth-cookies`, auth-cookie detection switches, and `--rebuild` retain
their previous behavior. `abandon <capture-id> [project]` excludes interrupted
captures without deleting evidence; rebuild afterward.

**Upgrade from earlier main:** back up the database, install the updated skills,
and rebuild with the desired embedding switches. Old `structure`/`behavior`
collections are replaced by the typed graph. Source observations, original capture
membership, structured findings, and finding IDs survive. Legacy summaries lacking
observations require original-source reimport. Never delete evidence to repair a
profile mismatch. Failed migrations retain state for recovery; inspect `status`
and rerun rebuild. Pending finding migration blocks finding writes until completed.

See [testing](docs/testing.md) for offline checks, opt-in Qwen benchmarks,
isolated host verification, and remaining live-validation gaps.
