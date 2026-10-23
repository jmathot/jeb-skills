---
name: jeb-import
description: Import Burp XML into a cumulative Chroma knowledge graph, select embedding providers with command-line switches, rebuild or inspect status, export evidence, and visualize captures. Use for ingestion and maintenance; use jeb-query for investigation.
---

# J.E.B. — Capture Import and Maintenance

Run in the engagement project, separate from the skill repository. Examples show
the default installation; use this skill's actual base directory when different.

## Setup

Python 3.10+ is required. Explicitly prepare the shared environment once; `--viz`
also installs plotting dependencies. Setup never downloads or calls a model:

```bash
bash ~/.config/opencode/skills/jeb-import/scripts/setup.sh --viz
```

## Embedding selection (no settings file or shell exports)

```bash
bash ~/.config/opencode/skills/jeb-import/scripts/process_burp.sh import capture.xml /path/to/project \
  --embedding-provider litellm \
  --embedding-preset litellm-qwen3-embedding-8b \
  --embedding-model qwen/qwen3-embedding-8b \
  --embedding-revision YOUR-PINNED-DEPLOYMENT-REVISION
```

Non-secret selections are stored in the existing `captures` collection. Subsequent
imports and queries inherit them. LiteLLM requires a pinned deployment revision
and a gateway with cross-model fallback disabled. Gateway aliases alone do not
identify immutable weights.

| Preset | Default dimensions | Maximum context |
|---|---:|---:|
| `ollama-embeddinggemma2` | 768 | 8192 |
| `litellm-gemini-embedding-2` | 3072 | 8192 |
| `litellm-qwen3-embedding-8b` | 4096 | 32768 |

Without switches, new projects use local Ollama. Manually prepare
`embeddinggemma-2:latest`; old `embeddinggemma` is a different model.

Other switches on `import` and `rebuild`: `--embedding-dimensions N`,
`--embedding-context-tokens N`, `--embedding-timeout SECONDS`,
`--embedding-send-dimensions` / `--no-embedding-send-dimensions` (LiteLLM),
`--embedding-base-url URL`, `--embedding-keep-alive DURATION`, and
`--opencode-server URL` for private/remote OpenCode server lookup.
Selecting another preset resets inherited model-specific defaults. Use `rebuild`
with the new switches to migrate an existing database, never delete it.

Runtime budgets are also set through import/rebuild switches and inherited by
queries: `--embed-batch-docs N`, `--embed-batch-chars N`, `--embed-workers N`,
`--candidate-ceiling N`, `--max-distance-graph VALUE`, `--max-distance-attacks VALUE`.
Distance values are [0, 2] or `none`. Depth overrides use
`--depth-<quick|normal|deep>-<candidate-k|n-results|max-per-endpoint|snippet-len|raw-chars> N`.
Counts are positive; snippet/raw budgets may be zero. Runtime-only changes do not
invalidate vectors. Use `--no-embedding-provider`, `--no-embedding-base-url`, or
`--no-opencode-server` to clear a saved override. No legacy JEB environment setting
is read, including endpoint URLs, keys, headers, model selection, or tuning values.

The Python launcher privately resolves the selected OpenCode provider through
`opencode api`, in the invocation's configuration scope, only when needed for an
embedding request. Resolved secrets, headers, and provider endpoint URLs are not
copied to Chroma. Explicit non-secret URL switches are saved. Authenticated endpoints
must use an OpenCode provider; a direct base URL without a provider is keyless.
Configured custom authentication headers and keyless providers are supported.
Only API-key connections are supported; OAuth/external credentials are not forwarded.
The public credential-list API returns all secrets: its response stays inside the
launcher, never in a tool result. Do not manually dump provider/credential responses.
Ambiguous/unusable stored credential connections fail closed. The OpenCode CLI's
existing authentication context is used; no JEB key/password switches are provided.

Distilled capture content is sent to the selected gateway/upstream. Confirm that
the user intends remote processing and accepts its logging/retention before the
first remote embedding operation. Normal shell permissions apply; standalone
skills do not provide a separate embedding permission hook.

## Operations

```bash
bash ~/.config/opencode/skills/jeb-import/scripts/process_burp.sh import capture.xml /path/to/project
bash ~/.config/opencode/skills/jeb-import/scripts/process_burp.sh rebuild /path/to/project
bash ~/.config/opencode/skills/jeb-import/scripts/process_burp.sh status /path/to/project
bash ~/.config/opencode/skills/jeb-import/scripts/process_burp.sh abandon <capture_id> /path/to/project
```

Legacy `capture.xml [project_dir]` invocation remains supported. Normal imports
stream directly into Chroma with an OS-released writer lock, without intermediate
JSON files. Capture parse state and index state are separate; inspect status after
an error. Resume parsing from source or rebuild from ready retained observations.
Abandon excludes failed/interrupted captures without deleting evidence; rebuild
afterward. Rebuild requires no original XML.

Omitted analysis flags inherit saved settings. Explicit flags apply corpus-wide:

- `--auth-cookies NAME[,NAME...]` (repeatable) replaces custom cookie names;
  `--auth-cookies ''` clears them.
- `--auto-detect-auth-cookies` / `--no-auto-detect-auth-cookies` controls
  origin-scoped login-cookie inference (enabled for new projects).
- `--rebuild` forces derived rebuilding during import.

## Storage, evidence, and recovery

Embedded collections: typed `graph` nodes and recorded `attacks`. Lookup-only
collections: `captures`, `exchanges`, `identifiers`, `edges`; they never embed.
No SQL/FTS sidecar, BM25, or lexical index is added.

Full decoded HTTP and original base64 remain in `exchanges`. Repeated observations
survive, as does original capture membership. Global analysis retains compact
features, hydrating source bodies on demand. Bounded batches reduce memory/model
cost; metadata-only changes retain vectors. Status reports the loss ledger for
derived representations; bounded previews do not replace source evidence.

Parser, feature, identifier, graph-schema, and embedding profile versions control
repeated work. Legacy `structure`/`behavior` projects migrate through rebuild.
Older sources without retained observations must be reimported; summaries cannot
reconstruct missing history. Never delete a database to fix profile mismatches.

Finding IDs and structured evidence survive rebuild. Interrupted finding migration
uses `attacks_rebuild_backup`; writes are blocked until migration finishes. Rebuild
repairs pending identifiers. Legacy free-form findings remain readable but may be
marked `legacy-unstructured`. Preserve original exports and back up databases before
migration. Legacy JSON/SQLite files are not removed.

## Explicit export and visualization

Export requires an unused destination and writes NDJSON:

```bash
bash ~/.config/opencode/skills/jeb-import/scripts/process_burp.sh export /path/to/project \
  --collection graph --output /path/to/graph.ndjson
```

Export supports all six collections. Standalone parser/builders are export
utilities, not normal pipeline stages, and require explicit output destinations.

```bash
bash ~/.config/opencode/skills/jeb-import/scripts/visualize.sh \
  --project-dir /path/to/project --mode graph --out /path/to/site-map.html
bash ~/.config/opencode/skills/jeb-import/scripts/visualize.sh \
  --project-dir /path/to/project --mode embedding --out /path/to/vectors.html
```

Visualization reads stored vectors and edges without calling an embedding provider.
Select output paths deliberately and keep engagement files outside the skills tree.
