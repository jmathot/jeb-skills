# J.E.B.E.D.I.A.H.

John's Extension for Burpsuite Export Data Ingestion And Handling: standalone
**OpenCode skills** for investigating Burp Suite XML captures with a local,
Chroma-only knowledge graph and selectable embeddings.

This branch is a skills collection, **not a plugin**: no npm packages, TypeScript
build, native `jeb_*` tools or plugin registration. The separate `plugin` branch
provides that packaging. Engagement captures and databases belong in separate
project directories, never in this repository.

## Quick start

Requirements: Python 3.10+ with venv/pip, and OpenCode V2.

```bash
bash install-skills.sh                                # 1. install skills + agent
~/.config/opencode/skills/jeb-import/jeb setup --viz  # 2. Python environment
ollama pull embeddinggemma-2                          # 3. default local embedding model

# 4. import a capture into an engagement directory
~/.config/opencode/skills/jeb-import/jeb import capture.xml --project-dir ~/engagements/acme
~/.config/opencode/skills/jeb-import/jeb status --project-dir ~/engagements/acme

# 5. investigate
~/.config/opencode/skills/jeb-query/jeb map --node-type route --project-dir ~/engagements/acme
```

Then select the **J.E.B.E.D.I.A.H.** agent in OpenCode and point it at the
engagement directory, or load either skill from another agent.

Each skill has one launcher at its root, `<skill-dir>/jeb`. Nothing is added to
`PATH`, and no environment variables or settings files are used. The rest of this
README writes `jeb` for the matching launcher.

| Launcher | Commands |
|---|---|
| `~/.config/opencode/skills/jeb-import/jeb` | `setup`, `import`, `rebuild`, `status`, `abandon`, `export`, `viz` |
| `~/.config/opencode/skills/jeb-query/jeb` | `endpoint`, `map`, `search`, `get`, `similar`, `identifier`, `evidence`, `graph`, `attacks`, `record-attack` |

Every command prints JSON (`import` and `rebuild` print progress lines first). Errors
are a JSON object with `command` and `error`; exit status is 2 for usage errors and 1
for failed commands. `jeb <command> -h` lists every option. `--project-dir` (and
`--opencode-server`) may come before or after the command.

## Install, update, uninstall

```bash
bash install-skills.sh             # install or update
bash install-skills.sh --dry-run   # show what would change
bash install-skills.sh --force     # replace conflicting files, keeping backups
bash install-skills.sh --uninstall # remove skills, agent and the Python environment
```

The installer copies `jeb-import`, `jeb-query` and the primary agent into
`$OPENCODE_CONFIG_DIR`, else `${XDG_CONFIG_HOME:-$HOME/.config}/opencode`, and writes
nothing anywhere else. It:

- preserves OpenCode configuration, unrelated plugins and skills, the installed Python
  environment, and engagement databases;
- tracks installed file hashes: updates replace unchanged managed files, remove files
  this version no longer ships, and refuse to overwrite local edits without `--force`;
- preflights conflicts and backs up, rather than deletes, anything it replaces;
- refuses symlink destinations, so it never modifies another checkout indirectly.

`jeb setup` is explicit, locked and retryable; `--viz` adds plotting dependencies.
Neither installation nor setup downloads models or issues embedding requests.

An installation from before the file manifest existed reports changed files as
conflicts: inspect them, then rerun with `--force`. A legacy `agents/jebediah.md` is
also replaced only with `--force`. Existing plugin installations are not removed;
disable their registration separately if you only want the skills.

## Embedding backends

New projects with no switches use local Ollama at `localhost:11434` with
`embeddinggemma-2:latest`. The older `embeddinggemma` is a different model.

To use a remote backend, pass switches on the first `import`, or on `rebuild` to
migrate an existing project. For example, through your OpenCode LiteLLM provider:

```bash
jeb import capture.xml --project-dir ~/engagements/acme \
  --embedding-provider litellm \
  --embedding-preset litellm-qwen3-embedding-8b \
  --embedding-model qwen/qwen3-embedding-8b \
  --embedding-revision YOUR-PINNED-DEPLOYMENT-REVISION
```

| Preset | Native dimensions | Context budget |
|---|---:|---:|
| `ollama-embeddinggemma2` (default) | 768 | 8192 |
| `litellm-gemini-embedding-2` | 3072 | 8192 |
| `litellm-qwen3-embedding-8b` | 4096 | 32768 |

- `--embedding-provider` names an existing OpenCode provider; `--embedding-model` is
  its gateway alias, not necessarily the upstream model ID.
- LiteLLM deployments must pin the actual weights (`--embedding-revision`) and disable
  cross-model fallbacks.
- Non-secret selections are saved in the project's Chroma metadata once a command
  commits to them, and later imports and queries inherit them. A failed import keeps
  the previous selection.
- Credentials are resolved privately through `opencode api` from the provider's
  active API-key connection, only when an embedding request needs them. They stay in
  process memory and are never stored, printed or passed as arguments. OAuth and
  external credentials are not forwarded; missing or ambiguous connections fail closed.

**Remote processing disclosure:** distilled capture text, query text and recorded
findings go to the selected gateway and its upstream. Obtain authorization and review
logging and retention. Standalone skills run under normal OpenCode shell permissions;
they cannot enforce the plugin's remote-embedding permission hook.

Every switch (connection, dimensions, batching, retrieval budgets and distance
cutoffs), the serving requirements per model, and credential handling are documented
in [`jeb-import/references/embedding.md`](jeb-import/references/embedding.md). Runtime
budget and connection changes never require new vectors.

Retrieval quality: the Gemma distance cutoff (0.38) is calibrated only for that
model; Qwen and Gemini default to no cutoff. The Qwen retrieval baseline (recall ≈0.70,
nDCG ≈0.60, precision 0.25 on the synthetic corpus) is lower than Gemma's.

## Investigate

```bash
jeb endpoint https://app.example/api/orders/42 --project-dir ~/engagements/acme
jeb search "password reset email" --node-type behavior --project-dir ~/engagements/acme
```

`--project-dir` selects `<project>/chroma_db`; alternatively use `--db-path`, not both.

| Command | Purpose |
|---|---|
| `endpoint <path-or-url>` | First move for a named route: protocol facts, auth, related data, raw preview |
| `map --node-type route` / `map --node-type origin` | Orient by route (`--kind page\|action\|endpoint`) or session model |
| `search [text]` | Semantic discovery or exact metadata/substring filters |
| `graph <id> [--rel REL] [--hops 2]` | Follow typed stored relationships, one or two hops |
| `get <id> [--original]` | Full document or source evidence, optional original base64 |
| `similar <id>` | Related documents using a stored vector |
| `identifier <value>` | Exact extracted value associations |
| `evidence <behavior-id> [--signal content\|schema]` | Paginated supporting observations |
| `attacks` / `record-attack` | Recall/record testing events with durable IDs and evidence |

Responses carry bounded previews, pagination and consistency diagnostics, and quoted
executable follow-up commands (`next`) that repeat your project selection. Use
`--in graph|attacks` for semantic scope; `--in exchanges --contains TEXT` scans full
decoded source HTTP without embedding. Route nodes index protocol facts;
behavior/section/form nodes carry page content. Search observed signals, not
vulnerability names. Distances indicate similarity, not security impact. Filter
values and depth budgets are in
[`jeb-query/references/retrieval.md`](jeb-query/references/retrieval.md).

## Design and evidence

Six Chroma collections, with no auxiliary SQL/FTS database, lexical search, BM25 or RRF:

| Collection | Contents |
|---|---|
| `graph` (embedded) | `origin`, `route`, `behavior`, `data_object`, `posture`, `section`, `form` nodes with one-hop context headers |
| `attacks` (embedded) | Durable testing events, supplied verdicts, and evidence |
| `captures` (lookup) | Source digests, import/index state, analysis and embedding selections |
| `exchanges` (lookup) | Full decoded and original base64 HTTP, capture provenance |
| `identifiers` (lookup) | Exact value/field/source associations |
| `edges` (lookup) | Typed relationships: `HAS_BEHAVIOR`, `RETURNS`, `CONTAINS`, `SUBMITS_TO`, `CALLS`, and more |

The graph includes bounded DOM-based sections, forms, hydration text and records,
JavaScript endpoint/library/credential-shape facts, module/source-map associations,
and external origins. Client-named stub routes are explicitly `observed=false`:
leads, not captured endpoints. High-cardinality and one-time values are suppressed
in embeddings; original evidence remains retained.

Imports are cumulative, streaming, writer-locked, and rebuildable from retained
observations. `status` exposes the loss ledger for derived summaries. Credential
presence is not successful authentication; equal identifiers or response shapes do
not establish an authorization failure.

## Maintenance and migration

```bash
jeb status --project-dir ~/engagements/acme
jeb rebuild --project-dir ~/engagements/acme
jeb export --project-dir ~/engagements/acme --collection graph --output graph.ndjson
jeb viz --project-dir ~/engagements/acme --mode graph --out site-map.html
jeb abandon <capture-id> --project-dir ~/engagements/acme   # then rebuild
```

Export requires an unused destination. Visualization (`graph` or `embedding` mode)
makes no provider requests. `status`, `export`, `abandon` and `viz` still work when a
saved selection no longer validates, so a stale project can always be inspected.
Analysis settings (`--auth-cookies`, auth-cookie detection) persist per project.
Never delete `chroma_db/` to repair an error; see
[`jeb-import/references/storage.md`](jeb-import/references/storage.md) for recovery.

Upgrading from earlier versions of these skills, including replacements for the
removed helper scripts, is covered in
[docs/migration.md](docs/migration.md). See [docs/testing.md](docs/testing.md) for
offline checks, opt-in Qwen benchmarks, isolated host verification, and remaining
live-validation gaps, and [CHANGELOG.md](CHANGELOG.md) for release notes.
