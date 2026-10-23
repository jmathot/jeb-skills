# Skills-only port of plugin improvements

Source: plugin commit `9e95045`; original skills base: `dbc5163`.
The Python engine and synthetic benchmark corpus were ported from that source;
plugin packaging and runtime hooks were deliberately excluded.

## Included

- Typed Chroma graph, edges, neighborhood retrieval, and graph visualizations.
- HTML sections/forms, hydration text and nested data, JavaScript facts, modules,
  source-map pairing, external origins, and explicitly unobserved stub routes.
- Reduced ingest loss, loss ledger, compact features, bounded source hydration,
  batched lookups/embeddings, unchanged-vector reuse, and schema/profile migrations.
- Original source evidence, normalized identifier lookup, suppressed one-time
  values in embeddings, durable findings, retry keys, and recovery after failures.
- Ollama Gemma 2, LiteLLM Gemini 2, and LiteLLM Qwen embedding transports/profiles.
- Standalone graph queries, explicit project selection, source evidence filters,
  and executable follow-up hints preserving the selected database.
- Safer installation with backups, local-edit detection, atomic replacement and
  rollback; explicit locked Python setup with readiness stamps.
- Pure checks, embedding/configuration/installer contracts, synthetic correctness
  and retrieval/performance suites, and isolated skills-host smoke.

## Standalone adaptations

`jeb-import` switches replace plugin options. Non-secret selections live in the
existing Chroma project metadata, not a settings file. Python resolves provider
settings and active API-key credentials through public OpenCode APIs, in memory,
only when needed. Production skills do not read or write JEB environment
configuration. Batching, workers, retrieval cutoffs, depth budgets, keep-alive,
explicit endpoint overrides and OpenCode server selection all use switches.
Prompt scheme and cosine distance are derived/fixed, not environment overrides.
Only explicitly supplied non-secret endpoint/server URL overrides are stored;
provider-resolved URLs and credentials remain private to the execution.

Existing `process_burp.sh` and `jeb-query.sh` entrypoints remain. Visualization and
setup have explicit wrappers under `jeb-import/scripts`. There are no npm/build
requirements, plugin entrypoints, native `jeb_*` tools, or plugin registrations.

Plugin permission hooks cannot be reproduced by Markdown skills. Normal shell
permissions apply; operators must authorize remote capture processing. Public
credential-list API responses contain all secrets and must remain private to the
launcher. OAuth/external credentials are never repurposed as embedding API keys.

## Upgrade an installation

1. Back up the engagement database and preserve original Burp exports.
2. Run `bash install-skills.sh`. For older installations without the new manifest,
   inspect conflicts and rerun with `--force` to retain backups.
3. Run the installed `setup.sh` (`--viz` for plots); models are prepared separately.
4. From the intended OpenCode configuration scope, run `process_burp.sh rebuild
   /path/to/project` with the desired embedding switches from the README.
5. Check `status`, investigate an endpoint, and confirm retained finding IDs/evidence.

Old `structure`/`behavior` indexes are replaced by the graph. Retained observations
are reused without source XML; projects lacking them require original-source
reimport. Never delete the database to repair a profile mismatch. Failed migration
retains state for retry. No installed plugin or unrelated configuration is removed.

## Verification recorded for this port

- Offline graph/parser pure checks passed.
- **38** offline contract/installer/setup/CLI tests passed with mocked HTTP, including
  regression checks that stale JEB environment values cannot affect execution.
- Installed CLI workflows covered API-key resolution, no secret output, exact
  lookups with an unavailable provider, cross-model rebuilds, unavailable-provider
  recovery, finding preservation, export, and both visualization modes.
- An actual database generated with the historical `dbc5163` code was rebuilt:
  source observation ID/document/capture membership and finding ID/evidence survived.
- **155/155** synthetic ground-truth fact/CLI checks passed with fake embeddings.
  This is not a live retrieval-quality result.
- A private real OpenCode V2 server discovered both skills and the primary agent,
  with no Jebediah plugin. The real CLI resolved a dummy provider's settings/key.
  The current smoke uses the unmodified production resolver with an explicit
  server selection, not a patched subprocess implementation.
- Shell syntax and `git diff --check` passed.

No live embedding requests or normal OpenCode configuration changes were made.
Live Qwen retrieval/performance/digest runs, real stored-integration credential
reuse, and manual Ollama/Gemini checks remain unverified for this port. Historical
plugin benchmark results are not claimed as new skills-packaging verification.
