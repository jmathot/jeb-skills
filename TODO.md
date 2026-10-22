# TODO

State as of 2026-10-22 on branch `plugin`. The knowledge-graph ingestion plan and
the a8432e6 bugfix plan are implemented; their history is in `git log`. What is
left needs a machine with OpenCode and with fast embedding.

## Next environment (OpenCode, fast Ollama)

1. **Regenerate tier C digests.** Ingest-path changes since the last full run
   (`FEATURE_VERSION` features-v5, `IDENTIFIER_VERSION` identifiers-v6, redacted
   `req_semantic`, decoded path identifiers, lower-cased UUID/hex identifiers,
   earliest-separator header split) change stored records. Tiers U, A (190/190)
   and B pass on a fresh import of the current code, but tier C (which re-imports
   twice and gates on the committed digests) was not run, so
   `tests/baseline/*.digest.json` and `perf.json` are stale:
   `./tests/run.sh --update-baseline`. Read the digest diff before keeping it.
2. **Verify the plugin in the real host** (never run from OpenCode so far):
   - `./install.sh`; confirm the symlinked plugin resolves `@opencode/plugin`.
   - Check the v2 docs for the `plugins/` and `agents/` directory names and the
     `opencode.jsonc` plugin and options keys.
   - Call `jeb_import` (import, status, rebuild), `jeb_query` with `command=graph`
     and with `project_dir`, `command=record-attack`, and `jeb_visualize`.

## Measured (keep for context)
- Scale (600 HTML pages + 8 bundles, 57 MB): parse+annotate 19.5 s, `build_graph`
  0.2 s, peak RSS 189 MB, 6,027 embedded records (4,800 sections). Embedding is
  the cost: an Ollama import of that capture ran over an hour on this machine.
- `command=rebuild` on a project built by 29cfffe: finding ids preserved,
  `structure`/`behavior` removed, `TARGETS` edge present.
- Tier B on `normal` is at or above the pre-graph recall and nDCG; precision is
  lower (0.36 vs 0.41) because route, behavior and section nodes share one
  collection and the query set grades one result per route.
- Boilerplate: chunk-hash plus repeated-text-block removal strips div-only chrome
  completely, so tag-path subtree hashes are not needed.
- `load_many` / `hydrate_item` is under 1% of annotate time (307 exchanges:
  0.01 s vs 1.31 s), so a preview-only decode path is not worth adding.

## Optional, unscheduled
- Embedding cost on very large captures: consider an env knob for
  `MAX_SECTIONS_PER_PAGE` (and a per-capture section budget) in `segment.py`.
- Tier B precision: a per-intent `node_type` default or a route-over-behavior
  rerank would recover it if it matters in practice.
