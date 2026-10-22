# TODO

State as of 2026-10-22 on branch `plugin`.

## Current status: isolated verification complete for this pass; stopped

**The requested isolated test pass is complete. Stop here until the user requests
more work. Do not install Jebediah into the normal OpenCode configuration.** All
host checks used private servers and temporary config/data/session directories;
live embeddings used LiteLLM Qwen3-Embedding-8B only.

### Implemented

- Compiled JavaScript plugin entrypoint (`dist/index.js`) and locked Node tooling.
- Root `index.js` for actual local-directory discovery. Linked installs register
  the real checkout path, avoiding symlink-directory watcher failures.
- Installer builds the package, installs a local-path registration and primary
  agent, preserves unrelated JSONC, preflights conflicts, and backs up forced
  replacements. No automatic model downloads or embedding calls.
- Lazy Python bootstrap with shared disk readiness and non-stealing locks.
- Native V2 agent permissions; tool write checks and remote embedding permission.
- JSON-only native-tool results, including maintenance/visualization CLIs that
  produce text or empty output rather than JSON.
- Three explicit embedding presets, using two transports:
  1. Ollama `embeddinggemma-2:latest` (768d default).
  2. LiteLLM `gemini-embedding-2` (3072d default).
  3. LiteLLM `Qwen3-Embedding-8B` (4096d default).
- Model-specific document/query formatting, dimension validation, bounded inputs,
  normalized vectors, batch-index checks, profile-aware cache/rebuild identity.
- Reuse of public OpenCode provider settings and active API-key connections;
  explicit endpoint/environment-key alternative. No private credential-file reads.
- Backend examples and manual verification procedures in `examples/` and
  `docs/testing.md`.

### Remaining (do not start automatically)

1. Broaden real-host checks for cancellation, endpoint reports, remote-embedding
   permission rejection, and unavailable-provider recovery. The completed smoke
   invokes registered tools through a test-only RPC bridge, not a generated chat
   tool loop, to avoid additional model costs.
2. Resume Qwen benchmarks in the isolated test environment. Tier C was stopped during the
   cold-import/performance phase; **Qwen digest/performance baselines are pending**.
   Historical Gemma baselines directly under `tests/baseline/` remain untouched
   and must not be treated as Qwen baselines.
3. Manually validate Ollama and Gemini, including any dimension overrides and
   cross-model rebuilds. These backends have mocked contract coverage only.

## Mandatory model/cost policy

**All live automated embedding tests MUST use LiteLLM Qwen3-Embedding-8B.**
Ollama and Gemini live tests are manual only. No automatic model fallback,
downloads, or multi-model benchmark matrix. Live Qwen suites require explicit
opt-in; transport mocks and pure unit checks make no embedding calls.

## Verified results

- Python pure checks and **17** Python contract/installer tests passed.
- **16** TypeScript argv/config/runtime checks passed; build and shell syntax
  checks passed. Installer regressions cover switching modes without duplicate
  registration and restoring original entries after a configuration-write failure.
- Private real-host checks passed for both linked and full-copy installations:
  one active Jebediah plugin, its primary agent, all three tools, and denied-edit
  enforcement before database creation. No normal OpenCode configuration changed.
- Private live Qwen smoke passed with four generated capture observations:
  import/status/map/search/graph, explicit `project_dir`, finding recording and ID
  preservation on rebuild, plus graph and embedding HTML visualizations.
- Qwen: 243 graph records embedded from 307 observations in ~110s.
- Tier A: **190/190** correctness checks passed with Qwen.
- Tier B: passed and wrote `tests/baseline/qwen3-embedding-8b-4096/retrieval.json`:
  normal recall ~0.703, nDCG ~0.604, precision 0.250. This is a separate Qwen
  baseline, not a claim of matching Gemma's retrieval quality.
- No calibrated Qwen distance cutoff yet; the Gemma `0.38` cutoff is not inherited.
- Private servers were terminated and their temporary configuration/data removed
  by the test harness. The test-only RPC probe is not part of the production plugin.

## Historical measurements / optional follow-up

- Scale (600 HTML pages + 8 bundles, 57 MB): parse+annotate 19.5s, graph build
  0.2s, peak RSS 189 MB, 6,027 embedded records. Prior Ollama embedding was slow.
- Earlier evidence-preserving rebuilds retained finding IDs and TARGETS edges.
- Optional: section-count/capture budgets for very large captures.
- Optional: intent-specific node types or route-over-behavior reranking to improve
  precision. Do not expand scope until packaging and host verification are done.
