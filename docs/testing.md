# Testing and manual host verification

**Current scope:** testing is isolated in temporary directories. Do not install
the plugin into the user's normal OpenCode configuration. Host checks use their
own server, configuration, data directory, and sessions. Live embeddings are Qwen only.
The current isolated pass has completed; further testing is paused until requested.

## Mandatory cost policy

Only **LiteLLM Qwen3-Embedding-8B** may receive live automated embedding requests.
All other model paths are mocked. `npm test` is offline and sets `JEB_TEST_MODE=unit`;
the engine rejects network embedding requests in that mode. The benchmark fixture
requires `JEB_TEST_LIVE=1` and selects the Qwen preset, native 4096 dimensions, and
a Qwen gateway alias. The live response must also identify Qwen3-Embedding-8B.
The gateway itself must pin the deployment and disable cross-model fallback;
the client cannot stop a misconfigured gateway from routing behind its back.

Prepare the engine environment with Python 3.10+:

```sh
python3 -m venv engine/.venv
engine/.venv/bin/python -m pip install -r engine/requirements.txt -r engine/requirements-viz.txt
npm ci --ignore-scripts
npm run typecheck
npm test
```

Use the configured OpenCode LiteLLM provider without printing/storing its key:

```sh
JEB_TEST_LIVE=1 python3 tests/live.py --revision YOUR-PINNED-REVISION -- --tier a
JEB_TEST_LIVE=1 python3 tests/live.py --revision YOUR-PINNED-REVISION -- --tier b
JEB_TEST_LIVE=1 python3 tests/live.py --revision YOUR-PINNED-REVISION -- --tier c
```

The helper defaults to provider `litellm` and gateway alias `qwen/qwen3-embedding-8b`.
It supports API keys from public provider settings, or `LITELLM_API_KEY`. Plugin
runtime also supports active API-key connections through the public plugin context.
To run without OpenCode provider lookup, export:

```sh
export JEB_TEST_LIVE=1
export JEB_EMBEDDING_PRESET=litellm-qwen3-embedding-8b
export JEB_EMBEDDING_MODEL=qwen/qwen3-embedding-8b
export JEB_EMBEDDING_DIMENSIONS=4096
export JEB_EMBEDDING_BASE_URL=https://your-gateway.example/v1
export JEB_EMBEDDING_REVISION=YOUR-PINNED-REVISION
# Supply LITELLM_API_KEY securely in the environment; never commit it.
./tests/run.sh --tier a
```

Use `JEB_EMBEDDING_SEND_DIMENSIONS=false` only if the upstream rejects the dimensions
parameter but returns native 4096d vectors. Lower a deployed context limit with
`JEB_EMBEDDING_CONTEXT_TOKENS`. Keep tests at 4096d so their baseline identity stays
unambiguous. The fixture key includes the profile and ingest source code, not keys
or endpoints. Reusing a fixture avoids repeat embedding costs. `--fresh` and Tier C
cold imports are explicit additional costs. Retries and worker concurrency are bounded.

## Baselines

Old files directly under `tests/baseline/` are historical Gemma results, not valid
Qwen thresholds. New automated baselines live under
`tests/baseline/qwen3-embedding-8b-4096/`. Do not invent results if the gateway is
unavailable. Missing baselines must be established deliberately, inspected, and
then checked by a normal run:

```sh
JEB_TEST_LIVE=1 python3 tests/live.py --revision YOUR-REVISION -- --live --fresh --update-baseline
JEB_TEST_LIVE=1 python3 tests/live.py --revision YOUR-REVISION -- --live
```

Qwen/Gemini do not inherit Gemma's `0.38` distance cutoff. Calibrate an explicit
cutoff using relevant and off-topic queries before enabling one. Performance
measurements are informational; correctness and digest gates remain enforced.

## Isolated real-host smoke checks

These start a private foreground OpenCode server with a temporary HOME, XDG
directories, database, and configuration under `/tmp/opencode`. They do not install
into or restart the normal OpenCode service. A test-only RPC bridge invokes the
registered tool executors without asking a chat model to generate tool calls.

```sh
python3 tests/host_smoke.py          # linked install, offline registration/permissions
python3 tests/host_smoke.py --copy   # full copy installation and host loading
JEB_TEST_LIVE=1 python3 tests/host_smoke.py --live --revision YOUR-REVISION
```

The live smoke uses four generated capture observations and only Qwen embeddings.
It covers import/status/map/search/graph, explicit project paths, finding ID
preservation on rebuild, and both visualization modes. The private server is
terminated and its temporary configuration/data removed on completion or failure.

## Manual OpenCode smoke test (all three presets)

These are operator-run checks, **not an automated multi-model test matrix**.
Use disposable engagement projects and the installer command for the selected
preset. Do not overwrite the global configuration just to test a second backend.

1. Confirm OpenCode lists one `jebediah` plugin and the `jebediah` primary agent.
   Verify the plugin options use the intended preset. Plugin loading alone must
   not create a venv, download a model, or issue an embedding request.
2. Run `jeb_import command=import xml_file=<authorized-capture>` in a disposable
   project; approve the relevant file/database and remote-embedding permissions.
3. Exercise status, endpoint, search, graph, and explicit `project_dir` query calls.
   Check import/query dimensions, model identity, errors, and batch cardinality.
4. Record a disposable finding, save its ID/evidence, run `command=rebuild`, and
   verify the finding ID and evidence remain unchanged.
5. Render graph and embedding visualizations. Cancel an import and check status;
   retain the database and rebuild rather than deleting evidence.
6. Verify missing credentials/model, wrong dimensions, and unavailable endpoint
   fail without silently changing models. Deny an edit/embedding permission and
   confirm the operation does not proceed.
7. For manual cross-model migration, retain the same disposable database and
   finding, switch presets, confirm mismatch detection, then rebuild and verify
   source observations and finding IDs survive. Never compare cross-model vectors.

### Ollama / EmbeddingGemma 2

Manually run `ollama pull embeddinggemma-2:latest` using a compatible Ollama release.
Check `/api/embed`, 768 dimensions, explicit `truncate: false`, and titled-document /
`task: search result` query prefixes. Reduced dimensions require normalization and
a rebuild. Old `embeddinggemma` and `embeddinggemma-2` are different models.

### LiteLLM / Gemini Embedding 2

Route the alias to stable `gemini/gemini-embedding-2`. Confirm LiteLLM supports
mapping `dimensions` to output dimensionality, does **not** send `task_type`, and
returns one vector per input (not a single aggregated vector). Start at 3072d;
768/1536 are optional profile changes. Vertex routing needs separate manual batch
verification. Native Gemini 2 normalizes reduced-dimensional vectors.

### LiteLLM / Qwen3-Embedding-8B

Confirm native 4096d output, English query-only instruction applied exactly once,
last-token pooling in the serving implementation, and no hidden cross-model
fallback. The public model supports 32K context but a deployment may be smaller.
Do not assume every upstream accepts `dimensions` or generic truncation parameters.
