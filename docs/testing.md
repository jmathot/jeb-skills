# Testing standalone skills

Tests must not install into the user's normal OpenCode configuration, change its
credentials, restart its service, or access real engagement databases. Use isolated
temporary directories; the automated tests create and remove their own.

## Offline checks

```bash
jeb-import/jeb setup --viz
bash tests/run.sh --tier u
jeb-import/scripts/venv/bin/python tests/offline_correctness.py
jeb-import/scripts/venv/bin/python tests/host_smoke.py
```

No Node/npm build or plugin is required. Tier U runs pure graph/parser checks,
mocked embedding contracts, standalone configuration/provider resolution, installer
regressions, and isolated CLI workflows. All embedding HTTP transports are mocked.
The offline launcher sets its network guard in process, not through environment
variables. Select an already-prepared interpreter with
`bash tests/run.sh --python /path/to/python --tier u`.

The offline correctness runner uses fake vectors for fact/CLI checks, not
retrieval-quality measurements or live baseline updates. The host smoke starts
its own OpenCode server, checks skill/agent discovery without a plugin, and
checks that the host loaded the agent's permissions, and resolves a dummy provider
through the unmodified production resolver using `--opencode-server`. The temporary
server password is supplied only through the standard OpenCode CLI authentication
context.

## Live automated testing: explicit Qwen-only opt-in

Only LiteLLM Qwen3-Embedding-8B may receive live automated embedding requests.
Ollama and Gemini have mocked contract coverage; live checks for them are manual
only. No automatic model downloads, fallback, or multi-model benchmark matrix.

```bash
bash tests/run.sh --live --revision YOUR-PINNED-REVISION --tier a
bash tests/run.sh --live --revision YOUR-PINNED-REVISION --tier b
bash tests/run.sh --live --revision YOUR-PINNED-REVISION --tier c
```

The runner defaults to OpenCode provider `litellm`, alias `qwen/qwen3-embedding-8b`,
and native 4096 dimensions. Use `--provider`, `--model`, and `--opencode-server` to
select the authorized connection. Settings are passed as non-secret switches and
inherited from Chroma; the in-process performance harness receives the same typed
configuration. Credentials are privately resolved by the production adapter.
Each live subprocess enforces Qwen-only mode. The retained `tests/live.py` launcher
also requires `--live`; there are no JEB environment-variable overrides or opt-ins.

Tier A checks ground-truth correctness. Tier B checks retrieval metrics. Tier C
records performance and checks stored-record digests. Fixtures are keyed by source
and embedding profile to avoid paying for unchanged imports. `--fresh` and baseline
updates are deliberate additional costs. Never invent results if a provider is
unavailable. The gateway must pin weights and disable cross-model fallback.

`tests/baseline/embeddinggemma2-768/` holds historical Gemma measurements from the
plugin branch, for reference only; no test reads them, and they are not Qwen
thresholds. Qwen retrieval has its own baseline under
`tests/baseline/qwen3-embedding-8b-4096/`.

**Pending for this release:** the Qwen digest and performance baselines have not
been recorded, so a live tier C run reports "no committed digest baseline" until
someone runs it once with `--update-baseline`. There is no calibrated Qwen or Gemini
distance cutoff (Gemma's 0.38 does not apply), and Ollama and Gemini have mocked
coverage only.

## Isolated OpenCode host smoke

`tests/host_smoke.py` automates discovery and dummy provider-settings
resolution without any embedding requests. The following broader checks remain
manual, with explicitly authorized test captures/connections:

In a disposable HOME/XDG/config/data directory:

1. Install the skills with `OPENCODE_CONFIG_DIR` pointing to the isolated config.
2. Start a private foreground OpenCode server using the supported V2 CLI. Never
   install a test plugin or restart the normal service.
3. Confirm both skills and the primary agent are discovered with no Jebediah plugin.
4. Load each skill and check that its supporting scripts resolve from its base.
5. For a manual remote test, explicitly configure an isolated provider and authorize
   sending test data. Run import switches and verify subsequent query inheritance.
6. Exercise status, endpoint, map, graph, semantic search, evidence, identifiers,
   finding recording, rebuild, export, and both visualization modes.
7. Change a pinned revision, verify mismatch/rebuild behavior and evidence/finding
   ID preservation. Cancel import, inspect status, and recover without deleting data.
8. Verify missing/ambiguous credentials, wrong dimensions, unavailable endpoints,
   and OAuth/external connections fail clearly without secret output or fallback.
9. Terminate the private server and remove only its known disposable files.

Skill instructions cannot enforce a distinct `jeb.embed` permission. Normal shell
permissions apply, including any writes/network actions of an allowed script.

## Manual backend checks

- **Ollama:** pull `embeddinggemma-2:latest`, verify `/api/embed`, 768d,
  `truncate: false`, and the expected document/query prefixes. Old Gemma differs.
- **Gemini:** verify LiteLLM routing, 3072d output, no `task_type`, and one indexed
  vector per input; Vertex batch aggregation requires separate verification.
- **Qwen:** verify 4096d, last-token pooling, query-only instruction once, and the
  gateway's pinned deployment. Reduced dimensions/context are deployment-dependent.

Plugin host smoke results and historical live benchmark numbers do not constitute
verification of the new skills packaging. Record actual runs and remaining gaps.
