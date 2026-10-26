# Embedding selection and runtime budgets

Read this before the first import that uses a non-default backend, or before changing
models. All settings are switches on `import` and `rebuild`; there is no settings file and
no environment variable. Non-secret selections are saved in the project's `captures`
collection, and later imports and queries inherit them.

## Presets

| Preset | Default dimensions | Maximum context |
|---|---:|---:|
| `ollama-embeddinggemma2` (default) | 768 | 8192 |
| `litellm-gemini-embedding-2` | 3072 | 8192 |
| `litellm-qwen3-embedding-8b` | 4096 | 32768 |

Without switches, new projects use local Ollama. The user must pull
`embeddinggemma-2:latest` (`ollama pull embeddinggemma-2`); the older `embeddinggemma`
is a different model. Setup never downloads a model.

```bash
<skill-dir>/jeb import capture.xml --project-dir /path/to/project \
  --embedding-provider litellm \
  --embedding-preset litellm-qwen3-embedding-8b \
  --embedding-model qwen/qwen3-embedding-8b \
  --embedding-revision YOUR-PINNED-DEPLOYMENT-REVISION
```

LiteLLM requires a pinned `--embedding-revision`, and a gateway with cross-model fallback
disabled. A gateway alias alone does not identify immutable weights.

## Switches

- Identity: `--embedding-preset`, `--embedding-model`, `--embedding-revision`,
  `--embedding-dimensions N`, `--embedding-context-tokens N`. Changing any of these
  re-embeds through `rebuild`. Selecting another preset resets inherited
  model-specific values.
- Connection: `--embedding-provider ID` (an OpenCode provider), `--embedding-base-url URL`,
  `--embedding-timeout SECONDS`, `--embedding-keep-alive DURATION` (Ollama),
  `--[no-]embedding-send-dimensions` (LiteLLM), and `--opencode-server URL` for a
  private or remote OpenCode server.
- Clear a saved override with `--no-embedding-provider`, `--no-embedding-base-url` or
  `--no-opencode-server`.
- Runtime budgets: `--embed-batch-docs N`, `--embed-batch-chars N`, `--embed-workers N`,
  `--candidate-ceiling N`, `--max-distance-graph VALUE`, `--max-distance-attacks VALUE`
  (`[0, 2]` or `none`), and
  `--depth-<quick|normal|deep>-<candidate-k|n-results|max-per-endpoint|snippet-len|raw-chars> N`.
  These never invalidate vectors. Only overridden budgets are saved, so new defaults
  still reach existing projects.

To migrate a project to another model, run `rebuild` with the new switches. Never delete
the database. A failed import does not save its switches.

## Credentials and remote processing

- The launcher resolves the selected OpenCode provider privately, through `opencode api`
  in the invocation's configuration scope, and only when an embedding request needs it.
  It uses the OpenCode CLI's existing authentication; JEB has no key or password switches.
- Resolved secrets, headers and provider endpoint URLs are never written to Chroma.
  Explicit non-secret URL switches are saved.
- Authenticated endpoints must go through an OpenCode provider. A bare base URL without
  a provider is keyless.
- Configured custom authentication headers and keyless providers are supported. Only
  API-key connections are reused: OAuth and external credentials are not forwarded.
  Stored credential connections that are ambiguous or unusable fail closed.
- The public credential-list API returns every secret, so its response stays inside the
  launcher. Never dump provider or credential responses yourself.
- Distilled capture content goes to the selected gateway and its upstream. Before the
  first remote embedding operation, confirm that the user intends remote processing and
  accepts its logging and retention. Shell permissions are the only execution boundary.

The Gemma-2 distance cutoff is calibrated only for that model. Qwen and Gemini default
to no cutoff.

## Serving requirements

| Preset | Formatting | Supported dimensions |
|---|---|---|
| `ollama-embeddinggemma2` | Titled documents; `task: search result` queries | 128, 256, 512, 768 |
| `litellm-gemini-embedding-2` | Same prefixes; no `task_type` parameter | 128–3072 |
| `litellm-qwen3-embedding-8b` | English `Instruct:` / `Query:` for queries only | 32–4096 |

Dimensions are also subject to what the endpoint supports. Omitting the dimension
parameter does not relax exact output validation. Qwen serving must use last-token
pooling and must not add a second query instruction. Gemini must return one vector
per input, not an aggregate.

The engine checks response cardinality and index order, finite nonzero exact-sized
vectors, L2 normalization, and conservative UTF-8 input budgets including prefixes.
There is no silent truncation, dimension slicing, redirect credential forwarding, or
model fallback. Models cannot be mixed even when their dimensions match, and JEB
cannot detect a weight replacement behind an unchanged alias.
