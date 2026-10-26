# Initial import recipes

Run from the intended engagement/OpenCode configuration scope. Replace the paths,
provider ID, gateway model alias, and pinned revision. Subsequent imports/queries
inherit the selections from Chroma; no settings file or environment exports.

## LiteLLM Qwen

```bash
~/.config/opencode/skills/jeb-import/jeb import capture.xml /path/to/project \
  --embedding-provider litellm --embedding-preset litellm-qwen3-embedding-8b \
  --embedding-model qwen/qwen3-embedding-8b --embedding-revision YOUR-PINNED-REVISION
```

## LiteLLM Gemini

```bash
~/.config/opencode/skills/jeb-import/jeb import capture.xml /path/to/project \
  --embedding-provider litellm --embedding-preset litellm-gemini-embedding-2 \
  --embedding-model gemini-embedding-2 --embedding-revision YOUR-PINNED-REVISION
```

## Local Ollama

Manually prepare `embeddinggemma-2:latest` first; imports never download models:

```bash
~/.config/opencode/skills/jeb-import/jeb import capture.xml /path/to/project \
  --embedding-preset ollama-embeddinggemma2
```

For existing databases, replace `import capture.xml` with `rebuild`. Preserve the
database and original exports. Remote examples send distilled capture content to
the gateway/upstream; authorize processing and review logging/retention first.
