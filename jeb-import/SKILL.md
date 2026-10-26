---
name: jeb-import
description: Import Burp Suite XML into a project's cumulative Chroma knowledge graph; choose the embedding backend; rebuild, check status, abandon failed captures, export, and visualize. Use for ingestion and maintenance; use jeb-query to investigate.
---

# JEB — import and maintenance

Every command goes through this skill's launcher: `<skill-dir>/jeb`, which is
`~/.config/opencode/skills/jeb-import/jeb` in a default install. **Below, `jeb` means
that full path**; there is no `jeb` on PATH. Always pass `--project-dir DIR` (the
engagement directory). The skill directory is source code, not engagement data.

## Setup (once)

```bash
~/.config/opencode/skills/jeb-import/jeb setup        # add --viz for plotting
```

Needs Python 3.10+. Setup creates a venv inside the skill and never downloads or
calls a model.

## Commands

| Need | Command |
|---|---|
| Import a capture | `jeb import capture.xml --project-dir DIR` |
| Re-derive indexes (no XML needed) | `jeb rebuild --project-dir DIR` |
| Inspect parse/index state and the loss ledger | `jeb status --project-dir DIR` |
| Exclude a failed/interrupted capture | `jeb abandon <capture_id> --project-dir DIR`, then `rebuild` |
| Export a collection as NDJSON | `jeb export --project-dir DIR --collection graph --output FILE` |
| Site map / vector-space HTML | `jeb viz --project-dir DIR --mode graph --out FILE` (or `--mode embedding`) |

Imports are cumulative: each new capture adds to the project, and every exchange
is retained with its capture provenance (duplicates are merged only in the
derived indexes). Analysis flags (on `import`/`rebuild`) persist for the project:
- `--auth-cookies NAME[,NAME...]` sets the custom session cookie names; `''` clears them.
- `--no-auto-detect-auth-cookies` turns off login-cookie inference.

Every command prints JSON; `import` and `rebuild` print progress lines first. Errors
are one JSON object `{"command", "error"}` (usage errors add `help`), with exit 2
for bad usage and 1 for a failed command. `jeb <command> -h` lists all options.

## Embedding backend

New projects default to local Ollama `embeddinggemma-2:latest`. The user must pull
that model with Ollama; you cannot. To use a remote backend, pass switches on the
first `import`, or on `rebuild` to migrate an existing project. For example,
`--embedding-provider litellm --embedding-preset litellm-qwen3-embedding-8b --embedding-model qwen/qwen3-embedding-8b --embedding-revision <pinned>`
(`--embedding-model` is the gateway's alias; ask the user if unsure).
Selections are saved in the project and inherited by later imports and queries.

**Before the first remote embedding, confirm that the user agrees to send distilled
capture content to that gateway.** Credentials come from OpenCode's own provider
configuration and are never stored or printed.

Read `references/embedding.md` for presets, every switch, credentials and runtime budgets.

## Rules

- Never delete `chroma_db/` to fix an error. Run `status`, then `rebuild`, which keeps
  findings and source evidence.
- Keep the original XML exports. `rebuild` doesn't need them, but a reimport does.
- After a failure, `status` separates capture parse state from project index state.

Read `references/storage.md` for collections, recovery, migration and export details.
