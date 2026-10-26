# Changelog

## 8.0.0 — 2026-10-25

First skills release built on the plugin branch's engine. Upgrade notes are in
[docs/migration.md](docs/migration.md).

### Added
- Typed knowledge graph (`graph` + `edges` collections) replacing the old
  `structure`/`behavior` indexes: routes, behaviors, origins, data objects, posture,
  page sections and forms, with `jeb graph` traversal and graph/embedding
  visualizations.
- JavaScript facts, source-map pairing, external origins and unobserved stub routes.
- Embedding presets for Ollama `embeddinggemma-2`, LiteLLM Gemini Embedding 2 and
  LiteLLM Qwen3-Embedding-8B, with provider credentials resolved privately through
  OpenCode.
- One `jeb` launcher per skill. Global flags (`--project-dir`, `--opencode-server`)
  can go before or after the command; help works before setup.
- Installer `--uninstall` and `--dry-run`; files a new version no longer ships are
  pruned on update; launchers are always installed executable.
- Evidence-preserving migrations: finding IDs, source observations and capture
  membership survive a rebuild.

### Changed
- All settings are command-line switches saved in the project's Chroma metadata.
  There is no settings file, and `JEB_*` environment variables are ignored.
- Every command prints JSON. Errors are one JSON object with `command` and `error`;
  exit 2 means bad usage and 1 means the command failed. `status`, `export`,
  `abandon`, `setup` and `viz` used to print plain text.
- `get`/`similar` with an unknown ID is now an error instead of an empty result.
- SKILL.md files are shorter, with detail moved into each skill's `references/`.

### Removed
- `jeb-import/scripts/process_burp.sh`, `setup.sh`, `visualize.sh` and
  `jeb-query/scripts/jeb-query.sh`. Use the `jeb` launchers; see the mapping in
  docs/migration.md.
- An unknown first word is no longer treated as a capture path. Only arguments
  ending in `.xml` or naming an existing file imply `import`.

### Fixed
- A mistyped capture path, an unknown command, or `viz`/`status` on an empty
  directory no longer create an empty `chroma_db`.
- Projects with no finished capture are told to import, not to rebuild.
- An up-to-date index is no longer marked pending when the saved selection came
  from an older version.

### Known gaps
- Qwen digest and performance baselines are not yet recorded, and there is no
  calibrated Qwen or Gemini distance cutoff. Qwen retrieval on the synthetic corpus
  (recall ≈0.70, nDCG ≈0.60) is below the Gemma baseline.
- Ollama and Gemini have mocked contract coverage only; validate them manually
  (docs/testing.md).
