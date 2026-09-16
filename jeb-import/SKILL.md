---
name: jeb-import
description: Stream Burp Suite XML captures into a cumulative project-local Chroma database; rebuild or inspect import status. Use when asked to ingest, import, process, or embed traffic; use jeb-query for investigation.
---

# J.E.B. — Streaming Chroma Import

Run in the engagement project, separate from the skill repository:

```bash
~/.config/opencode/skill/jeb-import/scripts/process_burp.sh import capture.xml /path/to/project
```

Legacy `capture.xml [project_dir]` invocation also works. Normal import persists
only Chroma data and the writer lock: no intermediate JSON files or debug dumps
in the cwd or temporary directories.

Prerequisites: Python 3.10+, Ollama 0.11.10+ with `embeddinggemma:latest` pulled,
and the shared environment:

```bash
python3 -m venv ~/.config/opencode/skill/jeb-import/scripts/venv
~/.config/opencode/skill/jeb-import/scripts/venv/bin/pip install -r ~/.config/opencode/skill/jeb-import/scripts/requirements.txt
```

## Operations

```bash
~/.config/opencode/skill/jeb-import/scripts/process_burp.sh rebuild /path/to/project
~/.config/opencode/skill/jeb-import/scripts/process_burp.sh status /path/to/project
~/.config/opencode/skill/jeb-import/scripts/process_burp.sh abandon <capture_id> /path/to/project
```

Rebuild needs no XML: it reads retained observations. Failed/interrupted captures
are excluded until resumed from their source. Abandon explicitly excludes failed
captures without deleting their evidence; rebuild afterward. Capture parse state
and project index state are separate. A single OS-released lock protects writes.

## Inherited project settings

Omitted flags inherit saved settings. Explicit flags apply to the entire corpus:

- `--auth-cookies NAME[,NAME...]` (repeatable): replace custom cookie names;
  `--auth-cookies ''` clears them.
- `--auto-detect-auth-cookies` / `--no-auto-detect-auth-cookies`: set origin-scoped
  login-cookie inference (new projects default to enabled).
- `--rebuild` on import: force derived rebuilding even if versions match.

Original capture import configuration is retained. Parser, feature, identifier,
document-schema, and embedding versions control repeated work. The resolved local
model digest is recorded, so changing the model behind `latest` requires rebuild.

## Streaming and evidence

XML is parsed, decoded, fingerprinted, and feature-extracted in small batches.
Full decoded HTTP and original base64 remain in `exchanges`; `captures` stores
source identity and state. Exact `identifiers` are updated for new or changed
extraction versions. All are Chroma collections; no auxiliary SQL/FTS index.

Global analysis retains compact feature records, fetching source bodies one at a
time for distillation. Memory scales with compact features and the largest single
exchange, not the whole raw corpus. Structure and behavior are emitted sequentially
in bounded embedding batches. Metadata-only changes retain existing vectors.

Repeated observations inside one capture survive. Equal full evidence plus
timestamp and occurrence ordinal identifies cross-capture overlap for aggregation.
Coarse timestamps can be ambiguous; original capture membership always survives.
Source records hold reverse behavior associations for paginated evidence lookup.

## Recovery and findings

Run status after an error. Resume parsing from the source or rebuild indexes from
ready captures. `attacks` retains structured testing events. Rebuild repairs pending
identifier writes and migrates finding embeddings through `attacks_rebuild_backup`.
Finding writes are blocked while migration is pending. Legacy free-form findings
remain readable; `legacy-unstructured` marks limits on automatic identifier repair.

Preserve the database and original exports. Import older sources to populate
observations; collapsed summaries cannot reconstruct missing history. Never delete
the database as a profile-migration step. Legacy JSON/SQLite files remain untouched.

## Explicit export

Only deliberate export writes diagnostics, at a required unused destination:

```bash
~/.config/opencode/skill/jeb-import/scripts/process_burp.sh export /path/to/project \
  --collection behavior --output /path/to/behavior.ndjson
```

Export streams newline-delimited records. Standalone parser/builders require
`--output` and are export utilities, not normal import stages. Reinstall the updated
definitions if an older installed wrapper still writes intermediate JSON files.
