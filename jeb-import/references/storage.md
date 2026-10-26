# Storage, recovery and migration

## Collections

- Embedded: typed `graph` nodes and recorded `attacks`.
- Lookup-only (never embedded): `captures`, `exchanges`, `identifiers`, `edges`.
- There is no SQL/FTS sidecar, BM25 or lexical index.

`exchanges` keeps the full decoded HTTP and the original base64, repeated observations,
and capture membership. Global analysis keeps compact features and loads source bodies
on demand. `status` reports the loss ledger for derived representations; bounded
previews never replace source evidence.

## Import and recovery

- Imports stream straight into Chroma under an OS-released writer lock, with no
  intermediate JSON files. A concurrent writer fails instead of waiting.
- Parse state (per capture) and index state (per project) are separate. After an error,
  run `status`:
  - Resume parsing by importing the same source again.
  - `rebuild` re-derives indexes from the retained observations, without the original XML.
  - `abandon <capture_id>` excludes a failed or interrupted capture without deleting its
    evidence; run `rebuild` afterwards.
- Omitted analysis flags inherit the saved settings, and explicit ones apply corpus-wide:
  - `--auth-cookies NAME[,NAME...]` (repeatable) replaces the custom cookie names, and
    `--auth-cookies ''` clears them.
  - `--[no-]auto-detect-auth-cookies` toggles origin-scoped login-cookie inference, which
    is on for new projects.
  - `--rebuild` forces re-derivation during an import.

## Versions and migration

- Parser, feature, identifier, graph-schema and embedding profile versions control what
  gets recomputed.
- Legacy `structure`/`behavior` projects migrate through `rebuild`. Older sources without
  retained observations must be reimported, because summaries cannot reconstruct
  missing history.
- Finding IDs and structured evidence survive a rebuild:
  - An interrupted finding migration resumes from `attacks_rebuild_backup`, and writes
    are blocked until it finishes.
  - Rebuild repairs pending identifiers.
  - Legacy free-form findings stay readable, but may be marked `legacy-unstructured`.
- Preserve the original exports and back up the database before migrating. Legacy JSON
  and SQLite files are not removed.
- Never delete a database to fix a profile mismatch.

## Export and visualization

`export` writes NDJSON for any of the six collections, and refuses an existing output
file. `viz` reads stored vectors and edges, and never calls an embedding provider.
`--mode graph` draws a site map; `--mode embedding` (the default) draws the vector
space. Keep output files outside the skills tree.
