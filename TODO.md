# Development plan

Two parts: the **bugfix plan** from the a8432e6 review, then the
**knowledge-graph ingestion plan** (at the end of this file). Do the bugfix P0
items and test-suite holes first: the graph work touches the same code.

## Status (2026-10-21)

The embedding model is now `embeddinggemma-2:latest` (still 768 dimensions;
cosine distances are compressed, so the query cutoffs moved to 0.38). The
knowledge-graph plan at the end of this file is **implemented** and the suite is
green against new baselines (`./tests/run.sh`, `engine/.venv/bin/python
tests/test_units.py`). On the fixture, embedded records fell from 717 to 197.

**Done:** P0-1..5, T-1, T-2, T-8 (as `tests/test_units.py`), P1-1, P1-4..9,
the P2 items for the chromadb pin, the shared read lock and the case-insensitive
host filter, and graph Phases 1-6 and 7 (baselines). P1-2 and P1-3 are resolved by
construction: diversity is keyed on `anchor_id`, and findings/synthetic nodes are
exempt.

**Not done:**
- T-3..T-7 (perf counter patch target, duplicate entity check, keyword oracle
  identities, Tier A fixture mutation, hint parser).
- P2 remainder: header/body split, `find_similar` seed parent, missing-DB message,
  `--where '{}'`, cosine validation, bootstrap and `install.sh` fixes.
- A TypeScript test for `buildArgv`.
- Graph: external `Origin` nodes (`observed=false`) for third-party hosts named by
  client code (counted in the ledger only); pairing a captured `.map` with its
  bundle and per-module `Section` nodes (module names are recorded in facts but not
  yet embedded); `make_capture.py` pages for every segmentation layer and a >2 MB
  bundle, with tier A/B assertions (the pure pieces are covered in
  `tests/test_units.py`); Tier B needle queries for the new page shapes.
- Boilerplate removal works on chunk hashes plus repeated text blocks, not on
  tag-path subtree hashes as originally planned.
- Unverified assumptions about OpenCode v2 (symlinked plugin dependencies,
  config key names).

---

# Bugfix plan

Found in a review of `plugin` @ a8432e6 (2026-10-06). Line numbers refer to that
commit. Status tags: **[verified]** means checked by hand against the code
(and for P0-1, reproduced); **[reported]** means it came from a read-only sweep
and should be re-checked before fixing.

Work order: P0 → test-suite holes → P1 → P2. Use one commit per item. After any
change to the ingest path, run `./tests/run.sh --fresh` (see "Verification").

---

## P0: fix first

### P0-1. `_fit()` never terminates once embed text is over the cap [verified] **[fixed, untested]**
`engine/import/distill.py:1476-1492`

`_truncate(text, n)` returns `text[:n] + "…"`, which is **n+1** characters
(`distill.py:148-154`). After the first shrink, `total()` sits at `cap + 1`.
On every later pass, `target = len - 1` and `_truncate` hands back a string of
the same length. Nothing changes and the `while` loop spins forever. A rebuild
then hangs at 100% CPU while it holds the writer lock.

You can reach this from real input: the behavior embed parts
(`behavior_embed_text`, ~1520-1538) can add up to about 2.3k characters against
`EMBED_TEXT_CAP` (1500). For example, a POST with a JSON body, many params, a
long response summary and the security clause.

Fix:
```python
    while texts and total() > cap:
        i = max(range(len(texts)), key=lambda k: len(texts[k]))
        # _truncate appends "…" (one char), so aim one below the target length.
        target = max(floor, len(texts[i]) - (total() - cap) - 1)
        if target >= len(texts[i]) - 1:
            break
        LEDGER['truncated.embed_shrunk'] += 1
        before = total()
        texts[i] = _truncate(texts[i], target)
        if total() >= before:   # no progress: never loop on a no-op
            break
```
The final `_truncate(sep.join(texts), cap, 'embed_text')` still enforces the
hard cap if `floor` stops the shrinking.

Regression test (add to tier A or a new `tests/test_units.py`):
```python
import distill as d
out = d._fit([('a' * 1000, 1400), ('b' * 1000, 1400)])   # must return, not hang
assert len(out) <= d.EMBED_TEXT_CAP + 1                  # +1 for the trailing "…"
```
Run it under `timeout 5`.

### P0-2. a8432e6 changed extraction without bumping the version constants [verified] **[fixed, untested]**
`engine/import/streaming.py:13-15`. `FEATURE_VERSION = 'features-v2'` and
`IDENTIFIER_VERSION = 'identifiers-v2'` have not changed since 7c4aa10.

a8432e6 changed path templating, param extraction, `json_schema` depth and
ranking, `_html_blocks` (now 12-char md5 hashes instead of text),
`req_semantic`, and the identifier regexes. `rebuild_project`
(`import_project.py:226-260`) reuses cached `_features` whenever the version
string matches, so existing projects:
- keep old routes and params, and get no `req_semantic`;
- mix text-block and hash boilerplate sets. `html_page_summary`'s
  `h not in boilerplate` check (~1298/1310) never matches the old text entries,
  so boilerplate stripping silently stops;
- never get the new identifiers;
- report "Project indexes are current", because the `version` digest at
  `import_project.py:199` is unchanged.

Fix:
1. `streaming.py`: set `FEATURE_VERSION = 'features-v3'` and `IDENTIFIER_VERSION = 'identifiers-v3'`.
2. Add a comment above them: *"Bump whenever extract_features / identifier_pairs
   output can change (distill.py, normalize.py, parse.py)."*
3. Nothing else is needed. `resolve_features` already re-extracts on a version
   mismatch, and the `version` digest changes, so the "current" short-circuit
   no longer fires.
4. `findings.py:45` writes `identifier_state='complete'` with no version.
   Store `identifier_version=IDENTIFIER_VERSION` on attack rows as well, and
   make `repair_identifiers` treat a mismatch as stale.

Verify by rebuilding a project imported before this fix. Status should show the
new `index_version`, and `_features` on exchanges should carry
`feature_version=features-v3`.

### P0-3. The query tool passes every input field to every subcommand [verified]
`src/tools.ts:180-183` vs. argparse in `engine/query/agent_interface.py:506-553`.

`buildArgv` turns every non-empty input field into a flag. Each subparser only
accepts some of them, so for example `get`+`depth`, `similar`+`kind`,
`evidence`+`depth` or `record-attack`+`limit` make argparse exit 2 and print
usage text instead of JSON.

Fix: in `tools.ts`, add a per-command allow-list that mirrors `build_parser()`,
and filter `input` before calling `buildArgv`:
```ts
const COMMON = ["db_path"]
const LISTING = ["depth", "limit", "host", "path"]
const FILTERS = ["offset", "method", "status", "kind", "access_control", "access_class",
  "contains", "where", "vuln_class", "verdict", "severity", "anon", "auth", "cors_open",
  "include_static", "anon_matches_auth", "cookie_issues", "jwt", "param", "cookie", "missing_header"]
const QUERY_FIELDS: Record<string, string[]> = {
  endpoint: [...COMMON, "target", ...LISTING, "method", "no_raw", "raw_chars"],
  map: [...COMMON, ...LISTING, ...FILTERS],
  search: [...COMMON, "text", "collection", ...LISTING, ...FILTERS, "loose"],
  get: [...COMMON, "target", "original", "collection"],
  similar: [...COMMON, "target", "collection", ...LISTING],
  identifier: [...COMMON, "target", "offset", "limit"],
  evidence: [...COMMON, "target", "offset", "limit", "signal"],
  attacks: [...COMMON, ...LISTING, ...FILTERS],
  "record-attack": [...COMMON, "event_id", "vuln_class", "endpoint", "method", "param", "payload",
    "status", "severity", "source_id", "evidence", "tool", "request", "request_file",
    "response", "response_file", "verdict"],
}
```
Before writing the list, check every name against the current `build_parser()`.
Choose one way to handle fields that don't belong to the command:
- (a) drop them and add a `notes` entry; or
- (b) recommended: return `{"error": "field X is not valid for command Y"}`
  without spawning Python, so the model learns the right shape.

Also check the `similar` subcommand. `execute()` runs `build_where`/`post_filters`
for `similar`, but the parser defines none of those filter flags for it. Either
add the filter flags to the `similar` parser or stop building filters for it.

### P0-4. Positionals that start with `-` are read as flags [verified]
`src/tools.ts:55-58`. Positionals are pushed right after the subcommand, so a
target like `--x-api-key` or `-abc`, or search text like `-1 offset`, breaks
argparse.

Fix: in `buildArgv`, collect flags first, then append `"--"`, then the
positionals:
```ts
const flags: string[] = [], pos: string[] = []
// ...push positionals into pos, flags into flags...
return pos.length ? [...flags, "--", ...pos] : flags
```
argparse accepts `--` before positionals, including `search`'s `nargs='*'` text.
Apply the same change to the import tool's `buildArgv` call, since `abandon`
takes positionals.

### P0-5. Arrays passed to single-value flags lose all but the last item [verified]
`src/tools.ts:72-74`. `endpoint --method` and `record-attack --method/--param`
are plain `store` args, so repeating the flag keeps only the last value.

Fix, together with P0-3: keep a set of single-value fields per command. If the
input is an array:
- with one element, unwrap it;
- with more, return a JSON error (`"method takes one value for endpoint"`).

For `record-attack --param`, joining with `,` is also acceptable if the finding
schema treats it as free text. Decide which and document it in the field
description.

---

## Test-suite holes (fix before P1 so the fixes are covered)

### T-1. `fixture.py` caches on the capture sha only **[fixed, untested]**
`tests/fixture.py`: engine changes reuse a stale DB unless you pass `--fresh`,
which would have hidden P0-2. Add `streaming.FEATURE_VERSION`,
`IDENTIFIER_VERSION`, `PARSER_VERSION` and a hash of `engine/import/*.py` to the
cache key.

### T-2. A missing digest baseline passes silently [reported] **[fixed, untested]**
`tests/bench_perf.py:258-261`. When `*.digest.json` is missing, the gate writes
a new one and passes. Change it to: missing baseline and no `--update-baseline`
→ print an error and set `status = 1`.

### T-3. The `sync_identifiers` perf counter never fires [reported]
`tests/bench_perf.py:~105` patches `storage.sync_identifiers`, but
`import_project.py:17` and `findings.py:6` bind the name at import time. Patch
`(import_project, 'sync_identifiers')` and `(findings, 'sync_identifiers')`
instead, as the comment at line 103 already says to do for the other names.

### T-4. Duplicate entity check; `non_entities` never tested [reported]
`tests/bench_correctness.py:168-170` repeats `entities/count` (line 134).
Replace it with a check that every name in `ground_truth.json["non_entities"]`
is absent from the engine's entity list.

### T-5. The keyword oracle compares counts, not identities [reported]
`tests/bench_retrieval.py:157-164`. Compare sets of exchange ids:
`tp = len(want_ids & got_ids)`, precision `tp/len(got_ids)`, recall
`tp/len(want_ids)`, `exact = want_ids == got_ids`. Expect the tier-B baseline to
move; review it before `--update-baseline`.

### T-6. Tier A writes findings into the shared fixture [reported]
`tests/bench_correctness.py:341-363` (`check_findings`). Run `record-attack`
against a scratch copy (`shutil.copytree` of the fixture DB into a tempdir), or
delete the created finding ids afterwards.

### T-7. The hint parser drops tokens that contain spaces
`tests/bench_correctness.py:256` uses `hint.split()` and silently ignores tokens
without `=`. Once P1-4 lands, parse with `shlex.split(hint)` and fail on any
token after the command that has no `=`.

### T-8. New unit regressions
In `tests/test_units.py` (plain asserts, run from `run.sh` before the tiers):
- the `_fit` termination case (P0-1);
- variant signatures stable under key reordering (P1-1):
  `request_variant_signature('{"a":1,"b":2}', 'application/json') == request_variant_signature('{"b":2,"a":1}', 'application/json')`;
- `graphql_operation('type=query&x=1') == ''` (P1-6).

For the TS argv builder (P0-3/4/5): export `buildArgv` and add a small
`bun test` / `node --test` file. Cases: a dash-prefixed target, an extra field
for `get`, and `method: ["GET","POST"]` for `endpoint`.

---

## P1: correctness

### P1-1. Variant signatures depend on key order [reported, mechanism verified]
`distill.py:982` (`json_schema`) and `:1024` (`xml_schema`) now return
`_ranked_keys(...)`, which ranks by depth and keeps discovery order within a
depth. `request_variant_signature` (1072-1081) and `response_variant_signature`
(1084-1100) hash `','.join(keys)`. The same key set in a different order gives a
new variant, which burns the 12-variant cap.

Fix: hash `','.join(sorted(keys))` in both functions. Keep the ranked order for
the 40-key display cut. This also changes the extracted features, so it ships
with, or bumps again after, P0-2's version bump.

### P1-2. The diversity cap collapses distinct findings [verified]
`engine/query/retrieval.py:94-99`. Findings in `attacks` use the endpoint key,
so 3 findings on one route come back as 1 (quick depth) or 2 (normal depth).

Fix: next to the `entity`/`auth_model` exemption, add
```python
if meta.get('node_kind') in ('entity', 'auth_model') or collection == 'attacks':
    key += (result['id'],)
```
Pass `collection` into the function if it isn't already there.

### P1-3. Candidate expansion stops before diversity is applied [verified]
`retrieval.py:58-61`. `eligible` counts parents, but `max_per_endpoint` trims
later. On quick depth (limit 5, max 1), 6 parents on one endpoint satisfy the
check and the result list collapses to 1. The baseline already shows
`dropped_by_diversity: 8`.

Fix: count eligible results per diversity key, capped at `max_per_endpoint`. The
key needs the parent metadata. Either fetch the parents inside the loop (cost:
one `get_many` per widening step), or approximate with the hit's own
`scheme/host/port/method/endpoint_template` metadata, which segment and variant
docs carry (check this first). Expect tier-B numbers to improve; re-baseline
after review.

### P1-4. Hints with spaces can't be parsed back into tool calls [verified]
`engine/query/hints.py:15-21`. Values are rendered bare, so
`endpoint_report.py:461` (`target='<id value>'`) and `:497`
(`target='<one of did_you_mean>'`), and any path containing a space, split into
several tokens.

Fix: in `_render`, `parts.append(f'{key}={shlex.quote(str(value))}')`. Change
the two placeholder hints to real values, or move the placeholder text into
`notes`, as the hints.py docstring requires. Then apply T-7.

### P1-5. The loss ledger counts the wrong things [reported]
- `import_project.py:216` calls `d.ledger_reset()` inside `rebuild_project`,
  after `ingest()` has already counted `param_names_dropped`,
  `identifiers_dropped` and `schema_keys_dropped`. Move the reset to the start
  of the command in `main()`, before ingest.
- Cached features skip extraction, so those counters are 0 on a pure rebuild.
  Persist per-exchange extraction loss in `_features` (e.g. `_loss: {...}`) and
  add it up during `resolve_features`.
- `build_structure.py:365` (`build_segments`) calls `endpoint_chunk()` a second
  time, which double-counts `truncated.embed_*`. Pass the already-built chunk
  in, or snapshot and restore `LEDGER` around the second call.
- `json_schema` runs in both pass A and pass D for the same body; same remedy.

### P1-6. `graphql_operation` flags non-GraphQL bodies [verified]
`distill.py:428-450`. Any non-JSON body containing "query", "mutation" or
"subscription" (a form body like `type=query`, SOAP, multipart) produces an
operation. Batched GraphQL (a JSON array) is missed.

Fix:
```python
    try:
        obj = json.loads(req_body or '')
    except Exception:
        obj = None
    if isinstance(obj, list):
        obj = next((o for o in obj if isinstance(o, dict) and 'query' in o), None)
    if isinstance(obj, dict):
        query = str(obj.get('query', ''))
    elif obj is None and (content_type or '').lower().startswith('application/graphql'):
        query = req_body or ''
```
This needs `content_type` passed in from the caller. Keep the URL `?query=`
fallback, but only for paths that contain `graphql`.

### P1-7. `identifier_version` is written before the identifier rows exist [verified]
`import_project.py:153-162`. `put_records` stores
`identifier_version=IDENTIFIER_VERSION`, and then `sync_identifiers` runs. If
the process crashes between the two, rebuild treats the rows as current.

Fix: call `sync_identifiers(...)` before `put_records(exchanges, records)`.
Identifier rows only reference the exchange id; nothing enforces that the
exchange exists, so the order is safe. If the order has to stay, write
`identifier_version=''` in the record and `exchanges.update(...)` it after the
sync.

### P1-8. The import tool hides tracebacks and exit codes [reported]
`src/tools.ts:95`. When stdout is non-empty, stderr and `res.code` are dropped.
Fix:
```ts
const out = res.stdout.trim(), err = res.stderr.trim()
if (res.code !== 0) {
  return { content: JSON.stringify({ error: `exit code ${res.code}`, stdout: out.slice(-4000), stderr: err.slice(-4000) }) }
}
return { content: out || err || JSON.stringify({ ok: true }) }
```
Also make `import_project.py main()` wrap its body in a try/except that prints a
JSON `{"command":..., "error":...}` and exits 2, matching `agent_interface.py`.
Make `export` and `abandon` print a JSON result.

### P1-9. Multibyte UTF-8 corrupted across stdout chunks [reported]
`src/engine.ts:37-38`, `src/bootstrap.ts:13,25`. Before attaching the `data`
handlers, add `child.stdout.setEncoding("utf8"); child.stderr.setEncoding("utf8")`.

---

## P2: triage, cheap ones first

- **`--host` filter is case-sensitive.** `agent_interface.py:344-348`: lower-case
  `host` in `build_where`; import always stores it lower-case.
- **Pin `chromadb`.** `engine/requirements.txt` has it unpinned (in
  `requirements-viz.txt` too). The code relies on `list_collections()` returning
  objects with `.name`, which is true on 1.x and false on 0.6.x. Pin
  `chromadb>=1.0,<2`, and pin the others to known-good versions.
- **`status`/`export` take the exclusive writer lock.** `import_project.py:348`:
  use a shared/read lock (`fcntl.LOCK_SH`) or no lock, so `status` works during
  an import.
- **Query and import disagree on the DB location.** Query defaults to
  `./chroma_db` (`tools.ts:21,207`); import uses `<project_dir>/chroma_db`. Add
  a `project_dir` field to `jeb_query` that maps to `--db-path <project_dir>/chroma_db`.
  For `record-attack`, refuse to create a DB that doesn't exist (pass
  `create_if_missing=False` and fail when no `captures` collection exists).
- **`req_semantic` embeds raw values.** `normalize.py:90-91` →
  `distill.py:1527,1553`: OAuth `code`/`state` and OTP values reach the embed
  text. Drop `code` and `state` from `VARIANT_KEY_VALUES` for the embed path, or
  replace values with a shape tag such as `<token:32>`.
- **Identifier lookup normalization.** `agent_interface.py:427-434` vs.
  `distill.py:298-305`: lower-case hex/uuid values at store and lookup, and
  percent-decode path segments at store time. Needs another identifier version
  bump.
- **Header/body split with mixed line endings.** `parse.py:56-61,124-128`: find
  the *earliest* of `\r\n\r\n` and `\n\n` instead of preferring `\r\n\r\n`
  anywhere in the message.
- **`find_similar` can return the seed's own parent.** `agent_interface.py:207-218`:
  also exclude the seed's `parent_id`.
- **Missing DB reported as a miss.** `agent_interface.py:422-425`: on a missing
  DB, `get`/`similar` should return a "Project database does not exist" error,
  not "ID not found".
- **`--where '{}'`** is passed through and Chroma rejects it with an unclear
  error; skip empty dicts.
- **Cosine assumptions under other metrics.** `retrieval.py:28`,
  `embedding.py:35`: validate or reject `JEB_DISTANCE_METRIC != cosine`, since
  the cutoffs assume cosine.
- **`visualize.py:543-554`.** The docstring promises a host-less fallback that
  doesn't exist. Implement it (match on `(method, endpoint_template)`) or fix
  the docstring.
- **Bootstrap.** `bootstrap.ts:51-81`:
  - check Ollama with `fetch(ollamaUrl + "/api/tags")` and a timeout instead of
    shelling out to `ollama list`; match the full `name:tag`;
  - add a lockfile around venv creation and pip install;
  - give pip a timeout.
- **Config signature warns falsely.** `config.ts:34-38`: build the signature
  from *effective* values (defaults merged in), not from the options that happen
  to be set.
- **`install.sh`.** Line 80: `ollama list | grep -q` under `pipefail` can SIGPIPE
  and trigger a re-pull. Use `grep -q ... <<<"$(ollama list)"`. With `--copy`,
  exclude `engine/.venv`, `.git` and `tests`.
- **Unverified.** Does OpenCode v2 install `@opencode/plugin` for a symlinked
  plugin? Are the `plugins/` and `agents/` directory names, and the
  `opencode.jsonc` plugin key, correct for v2? Check the v2 docs.
- **Perf.** `load_many` base64-decodes and decompresses full bodies even when
  `hydrate_chunks` only needs the preview.

---

## Verification

Set up on the dev machine:
```bash
python3 -m venv engine/.venv
engine/.venv/bin/pip install -r engine/requirements.txt -r engine/requirements-viz.txt
ollama pull embeddinggemma-2:latest      # tiers B and C need Ollama running
```

Checks:
1. `timeout 5 engine/.venv/bin/python -c "import sys; sys.path.insert(0,'engine/import'); import distill as d; print(len(d._fit([('a'*1000,1400),('b'*1000,1400)])))"`
   must print a number at most `EMBED_TEXT_CAP + 1`. It hangs before P0-1.
2. `./tests/run.sh --fresh`: all tiers pass. P1-1, P1-3 and T-5 move tier-B/C
   numbers on purpose. Diff against `tests/baseline/` and only then run
   `--update-baseline`.
3. Rebuild a project imported before P0-2. `jeb_import command=status` should
   show the new index version and the loss ledger. Boilerplate should be
   stripped from HTML summaries.
4. In OpenCode, run `jeb_query` with `command=get depth=quick` (expect a clean
   error or the field dropped), `command=identifier target=-abc` (expect a JSON
   envelope) and `command=endpoint method=["GET","POST"]` (expect an error).
5. Run `jeb_import command=import` on a malformed XML. The tool output should
   include the exit code and the traceback tail.

---

## Knowledge-graph ingestion plan (implemented 2026-10-21; see Status above for what was deferred)

### Context

The ingestion pipeline (`engine/import/`) turns a Burp capture into two embedded
Chroma collections, and it fans each route out into many near-duplicate vectors:

- **structure**: per route, 1 parent + 2 segments (`identity`, `posture`); plus auth-model and entity parents, each with a segment that repeats the parent's text (`build_structure.build_segments`).
- **behavior**: per (route × status × auth role × access class × credential), 1 parent + 3 segments (`route`, `response`, `security`) + up to 12 embedded variants (`build_behavior.build/build_segments/build_variants`).
- The same facts are embedded many times. Route words, params and the security clause appear in the structure parent, the structure segments, the behavior parent, the behavior `route` segment and every variant.
- The fixture's 296 exchanges produce **717 embedded records** (279 structure + 438 behavior). Embedding is about 29 of the 34 s import (`tests/baseline/perf.json`).
- Long pages are not split. They are **cut**: `html_page_summary` keeps a lead of at most 600 chars inside a 1500-char `EMBED_TEXT_CAP`. Most of a long page never reaches the index, even though EmbeddingGemma accepts 2048 tokens.
- Relationships already exist, but only as CSV strings in metadata (`entity_ids`, `example_ids`, `variant_ids`, `produced_by`) or are rebuilt on the fly (the `visualize.py` path trie, the `endpoint_report` parent scan). Nothing can traverse them.

**Goal:** one embedded node per real thing, typed by an explicit ontology, connected by stored edges. Each node's embed text is enriched with context from its graph neighbours. Long pages are represented in full by one node, or by a few heading sections when they don't fit.

**Decisions (confirmed with the user):** edges go in a Chroma lookup collection, so the store stays Chroma-only. `structure` and `behavior` are replaced by a single `graph` collection, and the old names stay as aliases for one release. A page is one node and is split into sections only if it is over budget; identical sections are shared across pages. Enrichment is deterministic graph context, with no LLM.

### Architecture

#### Ontology (T-box): `engine/import/ontology.py` (new)
These constants define the node classes, the edge relations with their domain and range, and `ONTOLOGY_VERSION`. The graph builder checks every edge against them. Pages and routes are the ontology/container level. Content chunks are the entity instances under them.

| Class | Embedded? | Id (keep existing ids where they exist) | Absorbs today's |
|---|---|---|---|
| `Origin` | yes | `md5(origin|auth_model)` | auth_model parent + segment |
| `Route` (`route_kind`: page / action / endpoint / asset); `Page` ⊂ `Route` | yes | `build_structure.endpoint_chunk` id | structure parent + identity/posture segments |
| `Behavior` | yes | `d.behavior_id` (findings' `source_behavior_id` keeps resolving) | behavior parent + 3 segments + embedded variants |
| `Section` | yes | `md5(origin|normalized section text)`, so it is shared across pages | the truncated HTML lead |
| `Form` | yes | `md5(origin|method|action template|sorted fields)` | form strings in the HTML summary |
| `DataObject` | yes | `md5("entity|"+sig)` (same as the entity id today) | entity parent + segment; carries `shared=true` when seen at 2 or more routes |
| `Posture` | yes | `md5(sorted missing headers, cors, cookie flags, tech)` | posture/security clauses repeated per record |
| `param:<name>`, `cookie:<name>` | no (literal ids, edge targets only) | n/a | `param_names` and `cookies_*` CSV |
| `Exchange`, `Finding` | existing `exchanges` and `attacks` | unchanged | `example_ids`, `variant_ids` lists |

Relations: `HAS_ROUTE` (Origin→Route), `CHILD_OF` (Route→nearest ancestor Route), `HAS_BEHAVIOR` (Route→Behavior), `RETURNS` (Behavior→DataObject), `ACCEPTS` (Route→DataObject | param), `CONTAINS` (Page→Section, ordered by `ord`; Page→Form), `LINKS_TO` (Page→Route), `SUBMITS_TO` (Form→Route), `HAS_FIELD` (Form→param), `CALLS` (asset Route or Page→Route, including stub routes with `observed=false`; from `jsfacts`), `LOADS` (Page→asset Route), `HAS_POSTURE` (Route→Posture), `SETS_COOKIE` / `SENDS_COOKIE` (Route→cookie), `RELATED` (DataObject↔DataObject, weight = Jaccard), `OBSERVED_IN` (Behavior→Exchange, with `variant_key`), `TARGETS` (Finding→Route).

#### Storage
- `graph`: embedded collection (EmbeddingGemma, cosine). One record per embedded node. Metadata keeps today's filter facets (host, method, template, status, access_control, cookies, …) plus `node_type`, `route_kind`, `anchor_id` (the owning Route; for a shared Section, its first page) and `context` (the enrichment header). Written by the unchanged `vector_store.store`, so content-hash skipping and the two embed workers still apply.
- `edges`: new lookup collection (fixed 1-d vectors, no Ollama), like `identifiers`. Id is `md5(src|rel|dst)`. Metadata is `src, src_type, rel, dst, dst_type, weight, ord, variant_key`. One hop is `edges.get(where={'src': {'$in': ids}})`, or the same on `dst`.
- `structure` and `behavior` are deleted after `graph` and `edges` are written successfully. `attacks`, `captures`, `exchanges` and `identifiers` are unchanged. Bump `COLLECTION_SCHEMA` to `jeb-v7-graph`.

#### Long pages: segmentation that doesn't depend on heading tags
Real sites lay content out with divs, put it in script blocks, or render it client-side, so heading tags can't decide where to split. A new module, `engine/import/segment.py`, runs four layers in order over the BeautifulSoup tree that `_html_view` already parses once per body.

1. **Script-embedded data first.** Parse `<script type="application/ld+json">`, `type="application/json"`, `__NEXT_DATA__`, `__NUXT__` and `window.__INITIAL_STATE__ = {…}`-style assignments with the existing `json_schema` / `structured_semantic_values`.
   - Each payload becomes a `DataObject` (same signature scheme as API responses, so a page and its API share one node) linked by `Page -RETURNS-> DataObject`.
   - Inline JS goes through `_script_endpoints` and becomes `CALLS` edges.
   - This covers SPA and hydration pages, where the visible DOM is a shell.
2. **Boilerplate removal by cross-page subtree diff.** Today's text-block hashes (`_html_blocks`, `normalize.pass_c_boilerplate`) are extended to **subtree hashes**: `md5(tag path + normalized text)` for each block-level subtree.
   - A subtree is template if it appears on more than `BOILERPLATE_FRACTION` of a host's page routes, or on every instance of one route template.
   - This detects chrome even when nav/footer/aside tags are missing. The existing tag-based removal stays as a cheap first pass.
   - `_html_blocks` is persisted in `_features`, so this needs a `FEATURE_VERSION` bump.
3. **Repeated-structure collapse.** Sibling subtrees with the same shape signature (tag + sorted class tokens + child tag sequence), when there are `REPEAT_MIN` (3) or more of them, become one `Section` with `section_kind=listing`.
   - Its text holds the item template (field labels and link targets), the item count and 2–3 sample items.
   - Cards, table rows, search results and long lists become one node instead of many.
4. **DOM budget-fit split.** Walk the cleaned tree from `main` / `[role=main]` / `article` / `body`.
   - A subtree whose visible text fits `SECTION_CAP` (~2500 chars) becomes one chunk.
   - An oversized subtree is recursed into, and adjacent small children are merged greedily up to the cap (`SECTION_MIN_CHARS` ~300, so a chunk is never a lone button).
   - Headings don't decide splits. A chunk's **label** comes from the first heading-like descendant (`h1–h6`, `[role=heading]`, `legend`, `caption`, `summary`, a leading `strong`/`b`, or a class/id containing `title`/`header`), falling back to `id`/`aria-label`.
5. **Text-window fallback.** If one leaf block still exceeds `SECTION_CAP`, because the DOM is flat (a single div, or text joined by `<br>`), split it into windows of `SECTION_CAP` with ~10% overlap, breaking at sentence boundaries where possible.

Then the page is assembled:
- If the whole cleaned text fits `PAGE_EMBED_CAP` (~4000 chars, about 1k tokens, well inside EmbeddingGemma's 2048), the **Page node holds everything** and no Section nodes are made.
- Otherwise the Page node keeps the title, the outline of chunk labels and a lead. Each chunk becomes a `Section` (`section_kind`: block / listing / window, `ord` on its `CONTAINS` edge), capped at `MAX_SECTIONS_PER_PAGE` (8, ranked by text length). Anything dropped is counted in `LEDGER`.
- A Section's id hashes its normalized text, so identical content on several pages is one node with several `CONTAINS` edges.

Everything is deterministic: no embedding calls are used to pick boundaries, which keeps the bit-identical export gate.

#### Long JavaScript bundles
**Today:** `static_asset_summary` scans the first 2 MB (`STATIC_SCAN_CHARS`) of a bundle and keeps 15 endpoint-like strings and 6 credential-assignment names. The result is one ≤400-char label. Everything past the cap, and every second-order fact, is lost. (The full body is still recoverable from `raw_base64`, so this is an extraction limit, not a storage limit.)

**Approach:** extract facts and keep code out of the index. Minified code embeds poorly and splitting it into text chunks would multiply vectors for little recall, so a bundle is never cut into text chunks. A new module, `engine/import/jsfacts.py`, turns a bundle into graph facts:

1. **Lex string literals across the whole body.** A small hand-written scanner understands `'…'`, `"…"`, template literals (with `${…}` replaced by `{param}`), escapes and comments, so the regex can't match across string boundaries.
   - It streams over the body in windows. There is a hard cap `JS_SCAN_CHARS` (8 MB) and a cap on literals; the ledger counts what is skipped.
   - No JS parser dependency is needed. (Optional later: `tree-sitter-javascript`, if call-site accuracy proves insufficient.)
2. **Classify each literal:**
   - **Endpoint**: a relative path, an absolute URL, or a GraphQL document (`query X {`, `mutation`). Run it through `templatize_path`. Look back ~80 chars for a call site (`fetch(`, `axios.`, `.get(`/`.post(`, `method:"PUT"`) to infer the method; otherwise the method is `ANY`.
   - **External origin**: a third-party host. It becomes an `Origin` node with `observed=false`.
   - **Credential-shaped**: the existing `_CREDENTIAL_ASSIGN_RE` names, plus known key shapes (`AKIA…`, `AIza…`, `sk_live_…`, `ghp_…`, JWTs). Only the name and value shape (`<aws-key:20>`) go into node text. The value goes into the `identifiers` lookup, so `jeb_query command=identifier` finds it, and the raw value stays in the exchange.
   - **Config keys**: object keys under `__CONFIG__` / `env` / `process.env.*`-style assignments, and feature-flag names. They are recorded as fields on the Asset node.
3. **Graph output:**
   - The bundle is one `Route` (`route_kind=asset`) node. Its text holds the library fingerprints (from `/*! name vX.Y */` banners and `@license` headers → `lib:<name>@<ver>` literal ids, which are also added to `tech`), the source-map URL, counts per fact class, and the top endpoints.
   - `CALLS` edges go to every endpoint. An endpoint that matches no observed route creates a **stub `Route` with `observed=false`**. Stubs are embedded with a tiny text, capped at `MAX_STUB_ROUTES_PER_HOST` (200, ranked by the number of bundles referencing them, overflow in the ledger). This makes "routes the client knows about but the capture never hit" searchable and mappable (`map kind=endpoint observed=false`).
   - Identical bundles (same `resp_body_sha256`) are one node, linked from every page that loads them (`Page -LOADS-> asset Route`, from `<script src>` in `_page_artifacts`).
4. **Module grouping, only when names exist.**
   - If a bundle has named modules (webpack dev builds: `"./src/api/user.js": function…`), or a captured `.map` file supplies `sources`, the facts are grouped per module.
   - Only modules that produced facts become `Section` nodes (`section_kind=module`, label = the source path), capped at `MAX_MODULES_PER_BUNDLE` (20).
   - Minified production bundles with numeric module ids stay one Asset node.
   - With a captured source map, `sourcesContent` (real, readable code) is run through the same extractor per original file. Its text is still not embedded verbatim.
5. **Inline scripts** in HTML pages use the same extractor (replacing the 6-endpoint `_page_artifacts` scan). Their facts attach to the Page node.

#### Enrichment
Build the graph in two passes: first assemble the nodes and edges in memory, then render the text.
- Each node gets a context header built from its 1-hop neighbours, such as: `page GET /account/settings @ app.example · title "Settings" · forms: change-password → POST /account/password · returns: user(id,email) · posture: missing content-security-policy`.
- The header goes into the existing `embedding_title` slot (`embedding.doc_prefix` already prompts EmbeddingGemma with `title: … | text: …`) and into `metadata.context`.
- The node's own text holds only what is specific to the node. Facts that are shared live once, on the `Posture`, `DataObject` and `Origin` nodes, and are reached through edges. This is what removes the duplication.
- Keep the retrieval vocabulary expansions (`header_words`, `cors_words`, `ACCESS_*_WORDS`, `method_words`), and fit text with `_fit` (after the P0-1 fix below).

#### Retrieval
- `retrieval.search` queries `graph` and maps each hit to its result unit:
  - the node itself, plus its `anchor` Route;
  - for a `Posture` or `DataObject` hit, the list of linked routes (bounded).
- Diversity is keyed on `anchor_id`. Findings and the synthetic nodes are exempt. This replaces the segment→parent collapse and resolves TODO P1-2/P1-3 by construction.
- Each result carries a bounded `neighbors` summary (one `edges.get`, one `graph.get`).

### Implementation phases

**Phase 0: prerequisites from the bugfix plan above.** (P0-1, P0-2, T-1, T-2 are fixed but untested; see the handoff status.) These touch the same code, so land them first, one commit each:
- P0-1: `_fit` termination.
- P0-2: version bumps.
- T-1: the fixture cache key includes the engine hash, otherwise graph changes are invisible to `run.sh`.
- T-2: a missing digest baseline fails.
- P1-1 (sorted variant signatures) can wait, because variants stop being embedded.

**Phase 1: ontology and graph builder (pure, no Chroma).**
- New `engine/import/ontology.py` and `engine/import/build_graph.py`. `build_graph(annotated, models) -> (nodes, edges)` reuses:
  - `build_structure.build_endpoint_nodes`, `build_entities` and `_dominant_schema`;
  - `build_behavior._representative`, `_variant_groups` and `_parent_metadata`;
  - `d.behavior_collapse_key`, `d.behavior_variant_key`, `d.templatize_path` (to resolve link and form targets to known route templates on the same origin) and `normalize.build_auth_models`.
- `CHILD_OF`: port the trie logic from `visualize.py:577-603`.
- Validate every edge against the ontology.

**Phase 2: page content extraction (`engine/import/segment.py`, new).**
- Implement the five layers above as pure functions over a soup: `script_payloads`, `subtree_hashes`, `collapse_repeats`, `fit_split` and `window_split`, plus `segment_page(body, boilerplate) -> {title, outline, lead, chunks, payloads, forms, links}`.
- `distill._html_view` calls `subtree_hashes` so the page is still parsed only once (the `html.parse` call count in tier C must not rise). Structured forms (`method`, `action`, `fields`) and raw link hrefs are returned next to today's display strings.
- `normalize.pass_c_boilerplate` works on subtree hashes and adds the per-route-template rule. Bump `FEATURE_VERSION`.
- Segmentation needs the body. Run it in `streaming.annotate_features`, where `_resp_body` is already loaded per batch, and keep the results on the annotated record (`a['_segments']`). Pop them once the graph is built.
- New constants in `distill.py`: `PAGE_EMBED_CAP`, `SECTION_CAP`, `SECTION_MIN_CHARS`, `MAX_SECTIONS_PER_PAGE`, `REPEAT_MIN`. `_LEAD_SCAN_CHARS` stays the hard read bound.

**Phase 2b: JavaScript facts (`engine/import/jsfacts.py`, new).**
- Implement `lex_strings(body, limit)`, `classify(literal, lookbehind)`, `library_banners(body)`, `webpack_modules(body)` and `sourcemap_facts(map_json)`, plus `js_facts(body, ct) -> {libs, endpoints[(method, template, module)], origins, secrets[(name, shape, value)], config_keys, sourcemap_url, modules}`.
- Call it from `distill.distill_response` for `static_asset` JS (replacing `static_asset_summary`'s scan), and from `segment_page` for inline scripts.
- Compact facts go into `_features` (bump `FEATURE_VERSION`). Secret values go through `identifier_pairs` (bump `IDENTIFIER_VERSION`).
- `.map` responses are paired with their bundle in `build_graph` by the `sourceMappingURL` match.
- New constants: `JS_SCAN_CHARS`, `JS_LITERAL_CAP`, `MAX_STUB_ROUTES_PER_HOST`, `MAX_MODULES_PER_BUNDLE`. `STATIC_SCAN_CHARS` / `STATIC_ENDPOINT_CAP` go away.

**Phase 3: text rendering and enrichment.**
- In `distill.py`, add `graph_node_text(node)` and `graph_context(node, neighbors)` per class. These replace `structure_embed_text`, `structure_segment_texts`, `behavior_embed_text`, `behavior_segment_texts`, `entity_embed_text` and `auth_model_embed_text`; delete those once the callers are gone.
- Summaries (`*_summary`) stay as the compact one-liners.

**Phase 4: storage wiring.**
- `storage.py`: add `'edges'` to `LOOKUP_COLLECTIONS`, and add `sync_edges(client, edges)`. It should upsert in batches and reconcile (delete ids not in the wanted set), mirroring `store(..., reconcile=True)`.
- `import_project.rebuild_project`:
  - replace `structure_chunks` / `behavior_chunks` with `build_graph`, then `store(semantic_collection(client,'graph',ef,True), hydrate_chunks(...))` (Behavior nodes keep raw evidence in `page_content`), then `sync_edges`;
  - after both succeed, delete `structure` and `behavior` if present;
  - update `EMBEDDED_COLLECTIONS`, `collection_counts` and `profiles_ok`;
  - the `version` digest includes `ONTOLOGY_VERSION`;
  - add ledger counters: `graph.nodes.<type>`, `graph.edges.<rel>`, `pages.sectioned`, `sections.shared`, `sections.dropped_by_cap`.
- `findings.py` / `migrate_attacks`: write a `TARGETS` edge per finding. `repair_identifiers` also repairs missing `TARGETS` edges.

**Phase 5: query side.**
- `agent_interface.py`:
  - `COLLECTIONS = ('graph', 'attacks')`. `structure` and `behavior` become aliases that add a `node_type $in` filter and a note to the response.
  - `has_segments` becomes node-type logic.
  - add a `graph` subcommand: `target`, `rel?`, `direction` (out/in/both), `depth` ≤ 2, `limit`.
  - `map kind=` gains page / form / data_object / posture / section.
- `retrieval.py`: anchor mapping, diversity and neighbours, as above.
- `endpoint_report.py`: build the report from `HAS_BEHAVIOR` / `RETURNS` / `CONTAINS` / `HAS_POSTURE` edges instead of `parent_index()` scans and `example_ids`.
- `hints.py`: add `graph` follow-ups (for example, from a Page to its forms).
- `src/tools.ts`: collection enums, the new command and fields (fold into the P0-3 allow-list).
- Update `agents/jebediah.md` and `README.md` (collections table, tools, design).

**Phase 6: visualize.** `visualize.py` graph mode reads `graph` + `edges` directly. Delete the trie reconstruction and the `entity_links` parsing.

**Phase 7: tests and baselines.**
- `tests/make_capture.py`: add pages that exercise every segmentation layer, each with needle text deep inside, and emit the expected nodes, edges and chunk labels into `ground_truth.json`:
  - a long **div-only** page with no h-tags, over `PAGE_EMBED_CAP`;
  - a **flat** page (one div, `<br>`-separated text), to trigger the window fallback;
  - a **listing** page with 30 cards, which must become one listing Section;
  - a **hydration** page whose content is only in `__NEXT_DATA__` / JSON-LD, which must become a DataObject shared with its API route;
  - chrome **without nav/footer tags** repeated across pages, which must be stripped by the subtree diff;
  - a shared widget on several pages, which must become one shared Section;
  - a form whose action resolves to a known route;
  - a **>2 MB minified bundle** with endpoints and a fake `AKIA…` key placed past the old 2 MB cap, a `/*! react v18.2.0 */` banner, and endpoints that were never requested. Expect `CALLS` edges, stub routes with `observed=false`, the key found by `command=identifier`, and `lib:react@18.2.0`;
  - a **webpack dev bundle** with named modules plus a captured `.map`. Expect module Sections only for modules that have facts;
  - the same bundle loaded by 3 pages. Expect one Asset node and 3 `LOADS` edges.
- Tier A (`bench_correctness.py`):
  - node counts per type;
  - the edge sets for the known routes (`SUBMITS_TO`, `RETURNS`, `LINKS_TO`, `CHILD_OF`);
  - shared-section dedupe;
  - the `graph` command's schema and hints.
- Unit tests for `jsfacts.py`: the lexer on escapes, template literals, comments and regex-like `/…/` strings; method inference from call sites; no secret value ever appears in node text.
- Unit tests for `segment.py` on small HTML strings: each layer in isolation, determinism (same input gives the same chunks and ids), and that no chunk exceeds `SECTION_CAP`.
- Tier B (`bench_retrieval.py`): add graded needle queries, one per new page shape (div-only, flat, listing, hydration). Map each query's `in` to `graph` plus its alias.
- Tier C (`bench_perf.py`): report embedded record counts per collection; patch `build_graph` phases.
- Review the diffs, then `--update-baseline`.

### Success criteria (fixture)
- Embedded records drop from 717 to roughly half or fewer. Report the actual number; the target is ≤ 400.
- The `store` phase time drops roughly in proportion.
- Tier B recall@k and nDCG stay at or above their current floors. The new needle queries (div-only, flat, listing, hydration pages) hit at rank ≤ 3. The tier C `html.parse` count does not increase.
- Tier A passes, including the existing entity grouping, `related` scores and access-control classification, which carry over through `DataObject` and `Route`.
- `command=rebuild` on a pre-graph project keeps finding IDs, creates `graph` + `edges`, and removes `structure` + `behavior`.

### Verification
1. `engine/.venv/bin/python -m pytest`-style unit checks in `tests/test_units.py` (from T-8): `build_graph` on a hand-built annotated list. Checks: every edge passes the ontology, ids are stable across two runs, and shared sections dedupe.
2. `./tests/run.sh --fresh`: all three tiers. Compare against `tests/baseline/`, then `--update-baseline`.
3. Take a copy of a project built before this change and run `jeb_import command=rebuild`. `command=status` should show `graph` and `edges` under embedded/lookup, no `structure`/`behavior`, the ledger graph counters, and unchanged `attacks` ids.
4. In OpenCode:
   - `jeb_query command=search text="..." collection=behavior` should work through the alias with a note;
   - `command=graph target=<page id>` should list its sections and forms;
   - `command=endpoint target=/login` should show behaviors, forms, posture and data objects from edges;
   - `jeb_visualize mode=graph` should render from the stored edges.
