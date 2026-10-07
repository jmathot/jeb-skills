# Bugfix plan

Found in a review of `plugin` @ a8432e6 (2026-10-06). Line numbers refer to that
commit. Status tags: **[verified]** means checked by hand against the code
(and for P0-1, reproduced); **[reported]** means it came from a read-only sweep
and should be re-checked before fixing.

Work order: P0 → test-suite holes → P1 → P2. Use one commit per item. After any
change to the ingest path, run `./tests/run.sh --fresh` (see "Verification").

---

## P0: fix first

### P0-1. `_fit()` never terminates once embed text is over the cap [verified]
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

### P0-2. a8432e6 changed extraction without bumping the version constants [verified]
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

### T-1. `fixture.py` caches on the capture sha only
`tests/fixture.py`: engine changes reuse a stale DB unless you pass `--fresh`,
which would have hidden P0-2. Add `streaming.FEATURE_VERSION`,
`IDENTIFIER_VERSION`, `PARSER_VERSION` and a hash of `engine/import/*.py` to the
cache key.

### T-2. A missing digest baseline passes silently [reported]
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
ollama pull embeddinggemma:latest      # tiers B and C need Ollama running
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
