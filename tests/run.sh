#!/usr/bin/env bash
# Run the J.E.B.E.D.I.A.H. benchmark suite.
#
#   ./tests/run.sh                 offline unit/contract tests (no model calls)
#   JEB_TEST_LIVE=1 ./tests/run.sh --live   all tiers, Qwen3-Embedding-8B ONLY
#   ./tests/run.sh --tier a        one tier (repeatable: --tier a --tier b); u = unit checks
#   ./tests/run.sh --fresh         discard the cached project and re-import
#   ./tests/run.sh --update-baseline   re-record tier B metrics and tier C digests
#   ./tests/run.sh --verbose       per-query detail
#
# Tier A fails on any changed derived fact. Tier B fails only below a metric
# floor. Tier C fails only if a stored record changed; timings are reported.
#
# Use --fresh after changing anything in the ingest path (parse.py, and the
# feature extraction in distill.py/normalize.py/streaming.py). Those results are
# persisted per observation as `_features` and a rebuild reuses them, so without
# a re-import the suite will not see the change at all.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(dirname "$here")"
python="$repo/engine/.venv/bin/python"
[ -x "$python" ] || python="$(command -v python3)"

tiers=()
fresh="" verbose="" update="" perf_extra="" live=""
while [ $# -gt 0 ]; do
  case "$1" in
    --tier) tiers+=("$2"); shift 2 ;;
    --fresh) fresh="--fresh"; shift ;;
    --verbose) verbose="--verbose"; shift ;;
    --update-baseline) update="--update-baseline"; shift ;;
    --skip-import) perf_extra="--skip-import"; shift ;;
    --live) live=1; shift ;;
    -h|--help) sed -n '2,/^set -euo/{/^#/s/^# \{0,1\}//p;}' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
if [ ${#tiers[@]} -eq 0 ]; then
  if [ -n "$live" ]; then tiers=(u a b c); else tiers=(u); fi
fi
export JEB_TEST_MODE=unit ANONYMIZED_TELEMETRY=False

if [ ! -f "$here/capture.xml" ] || [ ! -f "$here/ground_truth.json" ]; then
  echo "== generating the test artifact =="
  "$python" "$here/make_capture.py"
fi

# Tier U needs no database: pure-function checks and the TypeScript argv/config tests.
run_units() {
  echo "tier U: unit checks"
  "$python" "$here/test_units.py" || return 1
  "$python" -m unittest discover -s "$here" -p 'test_*.py' || return 1
  if command -v node >/dev/null 2>&1 && [ -x "$repo/node_modules/.bin/tsc" ]; then
    local out; out="$(mktemp -d "$repo/tests/.ts-build.XXXXXX")"
    "$repo/node_modules/.bin/tsc" -p "$repo" --noEmit false --outDir "$out" || { rm -rf "$out"; return 1; }
    JEB_TS_OUT="$out" node --test "$here"/ts/*.test.mjs; local rc=$?
    rm -rf "$out"; return $rc
  fi
  echo "TypeScript tests require npm ci (node or local tsc missing)" >&2
  return 1
}

# One import shared by every tier; only tier C builds its own for cold timings.
needs_db=""
for tier in "${tiers[@]}"; do case "$tier" in u|U) ;; *) needs_db=1 ;; esac; done
if [ -n "$needs_db" ]; then
  # Configure the parent too: Tier C instruments the engine in this process.
  export JEB_TEST_MODE=live-qwen
  export JEB_EMBEDDING_PRESET="${JEB_EMBEDDING_PRESET:-litellm-qwen3-embedding-8b}"
  export JEB_EMBEDDING_MODEL="${JEB_EMBEDDING_MODEL:-qwen3-embedding-8b}"
  export JEB_EMBEDDING_DIMENSIONS="${JEB_EMBEDDING_DIMENSIONS:-4096}"
  "$python" "$here/fixture.py" ${fresh:+--fresh}
fi

status=0
# Units first, so a pure-function failure is not buried under database output.
for tier in "${tiers[@]}"; do
  case "$tier" in u|U) run_units || status=1 ;; esac
done
for tier in "${tiers[@]}"; do
  echo
  case "$tier" in
    u|U) ;;
    a|A) "$python" "$here/bench_correctness.py" $verbose || status=1 ;;
    b|B) "$python" "$here/bench_retrieval.py" $verbose $update || status=1 ;;
    c|C) "$python" "$here/bench_perf.py" $update $perf_extra || status=1 ;;
    *) echo "unknown tier: $tier" >&2; exit 2 ;;
  esac
done

echo
[ $status -eq 0 ] && echo "suite: all selected tiers passed" || echo "suite: FAILURES above"
exit $status
