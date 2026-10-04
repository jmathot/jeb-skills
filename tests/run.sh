#!/usr/bin/env bash
# Run the J.E.B.E.D.I.A.H. benchmark suite.
#
#   ./tests/run.sh                 all three tiers against the cached fixture
#   ./tests/run.sh --tier a        one tier (repeatable: --tier a --tier b)
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
fresh="" verbose="" update="" perf_extra=""
while [ $# -gt 0 ]; do
  case "$1" in
    --tier) tiers+=("$2"); shift 2 ;;
    --fresh) fresh="--fresh"; shift ;;
    --verbose) verbose="--verbose"; shift ;;
    --update-baseline) update="--update-baseline"; shift ;;
    --skip-import) perf_extra="--skip-import"; shift ;;
    -h|--help) sed -n '2,/^set -euo/{/^#/s/^# \{0,1\}//p;}' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
[ ${#tiers[@]} -eq 0 ] && tiers=(a b c)

if [ ! -f "$here/capture.xml" ] || [ ! -f "$here/ground_truth.json" ]; then
  echo "== generating the test artifact =="
  "$python" "$here/make_capture.py"
fi

# One import shared by every tier; only tier C builds its own for cold timings.
"$python" "$here/fixture.py" ${fresh:+--fresh}

status=0
for tier in "${tiers[@]}"; do
  echo
  case "$tier" in
    a|A) "$python" "$here/bench_correctness.py" $verbose || status=1 ;;
    b|B) "$python" "$here/bench_retrieval.py" $verbose $update || status=1 ;;
    c|C) "$python" "$here/bench_perf.py" $update $perf_extra || status=1 ;;
    *) echo "unknown tier: $tier" >&2; exit 2 ;;
  esac
done

echo
[ $status -eq 0 ] && echo "suite: all selected tiers passed" || echo "suite: FAILURES above"
exit $status
