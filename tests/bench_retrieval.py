"""Tier B: retrieval quality. Metrics, with generous floors.

Semantic retrieval is graded against the authored query set in
tests/ground_truth.json; keyword retrieval is graded against an independent
decoder over tests/capture.xml that never touches the engine. The run fails only
when an aggregate metric drops below its committed floor -- HNSW query is
approximate, so exact-score assertions would force constant re-baselining.

    python3 tests/bench_retrieval.py [--update-baseline] [--verbose]
"""
import argparse
import base64
import json
import math
import os
import re
import sys

import fixture

TESTS = os.path.dirname(os.path.abspath(__file__))
BASELINE = os.path.join(TESTS, 'baseline', 'retrieval.json')
DEPTH_K = {'quick': 5, 'normal': 8}


# --- reference resolution -------------------------------------------------
def entity_names(manifest):
    """schema_sig -> entity name, by matching the authored field sets."""
    by_fields = {tuple(e['fields']): e['name'] for e in manifest['entities']}
    out = {}
    page = fixture.query(['map', '--kind', 'entity', '--limit', '100'])
    for row in page['results']:
        document = fixture.query(['get', row['id'], '--in', 'structure'])['document']['document']
        fields = tuple(re.search(r'^fields: (.*)$', document, re.M).group(1).split(', '))
        out[row['schema_sig']] = by_fields.get(fields, f'unknown:{row["schema_sig"][:8]}')
    return out


def result_ref(row, sigs):
    """The relevance key a result answers to."""
    kind = row.get('node_kind')
    if kind == 'entity':
        return 'entity:' + sigs.get(row.get('schema_sig', ''), '?')
    if kind == 'auth_model':
        return 'auth_model'
    return (f"{row.get('method', '')} {row.get('scheme', '')}://{row.get('host', '')}"
            f":{row.get('port', '')}{row.get('endpoint_template', '')}")


# --- metrics --------------------------------------------------------------
def dcg(grades):
    return sum(g / math.log2(i + 2) for i, g in enumerate(grades))


def score_query(spec, rows, k, sigs):
    """Graded metrics for one result list. Repeat refs score once."""
    relevant = spec['relevant']
    seen, grades, first_hit = set(), [], None
    for position, row in enumerate(rows[:k]):
        ref = result_ref(row, sigs)
        grade = relevant.get(ref, 0) if ref not in seen else 0
        seen.add(ref)
        grades.append(grade)
        if grade and first_hit is None:
            first_hit = position + 1
    found = {r for r in seen if r in relevant}
    ideal = sorted(relevant.values(), reverse=True)[:k]
    return {
        'recall': len(found) / len(relevant),
        'precision': sum(1 for g in grades if g) / max(1, len(grades)),
        'mrr': 1.0 / first_hit if first_hit else 0.0,
        'ndcg': dcg(grades) / dcg(ideal) if dcg(ideal) else 0.0,
        'hit': 1.0 if first_hit else 0.0,
        'found': sorted(found),
        'missed': sorted(set(relevant) - found),
    }


def mean(values):
    return sum(values) / len(values) if values else 0.0


def percentile(values, fraction):
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(fraction * len(ordered)))]


# --- semantic ------------------------------------------------------------
DIAGNOSTIC_KEYS = ('candidates', 'eligible_after_filter', 'dropped_by_distance',
                   'dropped_by_diversity', 'dropped_by_post_filter')


def run_semantic(manifest, sigs, verbose):
    out = {}
    for depth, k in DEPTH_K.items():
        per_query, distances, diagnostics, fallback_only = [], [], {}, 0
        for spec in manifest['queries']:
            argv = ['search', spec['q'], '--in', spec['in'], '--depth', depth]
            if spec.get('include_static'):
                argv.append('--include-static')
            payload = fixture.query(argv)
            scored = score_query(spec, payload['results'], k, sigs)
            scored['q'], scored['in'] = spec['q'], spec['in']
            per_query.append(scored)
            distances.extend(r['distance'] for r in payload['results'])
            for key in DIAGNOSTIC_KEYS:
                diagnostics[key] = diagnostics.get(key, 0) + payload['diagnostics'].get(key, 0)
            if not payload['results'] and payload.get('fallback'):
                fallback_only += 1
            if verbose:
                print(f"  [{depth}] recall={scored['recall']:.2f} ndcg={scored['ndcg']:.2f} "
                      f"mrr={scored['mrr']:.2f}  {spec['q'][:46]}")
                if scored['missed']:
                    print(f"           missed: {scored['missed'][:4]}")
        out[depth] = {
            'queries': len(per_query),
            'recall': round(mean([q['recall'] for q in per_query]), 4),
            'precision': round(mean([q['precision'] for q in per_query]), 4),
            'mrr': round(mean([q['mrr'] for q in per_query]), 4),
            'ndcg': round(mean([q['ndcg'] for q in per_query]), 4),
            'hit_rate': round(mean([q['hit'] for q in per_query]), 4),
            'distance_mean': round(mean(distances), 4),
            'distance_p90': round(percentile(distances, 0.9), 4),
            'fallback_only_queries': fallback_only,
            'diagnostics': diagnostics,
            'per_query': per_query,
        }
    return out


# --- keyword -------------------------------------------------------------
def oracle_hits(needle):
    """Count capture items containing `needle`, decoding the XML independently.

    Deliberately does not import distill/normalize: if this agreed with the
    engine by sharing its decoder it would prove nothing.
    """
    with open(os.path.join(TESTS, 'capture.xml')) as handle:
        xml = handle.read()
    hits = 0
    for item in re.findall(r'<item>.*?</item>', xml, re.S):
        text = '\n'.join(base64.b64decode(m.group(1)).decode('utf-8', 'replace')
                         for m in re.finditer(r'base64="true">([^<]*)</', item))
        if needle in text:
            hits += 1
    return hits


def run_keyword(manifest, verbose):
    rows, exact = [], True
    for needle in manifest['needles']:
        want = oracle_hits(needle['text'])
        got = fixture.query(['search', '--in', 'exchanges', '--contains',
                             needle['text'], '--limit', '500'])['total']
        true_positive = min(want, got)
        row = {
            'name': needle['name'], 'oracle': want, 'engine': got,
            'precision': round(true_positive / got, 4) if got else 0.0,
            'recall': round(true_positive / want, 4) if want else 0.0,
        }
        rows.append(row)
        exact = exact and got == want
        if verbose:
            print(f"  needle {row['name']:<16} oracle={want:<4} engine={got:<4} "
                  f"P={row['precision']} R={row['recall']}")
    return {'needles': rows, 'exact_agreement': exact,
            'precision': round(mean([r['precision'] for r in rows]), 4),
            'recall': round(mean([r['recall'] for r in rows]), 4)}


def run_screening(manifest, verbose):
    rows, ok = [], True
    for spec in manifest['screened']:
        payload = fixture.query(['search', spec['q'], '--in', 'structure'])
        rejected = set(t.lower() for t in payload.get('rejected_terms', []))
        action = payload.get('screening_action', 'none')
        matched = set(t.lower() for t in spec['expect_rejected']) <= rejected \
            and action == spec['expect_action']
        ok = ok and matched
        rows.append({'q': spec['q'], 'rejected': sorted(rejected), 'action': action,
                     'ok': matched})
        if verbose:
            print(f"  screen {'ok  ' if matched else 'FAIL'} {spec['q'][:40]:<42} "
                  f"action={action} rejected={sorted(rejected)}")
    return {'cases': rows, 'all_pass': ok}


# --- baseline ------------------------------------------------------------
def load_baseline():
    if os.path.exists(BASELINE):
        with open(BASELINE) as handle:
            return json.load(handle)
    return {'floors': {}, 'last': {}}


# Quality metrics carry floors. Retrieval counters are tracked for their delta
# only: they are not quality, and relevance here is graded per route, so e.g.
# halving max_per_endpoint shows up in dropped_by_diversity and NOT in recall.
GATED_METRICS = ('recall', 'precision', 'mrr', 'ndcg', 'hit_rate')


def flatten(semantic, keyword):
    flat = {}
    for depth, values in semantic.items():
        for key in GATED_METRICS:
            flat[f'{depth}.{key}'] = values[key]
        flat[f'{depth}.distance_mean'] = values['distance_mean']
    flat['keyword.precision'] = keyword['precision']
    flat['keyword.recall'] = keyword['recall']
    return flat


def flatten_counters(semantic):
    flat = {}
    for depth, values in semantic.items():
        for key, count in values['diagnostics'].items():
            flat[f'{depth}.{key}'] = count
        flat[f'{depth}.fallback_only'] = values['fallback_only_queries']
    return flat


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--update-baseline', action='store_true')
    parser.add_argument('--fresh', action='store_true')
    args = parser.parse_args()

    fixture.ensure(fresh=args.fresh)
    manifest = fixture.manifest()
    print('tier B: retrieval quality')

    # A typo in a relevance label would silently depress every metric.
    refs = {r['ref'] for r in manifest['routes']} \
        | {'entity:' + e['name'] for e in manifest['entities']} | {'auth_model'}
    unknown = sorted({t for q in manifest['queries'] for t in q['relevant']} - refs)
    if unknown:
        print(f'  FAIL query set references unknown targets: {unknown[:6]}')
        sys.exit(1)

    sigs = entity_names(manifest)
    semantic = run_semantic(manifest, sigs, args.verbose)
    keyword = run_keyword(manifest, args.verbose)
    screening = run_screening(manifest, args.verbose)

    failures = []
    baseline = load_baseline()
    flat = flatten(semantic, keyword)
    print(f"\n  {'metric':<26} {'value':>8} {'baseline':>9} {'delta':>8} {'floor':>7}")
    for name in sorted(flat):
        value = flat[name]
        last = baseline['last'].get(name)
        floor = baseline['floors'].get(name)
        delta = f'{value - last:+.4f}' if last is not None else '    n/a'
        below = floor is not None and value < floor
        print(f"  {name:<26} {value:>8.4f} "
              f"{last if last is not None else float('nan'):>9.4f} {delta:>8} "
              f"{floor if floor is not None else float('nan'):>7.3f}"
              f"{'  BELOW FLOOR' if below else ''}")
        if below:
            failures.append(f'{name} {value:.4f} < floor {floor:.3f}')

    # Presets must be monotone in recall: a deeper budget cannot retrieve less.
    if semantic['normal']['recall'] + 1e-9 < semantic['quick']['recall']:
        failures.append(f"depth presets not monotone: normal recall "
                        f"{semantic['normal']['recall']} < quick "
                        f"{semantic['quick']['recall']}")
    if not keyword['exact_agreement']:
        failures.append('keyword search disagrees with the independent oracle: '
                        + str([r for r in keyword['needles']
                               if r['oracle'] != r['engine']]))
    if not screening['all_pass']:
        failures.append('vulnerability-jargon screening changed: '
                        + str([c for c in screening['cases'] if not c['ok']]))

    # Zero-recall queries are printed every run: they are the standing record of
    # where semantic retrieval is weak, and the thing an optimization should move.
    weak = [q for q in semantic['normal']['per_query'] if q['recall'] == 0.0]
    if weak:
        print(f"\n  zero-recall queries at depth=normal ({len(weak)}/"
              f"{semantic['normal']['queries']}):")
        for q in weak:
            print(f"    [{q['in']}] {q['q']}")
            print(f"            wanted: {q['missed'][:4]}")

    print(f"\n  keyword oracle agreement : {'exact' if keyword['exact_agreement'] else 'MISMATCH'}")
    print(f"  jargon screening         : {'all pass' if screening['all_pass'] else 'FAILED'}")
    counters = flatten_counters(semantic)
    print(f"\n  retrieval counters (tracked, not gated)")
    print(f"  {'counter':<34} {'value':>8} {'baseline':>9} {'delta':>8}")
    for name in sorted(counters):
        value = counters[name]
        last = (baseline.get('counters') or {}).get(name)
        delta = f'{value - last:+d}' if last is not None else '    n/a'
        print(f"  {name:<34} {value:>8d} "
              f"{last if last is not None else -1:>9d} {delta:>8}")

    if args.update_baseline:
        baseline['last'] = flat
        baseline['counters'] = counters
        baseline['floors'] = {}
        for name, value in flat.items():
            if name.rsplit('.', 1)[-1] not in GATED_METRICS:
                continue   # distance_mean is informational, not a quality floor
            baseline['floors'][name] = round(max(0.0, value - 0.05), 3)
        baseline['note'] = ('floors are generous: HNSW query is approximate. '
                            'Regenerate with --update-baseline after a deliberate '
                            'retrieval change.')
        os.makedirs(os.path.dirname(BASELINE), exist_ok=True)
        with open(BASELINE, 'w') as handle:
            json.dump(baseline, handle, indent=2, sort_keys=True)
            handle.write('\n')
        print(f'\n  baseline written to {BASELINE}')

    if failures:
        print('\ntier B: FAILED')
        for failure in failures:
            print(f'  - {failure}')
        sys.exit(1)
    print('\ntier B: passed')


if __name__ == '__main__':
    main()
