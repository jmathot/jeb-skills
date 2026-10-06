"""Tier C: performance profile and the bit-identical gate.

Timings are reported with deltas against the committed baseline but never fail
the run -- they are machine-dependent. The ONLY failing check here is the
bit-identical gate: a speedup must not change a single stored record.

The engine is instrumented by monkeypatching, not edited, so what is measured is
exactly what ships.

    python3 tests/bench_perf.py [--update-baseline] [--skip-import]
"""
import argparse
import json
import os
import resource
import shutil
import statistics
import subprocess
import sys
import time

import fixture

TESTS = os.path.dirname(os.path.abspath(__file__))
BASELINE = os.path.join(TESTS, 'baseline', 'perf.json')
DIGESTS = os.path.join(TESTS, 'baseline')
GATED = ('structure', 'behavior', 'exchanges')

sys.path.insert(0, os.path.join(fixture.ENGINE, 'import'))
sys.path.insert(0, os.path.join(fixture.ENGINE, 'query'))


class Counters:
    """Call counts and phase timings collected by monkeypatching."""

    def __init__(self):
        self.calls, self.phases, self.undo = {}, {}, []

    def count(self, owner, name, label=None):
        label = label or f'{owner.__name__ if hasattr(owner, "__name__") else owner}.{name}'
        original = getattr(owner, name)

        def wrapper(*a, **kw):
            self.calls[label] = self.calls.get(label, 0) + 1
            return original(*a, **kw)

        setattr(owner, name, wrapper)
        self.undo.append(lambda: setattr(owner, name, original))

    def time(self, owner, name, label=None):
        label = label or name
        original = getattr(owner, name)

        def wrapper(*a, **kw):
            started = time.perf_counter()
            result = original(*a, **kw)
            if hasattr(result, '__next__'):
                # A generator does its work when drained, not when built. Time the
                # draining instead, or the phase would report ~0 regardless.
                def drain(source=result):
                    try:
                        for value in source:
                            yield value
                    finally:
                        slot = self.phases.setdefault(label, [0, 0.0])
                        slot[0] += 1
                        slot[1] += time.perf_counter() - started
                return drain()
            slot = self.phases.setdefault(label, [0, 0.0])
            slot[0] += 1
            slot[1] += time.perf_counter() - started
            return result

        setattr(owner, name, wrapper)
        self.undo.append(lambda: setattr(owner, name, original))

    def restore(self):
        for action in reversed(self.undo):
            action()
        self.undo = []

    def report(self):
        return {
            'calls': dict(sorted(self.calls.items())),
            'phases': {k: {'calls': v[0], 'seconds': round(v[1], 3)}
                       for k, v in sorted(self.phases.items())},
        }


def instrument(counters):
    """Wrap the Chroma, Ollama, HTML and phase boundaries."""
    import chromadb.api.models.Collection as collection_module
    import distill
    import embedding
    import import_project
    import build_structure
    import storage

    collection = collection_module.Collection
    for name in ('get', 'query', 'upsert', 'update', 'delete', 'count'):
        if hasattr(collection, name):
            counters.count(collection, name, f'chroma.{name}')
    import vector_store
    import retrieval
    counters.count(embedding, 'embed_documents', 'ollama.embed_documents')
    counters.count(vector_store, 'embed_documents', 'ollama.embed_documents')
    counters.count(retrieval, 'embed_query', 'ollama.embed_query')
    counters.count(distill, 'BeautifulSoup', 'html.parse')
    # import_project binds these at import time, so patch its own references.
    for owner, name in [(import_project, 'annotate_features'),
                        (import_project, 'hydrate_chunks'),
                        (import_project, 'store'),
                        (import_project, 'extract_features'),
                        (build_structure, 'build_endpoint_nodes'),
                        (build_structure, 'build_entities'),
                        (storage, 'sync_identifiers')]:
        counters.time(owner, name, f'{name}')
    counters.count(import_project, 'extract_features', 'features.extract')
    return import_project


def cold_import(counters, project):
    """Run ingest + rebuild in-process on a scratch project directory."""
    import chromadb
    import_project = instrument(counters)
    from storage import lookup_collection, writer_lock

    if os.path.isdir(project):
        shutil.rmtree(project)
    os.makedirs(project)
    db_path = os.path.join(project, 'chroma_db')
    timings = {}
    with writer_lock(db_path):
        client = chromadb.PersistentClient(path=db_path)
        captures = lookup_collection(client, 'captures')
        config = import_project.project_config(captures, None, None)
        started = time.perf_counter()
        import_project.ingest(client, captures, fixture.CAPTURE, config)
        timings['ingest'] = round(time.perf_counter() - started, 3)
        started = time.perf_counter()
        import_project.rebuild_project(client, captures, config, False)
        timings['rebuild_from_ingest'] = round(time.perf_counter() - started, 3)
        started = time.perf_counter()
        import_project.rebuild_project(client, captures, config, True)
        timings['forced_rebuild'] = round(time.perf_counter() - started, 3)
    timings['total'] = round(sum(timings.values()), 3)
    return timings


def entity_scaling():
    """Direct scaling probe for the O(E^2) all-pairs Jaccard in build_entities.

    Committed so the outstanding rewrite has a curve to beat, instead of a fresh
    ad-hoc benchmark each time someone looks at it.
    """
    import build_structure
    base = ['id', 'status', 'total', 'customer_id', 'note', 'tag', 'ref', 'owner']
    out = {}
    for count in (200, 500, 1000, 2000):
        nodes = []
        for index in range(count):
            keys = sorted(base[:4] + [f'f{index % 7}', f'g{index % 11}'])
            sig = f'sig{index:06d}'
            for method, suffix in (('GET', ''), ('PUT', '/edit')):
                nodes.append({
                    'host': 'app.example', 'scheme': 'https', 'port': 443,
                    'method': method, 'endpoint_template': f'/api/r{index}{suffix}',
                    'resp_schema_sig': sig, 'resp_schema_keys': keys,
                    'req_schema_sig': '', 'req_schema_keys': [],
                })
        started = time.perf_counter()
        entities, _ = build_structure.build_entities(nodes)
        out[str(count)] = {'ms': round((time.perf_counter() - started) * 1000, 1),
                           'entities': len(entities)}
    return out


def query_latency(queries):
    """Per-command subprocess latency, plus the fixed interpreter+import floor."""
    floor = []
    for _ in range(3):
        started = time.perf_counter()
        subprocess.run([fixture.interpreter(), '-c', 'import chromadb'],
                       capture_output=True)
        floor.append((time.perf_counter() - started) * 1000)
    floor_ms = round(statistics.median(floor), 1)

    samples = {}
    plan = [('map', ['map', '--limit', '20']),
            ('endpoint', ['endpoint', '/api/orders/1040']),
            ('get', ['get', '9000']),
            ('identifier', ['identifier', '4711', '--limit', '20']),
            ('contains', ['search', '--in', 'exchanges', '--contains', 'nginx',
                          '--limit', '20']),
            ('attacks', ['attacks', '--limit', '10'])]
    for name, argv in plan:
        timings = []
        for _ in range(3):
            started = time.perf_counter()
            fixture.query(argv, check=False)
            timings.append((time.perf_counter() - started) * 1000)
        samples[name] = timings
    search = []
    for spec in queries:
        argv = ['search', spec['q'], '--in', spec['in']]
        started = time.perf_counter()
        fixture.query(argv)
        search.append((time.perf_counter() - started) * 1000)
    samples['search'] = search

    out = {'process_floor_ms': floor_ms}
    for name, timings in samples.items():
        ordered = sorted(timings)
        p50 = statistics.median(ordered)
        p95 = ordered[min(len(ordered) - 1, int(0.95 * len(ordered)))]
        out[name] = {'n': len(ordered), 'p50_ms': round(p50, 1),
                     'p95_ms': round(p95, 1),
                     'p50_net_ms': round(max(0.0, p50 - floor_ms), 1)}
    return out


def export_and_gate(project, report_dir, update):
    """Export the gated collections and compare against the committed digests."""
    ok = True
    for name in GATED:
        out = os.path.join(report_dir, f'{name}.ndjson')
        if os.path.exists(out):
            os.remove(out)
        code, output = fixture.importer(['export', '--collection', name,
                                         '--output', out], project=project)
        if code != 0:
            print(f'  x  export {name} failed: {output.strip()[:200]}')
            ok = False
            continue
        digest = os.path.join(DIGESTS, f'{name}.digest.json')
        gate = os.path.join(TESTS, 'gate.py')
        argv = ([gate, 'digest', '--export', out, '--out', digest]
                if update or not os.path.exists(digest) else
                [gate, 'check', '--export', out, '--digest', digest, '--label', name])
        # Captured rather than inherited: the parent buffers its own prints, so
        # inherited output lands in the wrong place whenever stdout is a pipe.
        proc = subprocess.run([sys.executable] + argv, capture_output=True, text=True)
        print(proc.stdout.rstrip() or proc.stderr.rstrip())
        ok = ok and proc.returncode == 0
    return ok


def show(label, got, base, unit=''):
    if base is None:
        print(f'  {label:<34} {got:>9}{unit}')
        return
    try:
        delta = f'{got - base:+.1f}' if isinstance(got, float) else f'{got - base:+d}'
        pct = f'{(got - base) / base * 100:+.0f}%' if base else '  n/a'
    except TypeError:
        delta, pct = '  n/a', '  n/a'
    print(f'  {label:<34} {got:>9}{unit} (baseline {base}{unit}, {delta}, {pct})')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--update-baseline', action='store_true')
    parser.add_argument('--skip-import', action='store_true',
                        help='reuse the shared fixture instead of a cold import')
    args = parser.parse_args()

    if args.update_baseline and args.skip_import:
        # Without a cold import there are no phase timings, call counts or RSS, so
        # recording would silently drop them from the baseline.
        print('tier C: --update-baseline needs a cold import; drop --skip-import')
        sys.exit(2)

    print('tier C: performance profile')
    baseline = {}
    if os.path.exists(BASELINE):
        with open(BASELINE) as handle:
            baseline = json.load(handle)

    manifest = fixture.manifest()
    scratch = os.path.join(fixture.WORK, 'perf')
    report = {'capture': {'items': manifest['capture']['items'],
                          'bytes': manifest['capture']['bytes']}}

    if args.skip_import:
        project = fixture.ensure()
        print('  (cold import skipped; timings and call counts omitted)')
    else:
        counters = Counters()
        try:
            report['import'] = cold_import(counters, scratch)
        finally:
            counters.restore()
        report.update(counters.report())
        project = scratch
        print('\n  phase timings')
        for name, values in report['phases'].items():
            base = (baseline.get('phases', {}).get(name) or {}).get('seconds')
            show(f'{name} (x{values["calls"]})', values['seconds'], base, 's')
        print('\n  import wall clock')
        for name, value in report['import'].items():
            show(name, value, (baseline.get('import') or {}).get(name), 's')
        print('\n  call counts')
        for name, value in report['calls'].items():
            show(name, value, (baseline.get('calls') or {}).get(name))

    # Only meaningful when this process actually ran the import.
    if not args.skip_import:
        report['peak_rss_mb'] = round(
            resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)
        show('peak_rss_mb', report['peak_rss_mb'], baseline.get('peak_rss_mb'), 'MB')

    print('\n  build_entities scaling (all-pairs Jaccard)')
    report['entity_scaling'] = entity_scaling()
    for count, values in report['entity_scaling'].items():
        base = (baseline.get('entity_scaling', {}).get(count) or {}).get('ms')
        show(f'E={count} ({values["entities"]} entities)', values['ms'], base, 'ms')

    print('\n  query latency')
    report['query_latency'] = query_latency(manifest['queries'])
    floor = report['query_latency'].pop('process_floor_ms')
    show('process floor (python+chromadb)', floor,
         (baseline.get('query_latency') or {}).get('process_floor_ms'), 'ms')
    for name, values in report['query_latency'].items():
        base = ((baseline.get('query_latency') or {}).get(name) or {}).get('p50_ms')
        show(f'{name} p50 (net {values["p50_net_ms"]}ms)', values['p50_ms'], base, 'ms')
    report['query_latency']['process_floor_ms'] = floor

    print('\n  bit-identical gate')
    gate_ok = export_and_gate(project, scratch if not args.skip_import else fixture.WORK,
                              args.update_baseline)

    if args.update_baseline:
        report['note'] = ('Timings and RSS are machine-specific and are reported '
                          'as deltas only, never gated. Call counts and the '
                          'collection digests are machine-independent.')
        os.makedirs(os.path.dirname(BASELINE), exist_ok=True)
        with open(BASELINE, 'w') as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write('\n')
        print(f'\n  baseline written to {BASELINE}')

    print(f"\ntier C: {'passed' if gate_ok else 'FAILED (stored output changed)'}")
    sys.exit(0 if gate_ok else 1)


if __name__ == '__main__':
    main()
