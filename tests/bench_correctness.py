"""Tier A: ground-truth correctness. Hard pass/fail, no thresholds.

Every expectation comes from tests/ground_truth.json, which the generator wrote
from the authored capture -- so a failure here means a derived fact changed, not
that a threshold drifted.

    bash tests/run.sh --live --revision REVISION --tier a [--verbose]
"""
import argparse
import json
import os
import re
import shlex
import sys

import fixture

TESTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, fixture.IMPORT)
sys.path.insert(0, fixture.QUERY)


class Report:
    def __init__(self, verbose=False):
        self.verbose, self.failures, self.passed = verbose, [], 0

    def check(self, name, ok, detail=''):
        if ok:
            self.passed += 1
            if self.verbose:
                print(f'  ok   {name}')
        else:
            self.failures.append((name, detail))
            print(f'  FAIL {name}' + (f'\n         {detail}' if detail else ''))
        return ok

    def equal(self, name, got, want):
        if got == want:
            return self.check(name, True)
        if isinstance(got, (set, frozenset)) and isinstance(want, (set, frozenset)):
            detail = (f'missing={sorted(want - got)[:6]} extra={sorted(got - want)[:6]}')
        else:
            detail = f'got={got!r} want={want!r}'
        return self.check(name, False, detail)

    def finish(self, label):
        total = self.passed + len(self.failures)
        print(f'{label}: {self.passed}/{total} checks passed')
        return not self.failures


# --- helpers --------------------------------------------------------------
def all_structure_parents():
    """Every structure parent node, paged through the metadata listing."""
    rows, offset = [], 0
    while True:
        page = fixture.query(['map', '--limit', '300', '--offset', str(offset),
                              '--include-static'])
        rows.extend(page['results'])
        offset += len(page['results'])
        if not page.get('has_more') or not page['results']:
            break
    return rows


def route_ref(row):
    return (f"{row.get('method', '')} {row['scheme']}://{row['host']}:{row['port']}"
            f"{row['endpoint_template']}")


# --- checks ---------------------------------------------------------------
def check_artifact(report, manifest):
    import hashlib
    with open(os.path.join(TESTS, 'capture.xml'), 'rb') as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    report.equal('artifact/sha256 matches manifest', digest, manifest['capture']['sha256'])


def check_routes(report, manifest, rows):
    want = {r['ref']: r for r in manifest['routes']}
    got = {route_ref(r): r for r in rows
           if r.get('node_kind') in ('page', 'action', 'endpoint') and r.get('observed') is not False}
    if not report.equal('routes/exact route set', set(got), set(want)):
        return
    for field, default in [('node_kind', None), ('access_control', None),
                           ('anon_allowed', False), ('authenticated_ever', False)]:
        bad = {ref: (want[ref][field], got[ref].get(field, default))
               for ref in want if want[ref][field] != got[ref].get(field, default)}
        report.check(f'routes/{field}', not bad,
                     '; '.join(f'{k}: want {v[0]} got {v[1]}'
                               for k, v in list(bad.items())[:4]))
    # Every access-control state the classifier can emit must be represented,
    # or the route labels are not actually exercising it.
    states = {r['access_control'] for r in want.values()}
    report.equal('routes/all access_control states covered', states,
                 {'unknown', 'open-data', 'soft-auth-wall', 'enforced'})
    params = {ref: (set(want[ref]['params']), set(filter(None, str(got[ref].get('param_names', '')).split(','))))
              for ref in want if want[ref]['params']}
    bad = {k: v for k, v in params.items() if not v[0] <= v[1]}
    report.check('routes/declared params present', not bad,
                 '; '.join(f'{k}: missing {sorted(v[0] - v[1])}' for k, v in list(bad.items())[:4]))


def check_entities(report, manifest, rows):
    engine = [r for r in rows if r.get('node_kind') == 'entity']
    report.equal('entities/count', len(engine), len(manifest['entities']))
    docs, by_fields = {}, {}
    sig_to_fields = {}
    for row in engine:
        document = fixture.query(['get', row['id'], '--in', 'graph'])['document']['document']
        fields = tuple(re.search(r'^fields: (.*)$', document, re.M).group(1).split(', '))
        by_fields[fields] = row
        docs[fields] = document
        sig_to_fields[row['schema_sig'][:8]] = fields

    names = {tuple(e['fields']): e['name'] for e in manifest['entities']}
    if not report.equal('entities/field sets', set(by_fields), set(names)):
        return
    for entity in manifest['entities']:
        fields = tuple(entity['fields'])
        row, document = by_fields[fields], docs[fields]
        name = entity['name']
        linked = fixture.query(['graph', row['id'], '--direction', 'in', '--limit', '200'])
        routes = {n['id']: n for n in linked['results'] if n.get('node_type') == 'route'}
        for key, rel in (('produced_by', 'RETURNS'), ('consumed_by', 'ACCEPTS')):
            got = {route_ref(routes[e['src']]) for e in linked['edges']
                   if e['rel'] == rel and e['dst'] == row['id'] and e['src'] in routes}
            report.equal(f'entities/{name}/{key}', got, set(entity[key]))
        report.equal(f'entities/{name}/identifier_field',
                     row.get('identifier_field', ''), 'id')
        match = re.search(r'^related schemas \(fuzzy match\): (.*)$', document, re.M)
        got = set()
        order = []
        if match:
            for token in match.group(1).split(', '):
                sig, score = token.split('~')
                got.add((names[sig_to_fields[sig]], float(score)))
                order.append(float(score))
        report.equal(f'entities/{name}/related',
                     got, {(r['name'], r['score']) for r in entity['related']})
        report.check(f'entities/{name}/related sorted by score',
                     order == sorted(order, reverse=True), f'scores={order}')
    # Shapes seen at a single route must not be promoted.
    promoted = {tuple(sorted(f)) for f in by_fields}
    for name, fields in manifest['non_entity_fields'].items():
        report.check(f'entities/{name}/single-route shape not promoted', tuple(fields) not in promoted)


def check_auth_model(report, manifest, rows):
    models = [r for r in rows if r.get('node_kind') == 'auth_model']
    if not report.equal('auth_model/exactly one origin', len(models), 1):
        return
    model = models[0]
    want = manifest['auth_model']
    origin = manifest['origin']
    report.equal('auth_model/origin', (model['host'], model['port']),
                 (origin['host'], origin['port']))
    for key in ('cookies_set', 'cookies_sent'):
        got = set(filter(None, str(model.get(key, '')).split(',')))
        report.equal(f'auth_model/{key}', got, set(want[key]))
    report.check('auth_model/cookie mechanism recognized',
                 'cookie' in str(model.get('auth_mechanisms', '')),
                 f"auth_mechanisms={model.get('auth_mechanisms')!r}")


def check_identifiers(report, manifest):
    for spec in manifest['identifiers']:
        value = spec['value']
        found = fixture.query(['identifier', value, '--limit', '100'])
        if 'exact_hits' in spec:
            report.equal(f'identifier/{value}/hits', found['total'], spec['exact_hits'])
        else:
            report.check(f'identifier/{value}/hits >= {spec["min_hits"]}',
                         found['total'] >= spec['min_hits'], f"total={found['total']}")
        report.check(f'identifier/{value}/resolves to observations',
                     all(h['collection'] == 'exchanges' for h in found['results']),
                     str({h['collection'] for h in found['results']}))
        fields = {h['field'] for h in found['results']}
        report.check(f'identifier/{value}/fields', set(spec['fields']) <= fields,
                     f'missing={sorted(set(spec["fields"]) - fields)}')
        for template in spec.get('templates', []):
            got = {fixture.query(['get', h['id'], '--in', 'exchanges'])['document']
                   ['metadata'].get('endpoint_template') for h in found['results']}
            report.check(f'identifier/{value}/template {template}', template in got,
                         f'templates={sorted(got)}')


def check_evidence_roundtrip(report):
    """behavior document -> its source observations -> the original HTTP bytes."""
    found = fixture.query(['search', '--in', 'graph', '--node-type', 'behavior', '--path', '/api/orders/1040',
                           '--limit', '1'])
    if not report.check('evidence/behavior document located',
                        bool(found['results']), json.dumps(found)[:200]):
        return
    behavior_id = found['results'][0]['id']
    evidence = fixture.query(['evidence', behavior_id, '--limit', '5'])
    if not report.check('evidence/observations linked', bool(evidence['results']),
                        f'behavior_id={behavior_id} total={evidence["total"]}'):
        return
    document = fixture.query(['get', evidence['results'][0]['id'],
                              '--in', 'exchanges'])['document']
    report.check('evidence/raw request line recovered',
                 'GET /api/orders/1040 HTTP/1.1' in document['document'],
                 document['document'][:120])
    original = fixture.query(['get', evidence['results'][0]['id'], '--in', 'exchanges',
                              '--original'])['document']
    report.check('evidence/original base64 retained',
                 bool(original.get('original_http_base64', {}).get('request')))


def check_hint_contract(report):
    """Every `next` entry must parse as a real standalone command."""
    import agent_interface
    import runtime
    # Hints name a skill launcher: <skill-dir>/jeb, for jeb-query or jeb-import.
    parsers = {'jeb-query': agent_interface.build_parser(), 'jeb-import': runtime.import_parser()}
    commands = [
        ['map', '--limit', '3'], ['search', 'order record', '--limit', '3'],
        ['search', '--in', 'exchanges', '--contains', 'nginx', '--limit', '3'],
        ['attacks', '--limit', '3'], ['endpoint', '/api/orders/1040'],
        ['identifier', '9000'], ['get', 'definitely-not-a-real-id'],
        ['search', 'sql injection'],
    ]
    seen = 0
    for argv in commands:
        payload = fixture.query(argv, check=False)
        for hint in payload.get('next', []):
            seen += 1
            parts = shlex.split(hint)
            skill = os.path.basename(os.path.dirname(parts[0])) if parts else ''
            if not report.check(f'hints/{hint[:48]}/prefix',
                                len(parts) > 1 and os.path.basename(parts[0]) == 'jeb' and skill in parsers, hint):
                continue
            try:
                parsers[skill].parse_args(runtime.hoist(parts[1:], agent_interface.COMMANDS + runtime.IMPORT_COMMANDS))
                report.check(f'hints/{hint[:48]}/valid CLI', True)
            except SystemExit:
                report.check(f'hints/{hint[:48]}/valid CLI', False, hint)
    report.check('hints/at least one hint per run', seen > 0, f'seen={seen}')


def check_error_paths(report):
    cases = [
        (['search', '--in', 'exchanges', 'free text'], 'exact filters'),
        (['search', '--in', 'graph', '--node-type', 'nonsense'], 'invalid choice'),
        (['search', '--in', 'graph', '--severity', 'high'], 'not supported'),
        (['map', '--limit', '0'], 'must be positive'),
        (['map', '--offset', '-1'], 'nonnegative'),
        (['search', '--in', 'graph', '--vuln-class', 'xss'], 'not supported'),
    ]
    for argv, fragment in cases:
        payload = fixture.query(argv, check=False)
        report.check(f'errors/{" ".join(argv[:4])}',
                     fragment in payload.get('error', ''),
                     f"error={payload.get('error')!r}")
    # A finding is never written into a directory that holds no imported capture.
    import tempfile
    empty = tempfile.mkdtemp(prefix='jeb-empty-')
    try:
        for project in (os.path.join(empty, 'absent'), empty):
            got = fixture.query(['record-attack', '--vuln-class', 'x', '--endpoint', 'https://a.example:443/x'],
                                project=project, check=False)
            report.check('errors/record-attack outside an imported project',
                         'import' in got.get('error', ''), f"error={got.get('error')!r}")
        report.check('errors/record-attack created nothing', os.listdir(empty) == [], str(os.listdir(empty)))
    finally:
        import shutil
        shutil.rmtree(empty, ignore_errors=True)


def check_stored_document_invariant(report, manifest):
    """source_evidence must not be replaced by a where_document prefilter.

    Proven, not asserted: the escaped-quote needle is in the decoded HTTP and
    absent from the stored document, while a plainly-stored needle is in both.
    """
    import chromadb
    collection = chromadb.PersistentClient(
        path=os.path.join(fixture.project_dir(), 'chroma_db')).get_collection(
        'exchanges', embedding_function=None)
    for needle in manifest['needles']:
        stored = len(collection.get(where_document={'$contains': needle['text']},
                                    include=[], limit=500)['ids'])
        decoded = fixture.query(['search', '--in', 'exchanges', '--contains',
                                 needle['text'], '--limit', '500'])['total']
        if needle.get('absent_from_stored_document'):
            report.check(f'invariant/{needle["name"]}/absent from stored document',
                         stored == 0 and decoded > 0,
                         f'stored={stored} decoded={decoded}')
        else:
            report.check(f'invariant/{needle["name"]}/stored and decoded agree',
                         stored == decoded, f'stored={stored} decoded={decoded}')


def check_findings(report):
    """record-attack is idempotent on event_id and rejects reuse for new inputs.

    Runs against a scratch copy of the fixture database so the shared fixture
    (and the digests taken from it) never contains a finding."""
    import shutil
    import tempfile
    scratch = tempfile.mkdtemp(prefix='jeb-findings-')
    try:
        shutil.copytree(fixture.project_dir(), scratch, dirs_exist_ok=True)
        _check_findings(report, scratch)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def _check_findings(report, project):
    query = lambda argv, **kw: fixture.query(argv, project=project, **kw)
    endpoint = 'https://app.example:443/api/orders/1040'
    argv = ['record-attack', '--vuln-class', 'benchmark-probe', '--endpoint', endpoint,
            '--method', 'GET', '--param', 'id', '--payload', "1040' OR '1'='1",
            '--status', '500', '--verdict', 'inconclusive',
            '--evidence', 'tier-A fixture finding', '--event-id', 'jeb-bench-fixture-1']
    first = query(argv)
    report.check('findings/recorded', bool(first.get('recorded')), json.dumps(first)[:200])
    report.equal('findings/identifier index synced',
                 first.get('identifier_state'), 'complete')
    again = query(argv)
    report.equal('findings/idempotent on event_id',
                 again.get('recorded'), first.get('recorded'))
    clash = query(argv[:-1] + ['jeb-bench-fixture-1', '--evidence', 'different'],
                          check=False)
    report.check('findings/event_id reuse with new inputs rejected',
                 'different finding inputs' in clash.get('error', ''),
                 f"error={clash.get('error')!r}")
    listed = query(['attacks', '--limit', '10'])
    report.check('findings/listed in attacks',
                 any(r['id'] == first['recorded'] for r in listed['results']),
                 json.dumps(listed)[:200])
    route = next(r for r in all_structure_parents() if r.get('method') == 'GET'
                 and r['endpoint_template'] == '/api/orders/{id}')
    around = query(['graph', route['id'], '--rel', 'TARGETS', '--direction', 'in'])
    report.check('findings/graph shows the finding that targets a route',
                 any(r['id'] == first['recorded'] and r.get('node_type') == 'finding' for r in around['results']),
                 json.dumps(around)[:200])
    # With the collection now present, the per-collection filter guard applies.
    guard = query(['search', '--in', 'attacks', '--kind', 'entity'], check=False)
    report.check('findings/attacks rejects structural filters',
                 'not supported' in guard.get('error', ''),
                 f"error={guard.get('error')!r}")


def check_graph(report, manifest):
    """Knowledge-graph shapes: segmentation, shared nodes, edges, stubs, secrets."""
    import chromadb
    truth = manifest['graph']
    client = chromadb.PersistentClient(path=os.path.join(fixture.project_dir(), 'chroma_db'))
    nodes = client.get_collection('graph', embedding_function=None).get(include=['metadatas', 'documents'])
    edges = client.get_collection('edges', embedding_function=None).get(include=['metadatas'])
    meta = dict(zip(nodes['ids'], nodes['metadatas']))
    docs = dict(zip(nodes['ids'], nodes['documents']))
    embed = {i: m.get('_embed_text', '') for i, m in meta.items()}
    ref_id = {}
    for node_id, m in meta.items():
        if m.get('node_type') == 'route':
            ref_id[f"{m['method']} {m['scheme']}://{m['host']}:{m['port']}{m['endpoint_template']}"] = node_id
    edge_set = {(e['src'], e['rel'], e['dst']) for e in edges['metadatas']}
    contains = {}
    for src, rel, dst in edge_set:
        if rel == 'CONTAINS':
            contains.setdefault(dst, set()).add(src)

    # --- sectioning ------------------------------------------------------
    for ref in truth['long_pages']:
        sections = [s for s in contains if meta.get(s, {}).get('node_type') == 'section'
                    and ref_id[ref] in contains[s]]
        report.check(f'graph/{ref}/long page is sectioned within the cap', 1 < len(sections) <= 8,
                     f'{len(sections)} sections')
        report.check(f'graph/{ref}/no section over the cap', all(len(docs[s]) <= 3000 for s in sections))
    handbook = [docs[s] for s in contains if 'quarantine-escrow-ledger' in docs[s]]
    report.equal('graph/needle deep in a div-only page lands in exactly one section', len(handbook), 1)
    report.check('graph/flat-text needle lands in a section',
                 any('Gravel-harbour-transfer' in d for d in docs.values()))

    # --- listing, hydration, shared widget --------------------------------
    for ref in truth['listing_pages']:
        sections = [s for s in contains if ref_id[ref] in contains[s]]
        report.check(f'graph/{ref}/30 cards collapse, not 30 nodes', len(sections) <= 4, f'{len(sections)}')
    report.check('graph/hydration-only content is searchable on the route',
                 any('Zephyr-hydration-gizmo' in d for i, d in embed.items()
                     if meta[i].get('endpoint_template') == '/app/home'))
    widget = [s for s in contains if truth['widget_needle'] in docs[s]]
    report.equal('graph/shared widget stored once', len(widget), 1)
    report.equal('graph/shared widget contained by every page', len(contains[widget[0]]) if widget else 0,
                 len(truth['promo_pages']))

    # --- chrome ----------------------------------------------------------
    for phrase in truth['chrome_phrases']:
        leaked = [meta[i].get('endpoint_template') for i, d in embed.items()
                  if phrase in d and meta[i].get('node_type') in ('behavior', 'section')]
        report.check(f'graph/chrome "{phrase}" removed from page nodes', not leaked, str(leaked[:4]))

    # --- edges -----------------------------------------------------------
    for want in truth['edges']:
        src, dst = ref_id.get(want['src']), ref_id.get(want['dst'])
        if want['rel'] == 'SUBMITS_TO':
            forms = {d for s, r, d in edge_set if r == 'CONTAINS' and s == src and meta.get(d, {}).get('node_type') == 'form'}
            ok = any((f, 'SUBMITS_TO', dst) in edge_set for f in forms)
        else:
            ok = (src, want['rel'], dst) in edge_set
        report.check(f"graph/edge {want['src']} -{want['rel']}-> {want['dst']}", ok)
    entity = {i for i, m in meta.items() if m.get('node_type') == 'data_object'}
    report.check('graph/hydration payload RETURNS an entity',
                 any((ref_id[f"GET {manifest['origin']['scheme']}://{manifest['origin']['host']}:{manifest['origin']['port']}/app/home"],
                      'RETURNS', e) in edge_set for e in entity))

    # --- stubs -----------------------------------------------------------
    for template in truth['stub_routes']:
        stubs = [m for m in meta.values() if m.get('node_type') == 'route' and m['endpoint_template'] == template]
        report.check(f'graph/stub {template} exists and is unobserved',
                     len(stubs) == 1 and stubs[0].get('observed') is False, str(stubs))

    # --- external origins, module sections, source map ----------------------
    bundle = ref_id[truth['bundle']]
    for name in truth['external_origins']:
        hits = [i for i, m in meta.items() if m.get('node_type') == 'origin' and
                f"{m['scheme']}://{m['host']}:{m['port']}" == name]
        report.check(f'graph/external origin {name} is an unobserved node called by the bundle',
                     len(hits) == 1 and meta[hits[0]].get('observed') is False
                     and (bundle, 'CALLS', hits[0]) in edge_set, str(hits))
    dev = ref_id[truth['modules']['bundle']]
    modules = {meta[d].get('label'): d for s_, r, d in edge_set
               if r == 'CONTAINS' and s_ == dev and meta.get(d, {}).get('section_kind') == 'module'}
    report.equal('graph/module sections only for modules with facts', set(modules), set(truth['modules']['names']))
    report.check('graph/bundle LOADS its source map', (dev, 'LOADS', ref_id[truth['modules']['map']]) in edge_set)
    report.check('graph/module section names its endpoint',
                 all('/api/dev/reports/summary' in embed[m] for m in modules.values()))

    # --- secrets ---------------------------------------------------------
    key = truth['aws_key']
    report.check('graph/credential value absent from every embedded text',
                 not any(key in d for d in embed.values()) and
                 not any(key in d for i, d in docs.items() if meta[i].get('node_type') != 'behavior'))
    report.check('graph/credential value absent from every node metadata',
                 not any(key in json.dumps(m) for m in meta.values()))
    found = fixture.query(['identifier', key])
    report.check('graph/credential value resolves through the identifier index',
                 bool(found.get('results') or found.get('total')), json.dumps(found)[:200])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--fresh', action='store_true')
    args = parser.parse_args()

    fixture.ensure(fresh=args.fresh)
    manifest = fixture.manifest()
    report = Report(args.verbose)
    print('tier A: ground-truth correctness')
    rows = all_structure_parents()
    check_artifact(report, manifest)
    check_routes(report, manifest, rows)
    check_entities(report, manifest, rows)
    check_auth_model(report, manifest, rows)
    check_identifiers(report, manifest)
    check_evidence_roundtrip(report)
    check_hint_contract(report)
    check_error_paths(report)
    check_graph(report, manifest)
    check_findings(report)
    check_stored_document_invariant(report, manifest)
    sys.exit(0 if report.finish('tier A') else 1)


if __name__ == '__main__':
    main()
