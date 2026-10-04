"""Tier A: ground-truth correctness. Hard pass/fail, no thresholds.

Every expectation comes from tests/ground_truth.json, which the generator wrote
from the authored capture -- so a failure here means a derived fact changed, not
that a threshold drifted.

    python3 tests/bench_correctness.py [--verbose]
"""
import argparse
import json
import os
import re
import sys

import fixture

TESTS = os.path.dirname(os.path.abspath(__file__))
TOOLS_TS = os.path.join(os.path.dirname(TESTS), 'src', 'tools.ts')


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


def tool_schema():
    """Top-level argument names and command enums per `jeb` tool, from src/tools.ts."""
    source = open(TOOLS_TS).read()
    tools = {}
    for name in ('query', 'import'):
        start = source.index(f'name: "{name}"')
        head = source.index('properties: {', start) + len('properties: {')
        depth, index = 1, head
        while depth:
            if source[index] in '{[':
                depth += 1
            elif source[index] in '}]':
                depth -= 1
            index += 1
        block = source[head:index - 1]
        args, depth = set(), 0
        for line in block.splitlines():
            if depth == 0:
                match = re.match(r'\s{10}(\w+):', line)
                if match:
                    args.add(match.group(1))
            depth += line.count('{') + line.count('[') - line.count('}') - line.count(']')
        commands = re.search(r'command: enumStr\(\s*\[([^\]]*)\]', block, re.S)
        tools[name] = {
            'args': args,
            'commands': set(re.findall(r'"([^"]+)"', commands.group(1))) if commands else set(),
        }
    return tools


# --- checks ---------------------------------------------------------------
def check_artifact(report, manifest):
    import hashlib
    with open(os.path.join(TESTS, 'capture.xml'), 'rb') as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    report.equal('artifact/sha256 matches manifest', digest, manifest['capture']['sha256'])


def check_routes(report, manifest, rows):
    want = {r['ref']: r for r in manifest['routes']}
    got = {route_ref(r): r for r in rows
           if r.get('node_kind') in ('page', 'action', 'endpoint')}
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
        document = fixture.query(['get', row['id'], '--in', 'structure'])['document']['document']
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
        for key in ('produced_by', 'consumed_by'):
            got = set(filter(None, str(row.get(key, '')).split(',')))
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
    report.equal('entities/single-route shapes not promoted',
                 len(engine), len(manifest['entities']))


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
    found = fixture.query(['search', '--in', 'behavior', '--path', '/api/orders/1040',
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
    """Every `next` entry must be a real tool call: the mess this suite exists for."""
    schema = tool_schema()
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
            parts = hint.split()
            if not report.check(f'hints/{hint[:48]}/prefix',
                                hint.startswith('jeb query ') or hint.startswith('jeb import '),
                                hint):
                continue
            name = parts[1]
            kv = dict(p.split('=', 1) for p in parts[2:] if '=' in p)
            report.check(f'hints/{hint[:48]}/command known',
                         kv.get('command') in schema[name]['commands'],
                         f'command={kv.get("command")!r}')
            unknown = set(kv) - schema[name]['args'] - {'command'}
            report.check(f'hints/{hint[:48]}/args in tool schema', not unknown,
                         f'unknown={sorted(unknown)}')
    report.check('hints/at least one hint per run', seen > 0, f'seen={seen}')
    # The deleted wrapper scripts must not come back in any string the engine can
    # emit. Docstrings are excluded on purpose: hints.py documents the old syntax
    # to explain why it exists, which is not a string a user can ever receive.
    stale = stale_wrappers()
    report.check('hints/no deleted wrapper names in emitted strings', not stale, str(stale))


def stale_wrappers():
    """Deleted wrapper names appearing in non-docstring string literals."""
    import ast
    engine = os.path.join(os.path.dirname(TESTS), 'engine')
    tokens = ('jeb-query.sh', 'process_burp.sh', 'jeb-import')
    found = []
    for root, dirs, files in os.walk(engine):
        dirs[:] = [d for d in dirs if d != '.venv']
        for name in sorted(files):
            if not name.endswith('.py'):
                continue
            tree = ast.parse(open(os.path.join(root, name)).read())
            docstrings = set()
            for node in ast.walk(tree):
                if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                                     ast.AsyncFunctionDef)):
                    first = node.body[0] if node.body else None
                    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) \
                            and isinstance(first.value.value, str):
                        docstrings.add(id(first.value))
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                        and id(node) not in docstrings:
                    for token in tokens:
                        if token in node.value:
                            found.append(f'{name}:{node.lineno}:{token}')
    return found


def check_error_paths(report):
    cases = [
        (['search', '--in', 'exchanges', 'free text'], 'exact filters'),
        (['search', '--in', 'structure', '--status', '500'], '--status applies'),
        (['search', '--in', 'structure', '--access-class', 'data'], 'not supported'),
        (['search', '--in', 'behavior', '--kind', 'entity'], 'not supported'),
        (['map', '--limit', '0'], 'must be positive'),
        (['map', '--offset', '-1'], 'nonnegative'),
        (['search', '--in', 'behavior', '--vuln-class', 'xss'], 'not supported'),
    ]
    for argv, fragment in cases:
        payload = fixture.query(argv, check=False)
        report.check(f'errors/{" ".join(argv[:4])}',
                     fragment in payload.get('error', ''),
                     f"error={payload.get('error')!r}")


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
    """record-attack is idempotent on event_id and rejects reuse for new inputs."""
    endpoint = 'https://app.example:443/api/orders/1040'
    argv = ['record-attack', '--vuln-class', 'benchmark-probe', '--endpoint', endpoint,
            '--method', 'GET', '--param', 'id', '--payload', "1040' OR '1'='1",
            '--status', '500', '--verdict', 'inconclusive',
            '--evidence', 'tier-A fixture finding', '--event-id', 'jeb-bench-fixture-1']
    first = fixture.query(argv)
    report.check('findings/recorded', bool(first.get('recorded')), json.dumps(first)[:200])
    report.equal('findings/identifier index synced',
                 first.get('identifier_state'), 'complete')
    again = fixture.query(argv)
    report.equal('findings/idempotent on event_id',
                 again.get('recorded'), first.get('recorded'))
    clash = fixture.query(argv[:-1] + ['jeb-bench-fixture-1', '--evidence', 'different'],
                          check=False)
    report.check('findings/event_id reuse with new inputs rejected',
                 'different finding inputs' in clash.get('error', ''),
                 f"error={clash.get('error')!r}")
    listed = fixture.query(['attacks', '--limit', '10'])
    report.check('findings/listed in attacks',
                 any(r['id'] == first['recorded'] for r in listed['results']),
                 json.dumps(listed)[:200])
    # With the collection now present, the per-collection filter guard applies.
    guard = fixture.query(['search', '--in', 'attacks', '--kind', 'entity'], check=False)
    report.check('findings/attacks rejects structural filters',
                 'not supported' in guard.get('error', ''),
                 f"error={guard.get('error')!r}")


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
    check_findings(report)
    check_stored_document_invariant(report, manifest)
    sys.exit(0 if report.finish('tier A') else 1)


if __name__ == '__main__':
    main()
