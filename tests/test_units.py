"""Unit checks for the pure pieces of the knowledge-graph pipeline.

No Chroma and no Ollama: segmentation, JavaScript fact extraction, `_fit`
termination, and `build_graph` over the benchmark capture parsed in memory.

    jeb-import/scripts/venv/bin/python tests/test_units.py
"""
import os
import sys
import time

TESTS = os.path.dirname(os.path.abspath(__file__))
IMPORT = os.path.join(os.path.dirname(TESTS), 'jeb-import', 'scripts')
sys.path.insert(0, IMPORT)

from bs4 import BeautifulSoup  # noqa: E402

import build_graph  # noqa: E402
import distill as d  # noqa: E402
import jsfacts  # noqa: E402
import normalize  # noqa: E402
import ontology  # noqa: E402
import parse  # noqa: E402
import segment  # noqa: E402
import storage  # noqa: E402

FAILURES = []


def check(name, ok, detail=''):
    print(f"  {'ok  ' if ok else 'FAIL'} {name}" + ('' if ok else f'  {detail}'))
    if not ok:
        FAILURES.append(name)


def page(body_html):
    soup = BeautifulSoup(f'<html><head><title>T</title></head><body>{body_html}</body></html>', 'html.parser')
    pre = segment.pre_clean(soup)
    for tag in soup(['script', 'style']):
        tag.decompose()
    return pre, segment.post_clean(soup)


# --- segmentation ---------------------------------------------------------
def test_segment():
    print('segment')
    cards = ''.join(f'<div class="card"><h4>Item {i}</h4><p>Description of product {i} with enough words '
                    f'to count as content</p><a href="/p/{i}">view</a></div>' for i in range(30))
    _, post = page(f'<div id="main">{cards}</div>')
    kinds = [c['kind'] for c in post['chunks']]
    check('30 cards collapse to one listing', kinds.count('listing') == 1, str(kinds))
    check('listing keeps item links', '/p/0' in next(c['text'] for c in post['chunks'] if c['kind'] == 'listing'))

    flat = ('Sentence number one is here. ' * 400)
    _, post = page(f'<div>{flat}</div>')
    sizes = [len(c['text']) for c in post['chunks']]
    check('flat text is windowed under the cap', len(sizes) > 1 and max(sizes) <= segment.SECTION_CAP, str(sizes))

    # div-only page, no heading tags, over the page budget; needle deep inside
    blocks = ''.join(f'<div class="panel"><div class="panel-title">Panel {i}</div>'
                     f'<div>{"filler words " * 80}{" NEEDLE-DEEP " if i == 7 else ""}</div></div>' for i in range(12))
    _, post = page(f'<div>{blocks}</div>')
    chosen = segment.select(post['chunks'])
    check('div-only long page is sectioned', not chosen['text'] and 0 < len(chosen['sections']) <= segment.MAX_SECTIONS_PER_PAGE)
    check('needle survives in some section', any('NEEDLE-DEEP' in s['text'] for s in chosen['sections']))
    check('no section exceeds the cap', all(len(s['text']) <= segment.SECTION_CAP + 400 for s in chosen['sections']))
    check('labels come from class hints', any(s['label'].startswith('Panel') for s in chosen['sections']),
          str([s['label'] for s in chosen['sections']]))

    small = segment.select(page('<div>short page about invoices</div>')[1]['chunks'])
    check('short page is held whole', small['text'] == 'short page about invoices' and not small['sections'])

    # boilerplate: a repeated text block is removed without nav/footer tags
    html = ('<html><head><title>T</title></head><body><div><p>Contact the shared widget desk today</p></div>'
            '<div><p>unique body text for this page only</p></div></body></html>')
    shared = {d.block_hash('Contact the shared widget desk today')}
    facts = d.page_facts(html, shared)
    check('template block removed', 'shared widget' not in facts['embed'] and 'unique body text' in facts['embed'],
          facts['embed'])
    check('deterministic', d.page_facts(html, shared) == facts)

    pre, _ = page('<script type="application/ld+json">{"@type":"Product","name":"x","offers":{"price":1}}</script>'
                  '<script>window.__INITIAL_STATE__ = {"user":{"id":1,"email":"a"}};</script>'
                  '<script src="/static/app.js"></script><script>fetch("/api/x")</script>')
    check('embedded JSON payloads found', len(pre['payloads']) == 2, str(pre['payloads']))
    check('script src recorded', pre['loads'] == ['/static/app.js'])
    check('inline JS kept for jsfacts', 'fetch("/api/x")' in pre['inline_js'])


# --- javascript facts -----------------------------------------------------
def test_jsfacts():
    print('jsfacts')
    body = ('/*! react v18.2.0 */\n'
            'var a=/["\']/g, b = x/2/y; fetch("/api/users/"+id,{method:"PUT"});\n'
            'axios.post("/api/orders"); var k="AKIAABCDEFGHIJKLMNOP"; var apiKey = "abcd1234efgh5678";\n'
            'const u = `/api/items/${id}/detail`; var h="https://cdn.example.com/lib"; $.get(\'/legacy/ping\');\n'
            '// "/api/commented"\nvar e = "\\u002fapi\\u002fescaped";\n'
            '//# sourceMappingURL=app.js.map')
    facts = jsfacts.js_facts(body, 'https://app.example')
    endpoints = {(m, p) for m, p, _ in facts['endpoints']}
    check('call-site method inferred', ('PUT', '/api/users/') in endpoints and ('POST', '/api/orders') in endpoints
          and ('GET', '/legacy/ping') in endpoints, str(endpoints))
    check('template literal expression becomes {param}', ('ANY', '/api/items/{param}/detail') in endpoints)
    check('escapes decoded', ('ANY', '/api/escaped') in endpoints, str(endpoints))
    check('comments ignored', not any('commented' in p for _, p in endpoints))
    check('external origin separated', facts['origins'] == ['https://cdn.example.com'])
    check('library banner', facts['libs'] == [('react', '18.2.0')])
    check('source map url', facts['sourcemap_url'] == 'app.js.map')
    shapes = {s for _, s, _ in facts['secrets']}
    check('credential shapes found', 'aws-key' in shapes and 'credential-assignment' in shapes, str(shapes))
    persisted = str(jsfacts.compact(facts))
    summary = jsfacts.summary(facts, 'static asset')
    check('no secret value in persisted facts or summary',
          'AKIAABCDEFGHIJKLMNOP' not in persisted + summary and 'abcd1234efgh5678' not in persisted + summary)
    check('secret_values feeds the identifier index', 'AKIAABCDEFGHIJKLMNOP' in jsfacts.secret_values(body))

    big = ('var pad="' + 'x' * 100 + '";\n') * 25000 + 'var late="/api/late/endpoint"; var key="AKIAZZZZZZZZZZZZZZZZ";'
    assert len(big) > 2_000_000
    late = jsfacts.js_facts(big)
    check('endpoint past the old 2 MB cap is found', ('ANY', '/api/late/endpoint') in {(m, p) for m, p, _ in late['endpoints']})

    modules = ('__webpack_modules__ = {"./src/api/user.js": function(m){ fetch("/api/users/me") },'
               '"./src/ui/button.js": function(m){ return "ok" }};')
    named = jsfacts.js_facts(modules)
    check('module facts only where facts exist', list(named['modules']) == ['./src/api/user.js'], str(named['modules']))


# --- _fit -----------------------------------------------------------------
def test_fit():
    print('_fit')
    started = time.monotonic()
    out = d._fit([('a' * 5000, 5000), ('b' * 5000, 5000)], cap=1500)
    check('terminates and honours the cap', len(out) <= 1500 and time.monotonic() - started < 5, str(len(out)))


# --- build_graph ----------------------------------------------------------
def test_build_graph():
    print('build_graph')
    items = [d_ for d_ in parse.iter_items(os.path.join(TESTS, 'capture.xml'))]
    for index, item in enumerate(items):
        parse.hydrate_item(item)
        item.update(_exchange_id=d.md5(f'exchange-{index}'), _capture_id='unit', _source_item=index)
    annotated, models = normalize.annotate(items)
    chunks, edges = build_graph.build_graph(annotated, models)
    chunks2, edges2 = build_graph.build_graph(annotated, models)
    check('ids stable across two runs', [c['id'] for c in chunks] == [c['id'] for c in chunks2]
          and [e['id'] for e in edges] == [e['id'] for e in edges2])
    ids = {c['id'] for c in chunks}
    check('node ids unique', len(ids) == len(chunks))
    check('every embedded node is typed', all(c['metadata']['node_type'] in ontology.EMBEDDED_TYPES for c in chunks))
    for edge in edges:
        ontology.validate_edge(edge['metadata'])
    check('every edge passes the ontology', True)
    dangling = [e['metadata'] for e in edges
                if e['metadata']['src_type'] in ontology.EMBEDDED_TYPES and e['metadata']['src'] not in ids
                or e['metadata']['dst_type'] in ontology.EMBEDDED_TYPES and e['metadata']['dst'] not in ids]
    check('no dangling embedded endpoints', not dangling, str(dangling[:2]))
    check('embedded record target', len(chunks) <= 400, f'{len(chunks)} records')
    behaviors = [c for c in chunks if c['metadata']['node_type'] == 'behavior']
    routes = {c['id'] for c in chunks if c['metadata']['node_type'] == 'route'}
    check('every behavior anchors on a route', all(b['metadata']['anchor_id'] in routes for b in behaviors))
    check('graph texts within cap', all(len(c['embed_text']) <= segment.PAGE_EMBED_CAP + 1000 for c in chunks))


# --- request signatures, graphql, identifiers, redaction -------------------
def test_signatures_and_identifiers():
    print('signatures and identifiers')
    sig = d.request_variant_signature
    check('variant signature ignores key order',
          sig('{"a":1,"b":2}', 'application/json') == sig('{"b":2,"a":1}', 'application/json'))
    check('variant signature sees a different state value',
          sig('{"status":"a"}', 'application/json') != sig('{"status":"b"}', 'application/json'))
    check('form body is not graphql', d.graphql_operation('type=query&x=1') == '')
    batch = '[{"x":1},{"query":"query Orders { orders { id } }"}]'
    check('batched graphql is described', d.graphql_operation(batch).startswith('query:Orders:'),
          d.graphql_operation(batch))
    check('?query= only counts on graphql paths',
          d.graphql_operation('', 'https://a.example/search?query=mutation%20X%20%7B%20y%20%7D') == ''
          and d.graphql_operation('', 'https://a.example/graphql?query=mutation%20X%20%7B%20y%20%7D').startswith('mutation:X'))

    body = '{"code":"4f9a7c21d0","status":"ok","state":"abc123"}'
    shown = d.structured_semantic_values(body, d.VARIANT_KEY_VALUES, redact=True)
    check('one-time values are shape-tagged in embed form',
          'code=<value:10>' in shown and 'state=<value:6>' in shown and 'status=ok' in shown
          and not any('4f9a7c21d0' in v or 'abc123' in v for v in shown), str(shown))
    check('signature still sees the raw value',
          sig(body, 'application/json') != sig(body.replace('4f9a7c21d0', '0000000000'), 'application/json'))

    upper = '9F1B2C3D-4E5F-6789-ABCD-EF0123456789'
    check('uuid normalises to lower case', storage.normalize_identifier(upper) == upper.lower())
    check('opaque tokens stay verbatim', storage.normalize_identifier('Ab-Cd_Ef') == 'Ab-Cd_Ef')
    found = d.extract_identifier_values(f'/api/items/{upper}/%34%32%31%30%39', [])
    values = [v for _, v in found]
    check('percent-encoded path segments are decoded', '42109' in values and upper in values, str(found))


def main():
    for test in (test_segment, test_jsfacts, test_fit, test_signatures_and_identifiers, test_build_graph):
        test()
    print('unit checks:', 'FAILED ' + ', '.join(FAILURES) if FAILURES else 'all passed')
    return 1 if FAILURES else 0


if __name__ == '__main__':
    sys.exit(main())
