"""
Page and client-code nodes for `build_graph`.

Reads the compact facts attached to annotated observations (`a['page']` from
`segment`, `a['js']` from `jsfacts`) and adds:

  Section   a shared chunk of a page too long to hold whole (CONTAINS, ordered)
  Form      a shared form (CONTAINS, HAS_FIELD, SUBMITS_TO)
  routes    stub routes for endpoints client code names but the capture never hit
  edges     LINKS_TO, LOADS, CALLS, USES_LIB, and RETURNS for page-embedded data

Nothing here touches Chroma or the network.
"""
from collections import defaultdict
from urllib.parse import urljoin, urlparse

import distill as d
import jsfacts
import ontology as o
from storage import origin as format_origin

MAX_STUB_ROUTES_PER_HOST = 200
MAX_EXTERNAL_ORIGINS = 100
MAX_LINKS_PER_PAGE = 30
SECTION_TEXT_CAP = 2500


def _segments(template):
    return [s for s in str(template or '').split('/') if s]


def _wild(segment):
    return segment.startswith('{') and segment.endswith('}')


def _segment_match(a, b):
    left, right = _segments(a), _segments(b)
    return len(left) == len(right) and all(x == y or _wild(x) or _wild(y) for x, y in zip(left, right))


class Resolver:
    """Finds the observed route a path points at, on one origin."""

    def __init__(self, routes, primary):
        self._by_template = defaultdict(list)
        self._by_origin = defaultdict(set)
        for route in routes:
            key = format_origin(route)
            self._by_template[(key, route['endpoint_template'])].append(route)
            self._by_origin[key].add(route['endpoint_template'])
        self._primary = primary
        self._cache = {}

    def resolve(self, origin, path, method=''):
        template = d.templatize_path(path or '/')
        key = (origin, template, method)
        if key not in self._cache:
            candidates = self._by_template.get((origin, template))
            if not candidates:
                match = next((t for t in sorted(self._by_origin.get(origin, ())) if _segment_match(t, template)), None)
                candidates = self._by_template.get((origin, match)) if match else None
            chosen = None
            if candidates:
                exact = [r for r in candidates if method and r['method'] == method]
                chosen = exact[0] if exact else self._primary(candidates)
            self._cache[key] = (chosen, template)
        return self._cache[key]


def _target_origin(origin, raw):
    """(origin, path) for a link/endpoint that may be absolute."""
    parsed = urlparse(raw)
    if parsed.netloc:
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        host = parsed.hostname or ''
        host = f'[{host}]' if ':' in host else host
        return f'{parsed.scheme}://{host}:{port}', parsed.path or '/'
    return origin, parsed.path or '/'


def _node_meta(route, node_kind, template, method='', **extra):
    meta = {'scheme': route['scheme'], 'host': route['host'], 'port': route['port'],
            'endpoint_template': template, 'method': method, 'node_kind': node_kind,
            'is_static': False, 'instance_count': 1}
    meta.update(extra)
    return meta


def add_page_nodes(chunks, edges, routes, route_by_key, annotated, entity_of, chunk_by_id, origin_ids, primary):
    resolver = Resolver(routes, primary)
    sections, forms = {}, {}
    stub_refs = defaultdict(set)          # (origin, method, template) -> referencing route ids
    by_origin = {}
    for route in routes:
        by_origin.setdefault(format_origin(route), route)

    def add_edge(src, src_type, rel, dst, dst_type, **kw):
        edges.add(src, src_type, rel, dst, dst_type, **kw)

    external = {}                          # unobserved origin -> node id

    def reference_origin(route, target_origin):
        """CALLS edge to a third-party origin the capture never requested."""
        node_id = origin_ids.get(target_origin) or external.get(target_origin)
        if node_id is None:
            if len(external) >= MAX_EXTERNAL_ORIGINS:
                d.LEDGER['graph.external_origins_dropped_by_cap'] += 1
                return
            parsed = urlparse(target_origin)
            node_id = external[target_origin] = d.md5('origin|external|' + target_origin)
            text = f'origin referenced by client code but never requested in the capture: {target_origin}'
            meta = {'scheme': parsed.scheme, 'host': parsed.hostname or '', 'port': parsed.port or 0,
                    'endpoint_template': '{origin}', 'method': '', 'node_kind': 'origin',
                    'is_static': False, 'instance_count': 0, 'doc_kind': 'graph', 'node_type': o.ORIGIN,
                    'anchor_id': node_id, 'observed': False,
                    'summary': d._truncate(f'unobserved origin {target_origin}', d.SUMMARY_CAP)}
            chunks.append({'id': node_id, 'embed_text': text, 'page_content': text, 'metadata': meta})
            d.LEDGER['graph.external_origin_nodes'] += 1
        add_edge(route['id'], o.ROUTE, 'CALLS', node_id, o.ORIGIN)

    def js_edges(route, origin, js):
        for name, version in js.get('libs', []):
            add_edge(route['id'], o.ROUTE, 'USES_LIB', f'lib:{name}@{version}', o.LIB)
        for method, path, _module in js.get('endpoints', []):
            target_origin, target_path = _target_origin(origin, path)
            verb = '' if method == 'ANY' else method
            target, template = resolver.resolve(target_origin, target_path, verb)
            if target is not None:
                if target['id'] != route['id']:
                    add_edge(route['id'], o.ROUTE, 'CALLS', target['id'], o.ROUTE)
            elif target_origin == origin:
                stub_refs[(origin, verb, template)].add(route['id'])
            else:
                d.LEDGER['js.endpoints_on_unobserved_origins'] += 1
                reference_origin(route, target_origin)
        for raw in js.get('origins', []):
            d.LEDGER['js.external_origins'] += 1
            reference_origin(route, _target_origin(origin, raw)[0])

    maps = {}                              # source-map route id -> compact module facts
    for a in annotated:
        if a.get('jsmap'):
            mapped = route_by_key.get((a['scheme'], a['host'], a['port'], a['method'], a['endpoint_template']))
            if mapped is not None:
                maps[mapped['id']] = a['jsmap']

    def add_modules(route, origin, js):
        """Module Sections of one bundle: webpack module names and/or its paired source map."""
        modules = {name: {'endpoints': [(m, p) for m, p, mod in js['endpoints'] if mod == name],
                          'secrets': js['modules'][name].get('secrets', 0)}
                   for name in js.get('modules', {})}
        map_url = js.get('sourcemap_url', '')
        if map_url and not map_url.startswith('data:'):
            map_origin, map_path = _target_origin(origin, urljoin(route['endpoint_template'], map_url))
            map_route, _ = resolver.resolve(map_origin, map_path, 'GET')
            if map_route is not None:
                add_edge(route['id'], o.ROUTE, 'LOADS', map_route['id'], o.ROUTE)
                mapped = maps.get(map_route['id'])
                if mapped:
                    for name, found in mapped['modules'].items():
                        modules[name] = {'endpoints': [tuple(e) for e in found['endpoints']],
                                         'secrets': len(found['secrets'])}
                    js_edges(route, origin, {'endpoints': [(m, p, '') for found in mapped['modules'].values()
                                                           for m, p in found['endpoints']], 'libs': []})
                    d.LEDGER['js.maps_paired'] += 1
        ranked = sorted(modules.items(), key=lambda kv: (-len(kv[1]['endpoints']) - kv[1]['secrets'], kv[0]))
        d.LEDGER['js.modules_dropped_by_cap'] += max(0, len(ranked) - jsfacts.MAX_MODULES_PER_BUNDLE)
        for order, (name, found) in enumerate(ranked[:jsfacts.MAX_MODULES_PER_BUNDLE]):
            section_id = d.md5('module|' + route['id'] + '|' + name)
            shown = ', '.join((f'{m} ' if m != 'ANY' else '') + p for m, p in found['endpoints'][:12])
            text = d._fit([(f"module {name} of client code {route['endpoint_template']}", 200),
                           ('endpoints: ' + shown if shown else '', 600),
                           (f"credential-shaped literals: {found['secrets']}" if found['secrets'] else '', 80)])
            meta = _node_meta(route, 'section', '{section}', '', doc_kind='graph', node_type=o.SECTION,
                              anchor_id=route['id'], section_kind='module', label=name,
                              summary=d._truncate(f'module {name}', d.SUMMARY_CAP))
            chunk = {'id': section_id, 'embed_text': text, 'page_content': text, 'metadata': meta,
                     'embedding_title': name}
            chunks.append(chunk)
            add_edge(route['id'], o.ROUTE, 'CONTAINS', section_id, o.SECTION, ord=order)

    js_seen = set()
    for a in annotated:
        route = route_by_key.get((a['scheme'], a['host'], a['port'], a['method'], a['endpoint_template']))
        if route is None:
            continue
        origin = format_origin(a)
        page, js = a.get('page'), a.get('js')

        if js and (route['id'], a.get('resp_body_sha256', '')) not in js_seen:
            js_seen.add((route['id'], a.get('resp_body_sha256', '')))
            chunk = chunk_by_id[route['id']]
            facts = dict(js, endpoints=[tuple(e) for e in js['endpoints']],
                         secrets=[(n, s, '') for n, s in js['secrets']])
            summary = jsfacts.summary(facts, 'client code', cap=500)
            chunk['embed_text'] = d._fit([(chunk['embed_text'], 1000), (summary, 500)])
            chunk['metadata']['js_endpoints'] = js.get('endpoints_total', 0)
            js_edges(route, origin, js)
            add_modules(route, origin, js)

        if not page:
            continue
        for src in page.get('loads', []):
            target_origin, target_path = _target_origin(origin, src)
            target, _ = resolver.resolve(target_origin, target_path, 'GET')
            if target is not None and target['id'] != route['id']:
                add_edge(route['id'], o.ROUTE, 'LOADS', target['id'], o.ROUTE)
        for link in page.get('links', [])[:MAX_LINKS_PER_PAGE]:
            target_origin, target_path = _target_origin(origin, link)
            target, _ = resolver.resolve(target_origin, target_path, 'GET')
            if target is not None and target['id'] != route['id']:
                add_edge(route['id'], o.ROUTE, 'LINKS_TO', target['id'], o.ROUTE)
        for payload in page.get('payloads', []):
            if payload['sig'] in entity_of:
                add_edge(route['id'], o.ROUTE, 'RETURNS', entity_of[payload['sig']], o.DATA_OBJECT)
        if page.get('js'):
            js_edges(route, origin, page['js'])

        for form in page.get('forms', []):
            if not form['fields']:
                continue
            action = urljoin(route['endpoint_template'], form['action']) if form['action'] else route['endpoint_template']
            target_origin, target_path = _target_origin(origin, action)
            target, template = resolver.resolve(target_origin, target_path, form['method'])
            form_id = d.md5('form|' + '|'.join([origin, form['method'], template, ','.join(sorted(form['fields']))]))
            if form_id not in forms:
                text = d._fit([(f"form {form['method']} {template}", 200),
                               ('fields: ' + ', '.join(form['fields']), 600),
                               ('page: ' + (page.get('title') or route['endpoint_template']), 160)])
                meta = _node_meta(route, 'form', template, form['method'],
                                  doc_kind='graph', node_type=o.FORM, anchor_id=route['id'],
                                  summary=d._truncate(f"form {form['method']} {template} "
                                                      f"({len(form['fields'])} fields)", d.SUMMARY_CAP),
                                  param_names=','.join(form['fields']))
                chunk = {'id': form_id, 'embed_text': text, 'page_content': text, 'metadata': meta,
                         'embedding_title': page.get('title', '')}
                forms[form_id] = chunk
                chunks.append(chunk)
                for name in form['fields']:
                    add_edge(form_id, o.FORM, 'HAS_FIELD', f'param:{name}', o.PARAM)
                if target is not None:
                    add_edge(form_id, o.FORM, 'SUBMITS_TO', target['id'], o.ROUTE)
            add_edge(route['id'], o.ROUTE, 'CONTAINS', form_id, o.FORM)

        for section in page.get('sections', []):
            section_id = d.md5('section|' + origin + '|' + section['hash'])
            if section_id not in sections:
                label = section.get('label') or route['endpoint_template']
                text = d._fit([(f"section of {route['method']} {route['endpoint_template']}: {label}", 200),
                               (section['text'], SECTION_TEXT_CAP)], cap=SECTION_TEXT_CAP + 400)
                meta = _node_meta(route, 'section', '{section}', '',
                                  doc_kind='graph', node_type=o.SECTION, anchor_id=route['id'],
                                  section_kind=section['kind'], label=label,
                                  summary=d._truncate(f"section {label}", d.SUMMARY_CAP))
                chunk = {'id': section_id, 'embed_text': text, 'page_content': section['text'],
                         'metadata': meta, 'embedding_title': label}
                sections[section_id] = chunk
                chunks.append(chunk)
            else:
                sections[section_id]['metadata']['instance_count'] += 1
                d.LEDGER['graph.sections_shared'] += 1
            add_edge(route['id'], o.ROUTE, 'CONTAINS', section_id, o.SECTION, ord=section['ord'])

    # ---- stub routes: named by client code, never requested ----------------
    per_origin = defaultdict(list)
    for (origin, method, template), referrers in stub_refs.items():
        per_origin[origin].append((-len(referrers), template, method, sorted(referrers)))
    for origin, entries in sorted(per_origin.items()):
        entries.sort()
        d.LEDGER['graph.stubs_dropped_by_cap'] += max(0, len(entries) - MAX_STUB_ROUTES_PER_HOST)
        anchor = by_origin.get(origin)
        for _rank, template, method, referrers in entries[:MAX_STUB_ROUTES_PER_HOST]:
            stub_id = d.md5(f'stub|{origin}|{method}|{template}')
            label = f"{method} {template}".strip()
            text = f'route referenced by client code but never requested in the capture: {label}'
            meta = _node_meta(anchor, 'endpoint', template, method, doc_kind='graph', node_type=o.ROUTE,
                              route_kind='endpoint', anchor_id=stub_id, observed=False, instance_count=0,
                              summary=d._truncate(f'unobserved {label}', d.SUMMARY_CAP))
            chunk = {'id': stub_id, 'embed_text': text, 'page_content': text, 'metadata': meta}
            chunks.append(chunk)
            if origin in origin_ids:
                add_edge(origin_ids[origin], o.ORIGIN, 'HAS_ROUTE', stub_id, o.ROUTE)
            for referrer in referrers:
                add_edge(referrer, o.ROUTE, 'CALLS', stub_id, o.ROUTE)
            d.LEDGER['graph.stub_routes'] += 1
