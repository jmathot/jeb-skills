"""
Build the knowledge graph: embedded `graph` nodes plus typed `edges`.

Pure: annotated observations in, (chunks, edges) out, no Chroma access. Reuses the
per-class builders in `build_structure` / `build_behavior` for node content and
metadata, then adds node typing, the edges between them and a context header per
node derived from its one-hop neighbours (deterministic, no LLM).

Node ids are the ids those builders already produced, so findings that point at a
behavior id keep resolving.
"""
from collections import OrderedDict, defaultdict

import build_behavior as bb
import build_structure as bs
import distill as d
import ontology as o
from storage import origin as format_origin

CONTEXT_CAP = 400       # metadata.context
TITLE_CAP = 200         # embedding.doc_prefix keeps this much of the title slot
MAX_CONTEXT_ITEMS = 4

# Aggregates now carried by edges; kept out of node metadata.
_EDGE_BACKED = ('example_ids', 'entity_ids', 'variant_ids', 'produced_by', 'consumed_by')


def edge_id(src, rel, dst):
    return d.md5(f'{src}|{rel}|{dst}')


class EdgeSet:
    """Validated, de-duplicated edges."""

    def __init__(self):
        self._edges = OrderedDict()

    def add(self, src, src_type, rel, dst, dst_type, weight=1.0, ord=0, variant_key=''):
        edge = o.validate_edge({'src': src, 'src_type': src_type, 'rel': rel,
                                'dst': dst, 'dst_type': dst_type})
        key = edge_id(src, rel, dst)
        if key in self._edges:
            return
        edge.update(weight=float(weight), ord=int(ord), variant_key=variant_key)
        self._edges[key] = {'id': key, 'metadata': edge,
                            'document': f'{src_type} {src} {rel} {dst_type} {dst}'}

    def __iter__(self):
        return iter(self._edges.values())

    def __len__(self):
        return len(self._edges)


def _typed(chunk, node_type, anchor_id, route_kind=''):
    meta = chunk['metadata']
    for key in _EDGE_BACKED:
        meta.pop(key, None)
    meta.pop('granularity', None)
    meta.update(doc_kind='graph', node_type=node_type, anchor_id=anchor_id)
    if route_kind:
        meta['route_kind'] = route_kind
    return chunk


def _literal(kind, name):
    return f'{kind}:{name}'


def _route_key(meta_or_item):
    return (meta_or_item['scheme'], meta_or_item['host'], meta_or_item['port'],
            meta_or_item['method'], meta_or_item.get('endpoint_template'))


def _primary(routes):
    """The representative route of one template: pages first, then GET."""
    kind_rank = {'page': 0, 'endpoint': 1, 'action': 2}
    return min(routes, key=lambda r: (kind_rank.get(r['node_kind'], 3), r['method'] != 'GET',
                                      r['method'], r['id']))


def _posture_signature(node):
    return (tuple(node.get('security_headers_missing', [])), node.get('cors', ''))


def _posture_chunk(signature, route_count):
    missing, cors = signature
    parts = ['security posture']
    if missing:
        parts.append('missing security headers: ' + ', '.join(d.header_words(missing)))
    if cors:
        parts.append('cors: ' + d.cors_words(cors))
    parts.append(f'shared by {route_count} routes')
    text = d._fit([(p, 300) for p in parts])
    node_id = d.md5('posture|' + '|'.join(missing) + '|' + cors)
    meta = {
        'scheme': '', 'host': '', 'port': 0, 'endpoint_template': '{posture}', 'method': '',
        'node_kind': 'posture', 'security_headers_missing': ','.join(missing), 'cors': cors,
        'is_static': False, 'instance_count': route_count,
        'summary': d._truncate(f"posture: missing {', '.join(missing) or '-'} · cors {cors or '-'} · "
                               f"{route_count} routes", d.SUMMARY_CAP),
    }
    return {'id': node_id, 'embed_text': text, 'page_content': text, 'metadata': meta}


def _entity_label(entity):
    keys = entity.get('keys', [])[:4]
    return 'object(' + ','.join(keys) + ')' if keys else 'object'


def _route_label(meta):
    return f"{meta.get('method', '')} {meta.get('endpoint_template', '')}".strip()


def build_graph(annotated, models):
    """-> (chunks, edges). Page and client-code facts ride on the annotated
    observations (`a['page']`, `a['js']`) and become Section/Form nodes, stub
    routes and LINKS_TO/LOADS/CALLS edges (see `build_pages`)."""
    chunks, edges = [], EdgeSet()

    nodes = bs.build_endpoint_nodes(annotated)
    payloads = [(a, p['sig'], p['keys']) for a in annotated for p in (a.get('page') or {}).get('payloads', [])]
    entities, entity_of = bs.build_entities(nodes, extra=payloads)
    entity_by_id = {entity_of[e['schema_sig']]: e for e in entities}

    # ---- routes ------------------------------------------------------------
    routes, route_by_key, routes_by_origin = [], {}, defaultdict(list)
    for node in nodes:
        chunk = bs.endpoint_chunk(node, entity_of)
        _typed(chunk, o.ROUTE, chunk['id'], route_kind='asset' if node['is_static'] else node['node_kind'])
        chunk['metadata']['observed'] = True
        chunks.append(chunk)
        view = dict(chunk['metadata'], id=chunk['id'], node=node)
        routes.append(view)
        route_by_key[_route_key(node)] = view
        routes_by_origin[format_origin(node)].append(view)

    # ---- origins -----------------------------------------------------------
    origin_ids = {}
    for origin_name, model in models.items():
        chunk = bs.auth_model_chunk(origin_name, model)
        _typed(chunk, o.ORIGIN, chunk['id'])
        chunks.append(chunk)
        origin_ids[origin_name] = chunk['id']
        for route in routes_by_origin.get(origin_name, []):
            edges.add(chunk['id'], o.ORIGIN, 'HAS_ROUTE', route['id'], o.ROUTE)

    # ---- CHILD_OF: nearest ancestor template on the same origin -------------
    for origin_name, group in routes_by_origin.items():
        by_template = defaultdict(list)
        for route in group:
            by_template[route['endpoint_template']].append(route)
        for route in group:
            segments = [s for s in route['endpoint_template'].split('/') if s]
            for cut in range(len(segments) - 1, -1, -1):
                ancestor = '/' + '/'.join(segments[:cut])
                if ancestor in by_template:
                    edges.add(route['id'], o.ROUTE, 'CHILD_OF',
                              _primary(by_template[ancestor])['id'], o.ROUTE)
                    break

    # ---- data objects ------------------------------------------------------
    for entity in entities:
        chunk = bs.entity_chunk(entity, entity_of[entity['schema_sig']])
        _typed(chunk, o.DATA_OBJECT, chunk['id'])
        chunk['metadata']['shared'] = True
        chunks.append(chunk)
        for other_sig, score in entity.get('related', []):
            if other_sig in entity_of:
                edges.add(chunk['id'], o.DATA_OBJECT, 'RELATED', entity_of[other_sig],
                          o.DATA_OBJECT, weight=score)

    # ---- route -> data object / param / cookie edges -----------------------
    for route in routes:
        node = route['node']
        if node.get('resp_schema_sig') in entity_of:
            edges.add(route['id'], o.ROUTE, 'RETURNS', entity_of[node['resp_schema_sig']], o.DATA_OBJECT)
        if node.get('req_schema_sig') in entity_of:
            edges.add(route['id'], o.ROUTE, 'ACCEPTS', entity_of[node['req_schema_sig']], o.DATA_OBJECT)
        for name in node['param_names']:
            edges.add(route['id'], o.ROUTE, 'ACCEPTS', _literal('param', name), o.PARAM)
        for name in node['cookies_set']:
            edges.add(route['id'], o.ROUTE, 'SETS_COOKIE', _literal('cookie', name), o.COOKIE)
        for name in node['cookies_sent']:
            edges.add(route['id'], o.ROUTE, 'SENDS_COOKIE', _literal('cookie', name), o.COOKIE)

    # ---- posture (only where it is actually shared) ------------------------
    by_posture = defaultdict(list)
    for route in routes:
        signature = _posture_signature(route['node'])
        if any(signature):
            by_posture[signature].append(route)
    postures = {}
    for signature, group in by_posture.items():
        if len(group) < 2:
            continue
        chunk = _posture_chunk(signature, len(group))
        _typed(chunk, o.POSTURE, chunk['id'])
        chunks.append(chunk)
        postures[signature] = chunk['id']
        for route in group:
            edges.add(route['id'], o.ROUTE, 'HAS_POSTURE', chunk['id'], o.POSTURE)

    # ---- behaviors ---------------------------------------------------------
    groups = OrderedDict()
    for a in annotated:
        groups.setdefault(d.behavior_collapse_key(a), []).append(a)
    behavior_chunks = []
    for items in groups.values():
        rep, parent_id, metadata, variant_groups, selected = bb._group_metadata(items)
        route = route_by_key.get(_route_key(rep))
        if route is None:
            continue
        d.LEDGER['behavior.parents'] += 1
        if len(variant_groups) > 1:
            d.LEDGER['behavior.parents_with_variants'] += 1
            d.LEDGER['behavior.variant_edges'] += len(selected)
            d.LEDGER['behavior.variant_edges_dropped_by_cap'] += len(variant_groups) - len(selected)
        page_content = rep['raw']
        if len(items) > 1:
            urls = list(OrderedDict.fromkeys(i['url'] for i in items))[:5]
            page_content += (f"\n\n--- COLLAPSED: {len(items)} instances; examples ---\n"
                             + "\n".join(urls))
        chunk = {'id': parent_id, 'embed_text': d.behavior_embed_text(rep),
                 'embedding_title': rep.get('page_title', ''),
                 'page_content': page_content, 'metadata': metadata}
        _typed(chunk, o.BEHAVIOR, route['id'])
        chunk['metadata']['route_kind'] = route['route_kind']
        behavior_chunks.append(chunk)
        edges.add(route['id'], o.ROUTE, 'HAS_BEHAVIOR', parent_id, o.BEHAVIOR)
        if rep.get('resp_schema_sig') in entity_of:
            edges.add(parent_id, o.BEHAVIOR, 'RETURNS', entity_of[rep['resp_schema_sig']], o.DATA_OBJECT)
        for position, (key, variant_items) in enumerate(selected.items()):
            variant_rep = bb._representative(variant_items)
            edges.add(parent_id, o.BEHAVIOR, 'OBSERVED_IN', variant_rep['exchange_id'], o.EXCHANGE,
                      weight=len(variant_items), ord=position,
                      variant_key=bb._variant_id(parent_id, key))
    chunks.extend(behavior_chunks)

    from build_pages import add_page_nodes
    add_page_nodes(chunks, edges, routes, route_by_key, annotated, entity_of,
                   {c['id']: c for c in chunks}, origin_ids, _primary)

    _enrich(chunks, edges, entity_by_id)
    for chunk in chunks:
        d.LEDGER[f"graph.nodes.{chunk['metadata']['node_type']}"] += 1
    for edge in edges:
        d.LEDGER[f"graph.edges.{edge['metadata']['rel']}"] += 1
    return chunks, edges


def _enrich(chunks, edges, entity_by_id):
    """Second pass: a one-hop context header per node, in `metadata.context` and the
    embedding title slot. Node text keeps only what is specific to the node."""
    by_id = {c['id']: c for c in chunks}
    out, inc = defaultdict(list), defaultdict(list)
    for edge in edges:
        m = edge['metadata']
        out[m['src']].append(m)
        inc[m['dst']].append(m)

    def label(node_id):
        chunk = by_id.get(node_id)
        if chunk is None:
            return node_id.split(':', 1)[-1]
        meta = chunk['metadata']
        if meta['node_type'] == o.DATA_OBJECT:
            return _entity_label(entity_by_id[node_id]) if node_id in entity_by_id else 'object'
        return _route_label(meta) or meta['node_type']

    def listing(prefix, ids):
        ids = list(dict.fromkeys(ids))
        if not ids:
            return ''
        shown = ', '.join(label(i) for i in ids[:MAX_CONTEXT_ITEMS])
        more = f' +{len(ids) - MAX_CONTEXT_ITEMS}' if len(ids) > MAX_CONTEXT_ITEMS else ''
        return f'{prefix}: {shown}{more}'

    for chunk in chunks:
        meta = chunk['metadata']
        node_id, kind = chunk['id'], meta['node_type']
        parts = []
        if kind == o.ROUTE:
            parts.append(listing('returns', [e['dst'] for e in out[node_id] if e['rel'] == 'RETURNS']))
            parts.append(listing('accepts', [e['dst'] for e in out[node_id]
                                             if e['rel'] == 'ACCEPTS' and e['dst_type'] == o.DATA_OBJECT]))
            parts.append(listing('child of', [e['dst'] for e in out[node_id] if e['rel'] == 'CHILD_OF']))
        elif kind == o.BEHAVIOR:
            anchor = by_id.get(meta['anchor_id'])
            if anchor is not None:
                parts.append('route: ' + label(anchor['id']))
            parts.append(listing('returns', [e['dst'] for e in out[node_id] if e['rel'] == 'RETURNS']))
        elif kind == o.DATA_OBJECT:
            parts.append(listing('returned by', [e['src'] for e in inc[node_id] if e['rel'] == 'RETURNS'
                                                 and e['src_type'] == o.ROUTE]))
            parts.append(listing('accepted by', [e['src'] for e in inc[node_id] if e['rel'] == 'ACCEPTS']))
        elif kind == o.POSTURE:
            parts.append(listing('applies to', [e['src'] for e in inc[node_id] if e['rel'] == 'HAS_POSTURE']))
        elif kind == o.ORIGIN:
            parts.append(f"{sum(1 for e in out[node_id] if e['rel'] == 'HAS_ROUTE')} routes")
        elif kind in (o.SECTION, o.FORM):
            parts.append(listing('on', [e['src'] for e in inc[node_id] if e['rel'] == 'CONTAINS']))
            parts.append(listing('submits to', [e['dst'] for e in out[node_id] if e['rel'] == 'SUBMITS_TO']))
        context = ' · '.join(p for p in parts if p)[:CONTEXT_CAP]
        meta['context'] = context
        title = ' · '.join(p for p in (chunk.get('embedding_title', ''), context) if p)
        if title:
            chunk['embedding_title'] = title[:TITLE_CAP]
