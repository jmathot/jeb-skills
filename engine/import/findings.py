"""Structured finding evidence and idempotent identifier repair."""
import json
from urllib.parse import urlparse
import distill as d
from parse import parse_http, decode_transfer, decode_content, decode_text, _header
from storage import batches, delete_ids, lookup_collection, origin, put_records, scan, sync_identifiers
from streaming import IDENTIFIER_VERSION


def pairs_for_finding(data):
    endpoint = data.get('endpoint', '')
    pairs = [('url.' + k, v) for k, v in d.extract_identifier_values(
        urlparse(endpoint).path, [], endpoint)]
    for side in ('request', 'response'):
        raw = data.get(side, '')
        http = parse_http(raw.encode(), is_request=side == 'request')
        if http:
            transferred, error = decode_transfer(http['body'], http['headers'])
            decoded, content_error = decode_content(transferred, http['headers'])
            if not error and not content_error:
                ct = _header(http['headers'], 'content-type')
                pairs += [(side + '.' + k, v) for k, v in d.extract_identifier_values(
                    '', [decode_text(decoded, ct)], content_types=[ct])]
    return pairs


def finding_document(data):
    return json.dumps({'format': 'jeb-finding-v1', **data})


def parse_finding(document):
    try:
        data = json.loads(document)
        if isinstance(data, dict) and data.get('format') == 'jeb-finding-v1':
            return data
    except (ValueError, TypeError):
        pass
    return None


def repair_identifiers(client, force=False):
    if 'attacks' not in {c.name for c in client.list_collections()}:
        return
    col = client.get_collection('attacks', embedding_function=None)
    for row in scan(col, include=('documents', 'metadatas'), page_size=20):
        meta = row['metadatas']
        if not force and (meta.get('identifier_state') == 'legacy-unstructured' or (
                meta.get('identifier_state') == 'complete'
                and meta.get('identifier_version') == IDENTIFIER_VERSION)):
            continue
        data = parse_finding(row['documents'])
        if data is None:
            # Legacy free-form evidence is retained, with explicit repair limits.
            col.update(ids=[row['id']], metadatas=[{'identifier_state': 'legacy-unstructured'}])
            continue
        sync_identifiers(client, 'attacks', [{'id': row['id'],
                          'identifier_pairs': pairs_for_finding(data)}], replace=True)
        col.update(ids=[row['id']], metadatas=[{'identifier_state': 'complete',
                                                'identifier_version': IDENTIFIER_VERSION}])


def finding_edge(finding_id, meta, routes):
    """A TARGETS edge for one finding, or None when no observed route matches.

    `routes` maps (origin, method, template) to a route id. A finding recorded
    without a method falls back to any method on that template."""
    key_origin = origin(meta)
    template = meta.get('endpoint_template', '')
    method = (meta.get('method') or '').upper()
    if method:
        route = routes.get((key_origin, method, template))
    else:
        route = next((rid for (o, _m, t), rid in sorted(routes.items())
                      if (o, t) == (key_origin, template)), None)
    if route is None:
        return None
    return {'id': d.md5(f'{finding_id}|TARGETS|{route}'), 'document': f'finding {finding_id} TARGETS {route}',
            'metadata': {'src': finding_id, 'src_type': 'finding', 'rel': 'TARGETS', 'dst': route,
                         'dst_type': 'route', 'weight': 1.0, 'ord': 0, 'variant_key': ''}}


def sync_finding_edges(client, only=None):
    """Write (and prune) `Finding -TARGETS-> Route` edges; `only` limits to finding ids."""
    names = {c.name for c in client.list_collections()}
    if not {'attacks', 'graph', 'edges'} <= names:
        return 0
    graph = client.get_collection('graph', embedding_function=None)
    routes = {(origin(r['metadatas']), r['metadatas'].get('method', ''),
               r['metadatas'].get('endpoint_template', '')): r['id']
              for r in scan(graph, where={'node_type': 'route'})}
    attacks = client.get_collection('attacks', embedding_function=None)
    kwargs = {'ids': list(only)} if only else {}
    wanted, edges = set(), []
    pages = [attacks.get(include=['metadatas'], **kwargs)] if only else (
        {'ids': [r['id'] for r in page], 'metadatas': [r['metadatas'] for r in page]}
        for page in batches(scan(attacks)))
    for page in pages:
        for finding_id, meta in zip(page['ids'], page['metadatas']):
            edge = finding_edge(finding_id, meta or {}, routes)
            if edge:
                edges.append(edge)
                wanted.add(edge['id'])
    collection = lookup_collection(client, 'edges')
    for batch in batches(edges):
        put_records(collection, batch)
    if not only:
        delete_ids(collection, [r['id'] for r in scan(collection, include=(), where={'src_type': 'finding'})
                                if r['id'] not in wanted])
    return len(edges)
