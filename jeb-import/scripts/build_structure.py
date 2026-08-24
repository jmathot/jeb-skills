"""
J.E.B. v2 — Phase 3b: build the `structure` collection (the site map).

Aggregates annotated items into one node per (host, method, endpoint_template)
— SPA shells collapse to a single per-host node — and emits one synthetic
`auth_model` node per host summarising the session/auth model across endpoints.
"""
import argparse
import json
from collections import Counter, OrderedDict, defaultdict

import distill as d

CORS_RANK = {'*': 4, 'reflected': 3, 'null': 2, 'specific': 1, '': 0}
ENTITY_JACCARD_THRESHOLD = 0.6


def _csv(v):
    return ",".join(str(x) for x in v) if isinstance(v, (list, tuple, set)) else (v or "")


def _node_kind(template, method, produces):
    if template == '{spa-shell}':
        return 'page'
    if method == 'GET' and any('html' in p for p in produces):
        return 'page'
    if method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        return 'action'
    return 'endpoint'


def _cookie_name(entry):
    return entry.split('(', 1)[0]


def _dominant_schema(items, sig_field, keys_field):
    """Most common non-empty schema_sig across a group of items, with its keys."""
    sigs = Counter(a[sig_field] for a in items if a.get(sig_field))
    if not sigs:
        return '', []
    sig, _ = sigs.most_common(1)[0]
    keys = next((a[keys_field] for a in items if a.get(sig_field) == sig), [])
    return sig, keys


def _union_identifier_pairs(items):
    seen, out = set(), []
    for a in items:
        for pair in a.get('identifiers', []):
            pair = tuple(pair)
            if pair not in seen:
                seen.add(pair)
                out.append(pair)
    return out[:d.IDENTIFIER_CAP]


def build_endpoint_nodes(annotated):
    groups = OrderedDict()
    for a in annotated:
        template = '{spa-shell}' if a['resp_class'] == 'spa_shell' else a['endpoint_template']
        key = (a['scheme'], a['host'], a['port'], a['method'], template)
        groups.setdefault(key, []).append(a)

    nodes = []
    for (scheme, host, port, method, template), items in groups.items():
        param_names, produces, statuses = set(), set(), set()
        auth_mechs, cookies_set, cookies_sent, sec_missing = set(), set(), set(), set()
        authenticated_ever = is_static = False
        anon_data = anon_soft = anon_denied = False
        cors = ''
        page_title = ''
        example_ids = []
        for a in items:
            param_names.update(a['param_names'])
            if a['resp_content_type']:
                produces.add(a['resp_content_type'])
            statuses.add(a['status_code'])
            reqf, respf = a['req_features'], a['resp_features']
            if reqf['auth_mechanism'] != 'none':
                auth_mechs.add(reqf['auth_mechanism'])
            if reqf['authenticated']:
                authenticated_ever = True
            else:
                # Content-aware access outcome for anonymous requests.
                if a.get('anon_data_served'):
                    anon_data = True
                if a.get('soft_denied'):
                    anon_soft = True
                if a.get('access_class') == 'denied':
                    anon_denied = True
            for entry in respf['set_cookies']:
                cookies_set.add(_cookie_name(entry))
            cookies_sent.update(reqf['cookie_names'])
            sec_missing.update(respf['security_headers_missing'])
            if CORS_RANK.get(respf['cors'], 0) > CORS_RANK.get(cors, 0):
                cors = respf['cors']
            if a['is_static']:
                is_static = True
            if not page_title and a.get('page_title'):
                page_title = a['page_title']
            bid = d.behavior_id(a)
            if bid not in example_ids:
                example_ids.append(bid)

        # Broken access control requires the anon request to receive real data.
        anon_allowed = anon_data
        if anon_data:
            access_control = 'open-data'
        elif anon_soft:
            access_control = 'soft-auth-wall'
        elif anon_denied:
            access_control = 'enforced'
        else:
            access_control = 'unknown'

        produces = sorted(produces)
        node = {
            'scheme': scheme, 'host': host, 'port': port, 'method': method,
            'endpoint_template': template,
            'node_kind': _node_kind(template, method, produces),
            'param_names': sorted(param_names),
            'produces': produces,
            'status_codes': sorted(statuses),
            'authenticated_ever': authenticated_ever,
            'anon_allowed': anon_allowed,
            'anon_soft_denied': anon_soft,
            'access_control': access_control,
            'auth_mechanisms': sorted(auth_mechs),
            'cookies_set': sorted(cookies_set),
            'cookies_sent': sorted(cookies_sent),
            'security_headers_missing': sorted(sec_missing),
            'cors': cors,
            'is_static': is_static,
            'page_title': page_title,
            'path_depth': items[0]['path_depth'],
            'instance_count': len(items),
            'example_ids': example_ids[:5],
        }
        node['resp_schema_sig'], node['resp_schema_keys'] = _dominant_schema(
            items, 'resp_schema_sig', 'resp_schema_keys')
        node['req_schema_sig'], node['req_schema_keys'] = _dominant_schema(
            items, 'req_schema_sig', 'req_schema_keys')
        node['identifier_pairs'] = _union_identifier_pairs(items)
        nodes.append(node)
    return nodes


def endpoint_chunk(node, entity_of=None):
    entity_of = entity_of or {}
    entity_ids = []
    for sig in (node.get('resp_schema_sig', ''), node.get('req_schema_sig', '')):
        eid = entity_of.get(sig)
        if eid and eid not in entity_ids:
            entity_ids.append(eid)
    embed_text = d.structure_embed_text(node)
    summary = d.structure_summary(node)
    pc = [
        f"{node['node_kind'].upper()}  {node['method']} {node['endpoint_template']}  "
        f"@ {node['scheme']}://{node['host']}:{node['port']}",
        f"params: {', '.join(node['param_names'])}",
        f"produces: {', '.join(node['produces'])}",
        f"statuses: {', '.join(str(s) for s in node['status_codes'])}",
        f"auth: mechanisms={', '.join(node['auth_mechanisms']) or 'none'} "
        f"authenticated_ever={node['authenticated_ever']} anon_allowed={node['anon_allowed']}",
        f"access-control: {node['access_control']} "
        f"(anon_soft_denied={node['anon_soft_denied']})",
        f"cookies sent: {', '.join(node['cookies_sent']) or '-'}",
        f"cookies set: {', '.join(node['cookies_set']) or '-'}",
        f"security-headers-missing: {', '.join(node['security_headers_missing']) or '-'}",
        f"cors: {node['cors'] or '-'}",
        f"seen {node['instance_count']}× · behavior ids: {', '.join(node['example_ids'])}",
    ]
    metadata = {
        'doc_kind': 'structure',
        'scheme': node['scheme'],
        'host': node['host'],
        'port': node['port'],
        'endpoint_template': node['endpoint_template'],
        'method': node['method'],
        'node_kind': node['node_kind'],
        'param_names': _csv(node['param_names']),
        'produces': _csv(node['produces']),
        'status_codes': _csv(node['status_codes']),
        'authenticated_ever': node['authenticated_ever'],
        'anon_allowed': node['anon_allowed'],
        'anon_soft_denied': node['anon_soft_denied'],
        'access_control': node['access_control'],
        'auth_mechanisms': _csv(node['auth_mechanisms']),
        'cookies_sent': _csv(node['cookies_sent']),
        'cookies_set': _csv(node['cookies_set']),
        'security_headers_missing': _csv(node['security_headers_missing']),
        'cors': node['cors'],
        'is_static': node['is_static'],
        'instance_count': node['instance_count'],
        'path_depth': node['path_depth'],
        'example_ids': _csv(node['example_ids']),
        'entity_ids': _csv(entity_ids),
        'granularity': 'parent',
        'summary': summary,
    }
    node_id = d.md5(f"{node['scheme']}|{node['host']}|{node['port']}|"
                    f"{node['method']}|{node['endpoint_template']}|{node['node_kind']}")
    return {'id': node_id, 'embed_text': embed_text,
            'page_content': "\n".join(pc), 'metadata': metadata,
            'identifier_pairs': node.get('identifier_pairs', [])}


def auth_model_chunk(origin, model):
    embed_text = d.auth_model_embed_text(origin, model)
    summary = d.auth_model_summary(origin, model)
    scheme = model.get('scheme', '')
    host = model.get('host', origin)
    port = model.get('port', 0)
    set_map = model.get('cookies_set_map', {})
    sent_map = model.get('cookies_sent_map', {})
    pc = [
        f"AUTH MODEL  @ {origin}",
        f"mechanisms: {', '.join(model.get('auth_mechanisms', [])) or 'none'}",
        f"token: {model.get('token', '') or '-'}",
        "cookies set:",
    ] + [f"  {c}  <- {', '.join(eps)}" for c, eps in set_map.items()] + [
        "cookies consumed:",
    ] + [f"  {c}  -> {', '.join(eps)}" for c, eps in sent_map.items()] + [
        f"app posture: security-headers-missing={', '.join(model.get('security_headers_missing', [])) or '-'}; "
        f"cors={model.get('cors', '') or '-'}",
    ]
    metadata = {
        'doc_kind': 'structure',
        'scheme': scheme,
        'host': host,
        'port': port,
        'endpoint_template': '{auth-model}',
        'method': '',
        'node_kind': 'auth_model',
        'param_names': '',
        'produces': '',
        'status_codes': '',
        'authenticated_ever': bool(model.get('auth_mechanisms')),
        'anon_allowed': False,
        'anon_soft_denied': False,
        'access_control': 'unknown',
        'auth_mechanisms': _csv(model.get('auth_mechanisms', [])),
        'cookies_sent': _csv(sorted(sent_map.keys())),
        'cookies_set': _csv(sorted(set_map.keys())),
        'security_headers_missing': _csv(model.get('security_headers_missing', [])),
        'cors': model.get('cors', ''),
        'is_static': False,
        'instance_count': 1,
        'path_depth': 0,
        'example_ids': '',
        'granularity': 'parent',
        'summary': summary,
    }
    node_id = d.md5(f"{origin}|auth_model")
    return {'id': node_id, 'embed_text': embed_text,
            'page_content': "\n".join(pc), 'metadata': metadata}


def _jaccard(a, b):
    if not a or not b:
        return 0.0
    sa, sb = set(a), set(b)
    return len(sa & sb) / len(sa | sb)


def build_entities(nodes):
    """Cross-endpoint structural correlation: group by response/request-body
    schema signature across ALL endpoints (not just within one, unlike
    behavior_collapse_key). A schema seen at 2+ distinct (method, template)
    pairs -- whether as a response shape, a request-body shape, or one
    endpoint's request matching another's response -- becomes one entity node
    linking every producing/consuming route. Near-identical (but not exactly
    equal) schemas are recorded as lower-confidence `related` matches."""
    by_sig = OrderedDict()
    for n in nodes:
        ep = (n['method'], n['endpoint_template'])
        rsig, rkeys = n.get('resp_schema_sig', ''), n.get('resp_schema_keys', [])
        if rsig:
            e = by_sig.setdefault(rsig, {'keys': rkeys, 'produced_by': [], 'consumed_by': []})
            if ep not in e['produced_by']:
                e['produced_by'].append(ep)
        qsig, qkeys = n.get('req_schema_sig', ''), n.get('req_schema_keys', [])
        if qsig:
            e = by_sig.setdefault(qsig, {'keys': qkeys, 'produced_by': [], 'consumed_by': []})
            if ep not in e['consumed_by']:
                e['consumed_by'].append(ep)

    entities, entity_of = [], {}
    for sig, e in by_sig.items():
        if len(set(e['produced_by']) | set(e['consumed_by'])) < 2:
            continue
        e['schema_sig'] = sig
        e['likely_identifier_field'] = d.likely_identifier_field(e['keys'])
        entities.append(e)
        entity_of[sig] = d.md5(f"entity|{sig}")

    for i, e1 in enumerate(entities):
        related = []
        for j, e2 in enumerate(entities):
            if i == j:
                continue
            score = _jaccard(e1['keys'], e2['keys'])
            if score >= ENTITY_JACCARD_THRESHOLD:
                related.append((e2['schema_sig'], round(score, 2)))
        e1['related'] = sorted(related, key=lambda x: -x[1])[:5]

    return entities, entity_of


def entity_chunk(entity, entity_id):
    embed_text = d.entity_embed_text(entity)
    summary = d.entity_summary(entity)
    pc = [
        f"ENTITY  identifier_field={entity.get('likely_identifier_field') or '-'}",
        f"fields: {', '.join(entity.get('keys', []))}",
        "produced by:",
    ] + [f"  {m} {t}" for m, t in entity.get('produced_by', [])] + [
        "consumed by:",
    ] + [f"  {m} {t}" for m, t in entity.get('consumed_by', [])]
    if entity.get('related'):
        pc.append("related schemas (fuzzy match): " +
                   ", ".join(f"{sig[:8]}~{score}" for sig, score in entity['related']))
    metadata = {
        'doc_kind': 'structure',
        'scheme': '', 'host': '', 'port': 0,
        'endpoint_template': '{entity}',
        'method': '',
        'node_kind': 'entity',
        'param_names': '',
        'produces': '',
        'status_codes': '',
        'authenticated_ever': False,
        'anon_allowed': False,
        'anon_soft_denied': False,
        'access_control': 'unknown',
        'auth_mechanisms': '',
        'cookies_sent': '',
        'cookies_set': '',
        'security_headers_missing': '',
        'cors': '',
        'is_static': False,
        'instance_count': len(set(entity.get('produced_by', [])) | set(entity.get('consumed_by', []))),
        'path_depth': 0,
        'example_ids': '',
        'entity_ids': '',
        'schema_sig': entity['schema_sig'],
        'identifier_field': entity.get('likely_identifier_field', ''),
        'produced_by': _csv([f"{m} {t}" for m, t in entity.get('produced_by', [])]),
        'consumed_by': _csv([f"{m} {t}" for m, t in entity.get('consumed_by', [])]),
        'granularity': 'parent',
        'summary': summary,
    }
    return {'id': entity_id, 'embed_text': embed_text,
            'page_content': "\n".join(pc), 'metadata': metadata}


def build_segments(nodes, auth_models, entity_of=None):
    chunks = []
    for node in nodes:
        parent = endpoint_chunk(node, entity_of)
        for representation, text in d.structure_segment_texts(node).items():
            metadata = dict(parent['metadata'])
            metadata.update({'parent_id': parent['id'], 'representation': representation,
                             'granularity': 'segment'})
            chunks.append({
                'id': d.md5(f"{parent['id']}|{representation}"),
                'embed_text': text,
                'page_content': text,
                'metadata': metadata,
            })
    for origin, model in auth_models.items():
        parent = auth_model_chunk(origin, model)
        metadata = dict(parent['metadata'])
        metadata.update({'parent_id': parent['id'], 'representation': 'auth_model',
                         'granularity': 'segment'})
        chunks.append({
            'id': d.md5(f"{parent['id']}|auth_model"),
            'embed_text': parent['embed_text'],
            'page_content': parent['embed_text'],
            'metadata': metadata,
        })
    return chunks


def main():
    ap = argparse.ArgumentParser(description="J.E.B. v3 Phase 3b: build structure docs")
    ap.add_argument('input_file', nargs='?', default='annotated_traffic.json')
    ap.add_argument('-o', '--output', default='structure_chunks.json')
    args = ap.parse_args()

    with open(args.input_file) as f:
        data = json.load(f)
    annotated = data['items']
    auth_models = data.get('auth_models', {})

    nodes = build_endpoint_nodes(annotated)
    entities, entity_of = build_entities(nodes)
    chunks = [endpoint_chunk(n, entity_of) for n in nodes]
    for origin, model in auth_models.items():
        chunks.append(auth_model_chunk(origin, model))
    for entity in entities:
        chunks.append(entity_chunk(entity, entity_of[entity['schema_sig']]))
    n_parents = len(chunks)

    chunks += build_segments(nodes, auth_models, entity_of)

    with open(args.output, 'w') as f:
        json.dump(chunks, f, indent=2)
    print(f"Built {n_parents} structure docs "
          f"({len(auth_models)} auth-model node(s), {len(entities)} entity node(s)) "
          f"+ {len(chunks) - n_parents} semantic segments. Saved to {args.output}")


if __name__ == '__main__':
    main()
