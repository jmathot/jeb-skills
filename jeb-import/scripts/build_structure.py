"""
J.E.B. v2 — Phase 3b: build the `structure` collection (the site map).

Aggregates annotated items into one node per (host, method, endpoint_template)
— SPA shells collapse to a single per-host node — and emits one synthetic
`auth_model` node per host summarising the session/auth model across endpoints.
"""
import argparse
import json
from collections import OrderedDict

import distill as d

CORS_RANK = {'*': 4, 'reflected': 3, 'null': 2, 'specific': 1, '': 0}


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


def build_endpoint_nodes(annotated):
    groups = OrderedDict()
    for a in annotated:
        template = '{spa-shell}' if a['resp_class'] == 'spa_shell' else a['endpoint_template']
        key = (a['host'], a['method'], template)
        groups.setdefault(key, []).append(a)

    nodes = []
    for (host, method, template), items in groups.items():
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
            'host': host, 'method': method, 'endpoint_template': template,
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
        nodes.append(node)
    return nodes


def endpoint_chunk(node):
    embed_text = d.structure_embed_text(node)
    summary = d.structure_summary(node)
    pc = [
        f"{node['node_kind'].upper()}  {node['method']} {node['endpoint_template']}  @ {node['host']}",
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
        'host': node['host'],
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
        'summary': summary,
    }
    node_id = d.md5(f"{node['host']}|{node['method']}|{node['endpoint_template']}|{node['node_kind']}")
    return {'id': node_id, 'embed_text': embed_text,
            'page_content': "\n".join(pc), 'metadata': metadata}


def auth_model_chunk(host, model):
    embed_text = d.auth_model_embed_text(host, model)
    summary = d.auth_model_summary(host, model)
    set_map = model.get('cookies_set_map', {})
    sent_map = model.get('cookies_sent_map', {})
    pc = [
        f"AUTH MODEL  @ {host}",
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
        'host': host,
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
        'summary': summary,
    }
    node_id = d.md5(f"{host}|auth_model")
    return {'id': node_id, 'embed_text': embed_text,
            'page_content': "\n".join(pc), 'metadata': metadata}


def main():
    ap = argparse.ArgumentParser(description="J.E.B. v2 Phase 3b: build structure docs")
    ap.add_argument('input_file', nargs='?', default='annotated_traffic.json')
    ap.add_argument('-o', '--output', default='structure_chunks.json')
    args = ap.parse_args()

    with open(args.input_file) as f:
        data = json.load(f)
    annotated = data['items']
    auth_models = data.get('auth_models', {})

    chunks = [endpoint_chunk(n) for n in build_endpoint_nodes(annotated)]
    for host, model in auth_models.items():
        chunks.append(auth_model_chunk(host, model))

    with open(args.output, 'w') as f:
        json.dump(chunks, f, indent=2)
    print(f"Built {len(chunks)} structure docs "
          f"({len(auth_models)} auth-model node(s)). Saved to {args.output}")


if __name__ == '__main__':
    main()
