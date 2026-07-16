"""
J.E.B. v2 — Phase 2: normalise + annotate parsed items.

Runs the corpus-level passes that need to see the whole capture at once, then
annotates every item with the value-suppressed features the builders consume:

  Pass A  per-item: url decomposition, endpoint template, params, request
          features, response media type, initial response class, and (for HTML)
          a content hash + text blocks.
  Pass B  SPA-shell detection: an HTML body served at many distinct routes, or a
          near-empty body with a JS mount point, collapses to `spa_shell`.
  Pass C  MPA boilerplate: per host, DOM text blocks appearing on >50% of pages
          (>=5 pages) are treated as template chrome and subtracted.
  Pass D  emit annotated items (distilled response + response features + raw doc).
  Auth-model aggregation: per host, which cookies are set vs consumed where,
          auth mechanisms, token shape, and the app-wide missing-header posture.

Output: annotated_<name>.json = {"items": [...], "auth_models": {host: {...}}}.
"""
import argparse
import json
import os
from collections import defaultdict
from urllib.parse import urlparse

import distill as d

SPA_ROUTE_THRESHOLD = 4       # identical HTML body across >= N routes => shell
BOILERPLATE_MIN_PAGES = 5     # need this many host pages to infer a template
BOILERPLATE_FRACTION = 0.5    # block on > this fraction of pages => boilerplate
CORS_RANK = {'*': 4, 'reflected': 3, 'null': 2, 'specific': 1, '': 0}


def _reconstruct_headers(headers: dict) -> str:
    lines = []
    for k, v in headers.items():
        for piece in str(v).split('\n'):       # repeated headers were joined by \n
            lines.append(f"{k}: {piece}")
    return "\n".join(lines)


def reconstruct_raw(item) -> str:
    req = item.get('request', {})
    resp = item.get('response', {})
    parts = ["--- REQUEST ---", req.get('line', '')]
    if req.get('headers'):
        parts.append(_reconstruct_headers(req['headers']))
    parts.append("")
    parts.append(req.get('body', '') or '')
    parts.append("")
    parts.append("--- RESPONSE ---")
    parts.append(resp.get('line', ''))
    if resp.get('headers'):
        parts.append(_reconstruct_headers(resp['headers']))
    parts.append("")
    parts.append(resp.get('body', '') or '')
    return "\n".join(parts)


def pass_a(items):
    annotated = []
    for item in items:
        url = item.get('url', '')
        p = urlparse(url)
        endpoint = p.path or '/'
        host = (p.hostname or '').lower()
        scheme = p.scheme or ''
        port = p.port or (443 if scheme == 'https' else 80)
        seg = endpoint.rsplit('/', 1)[-1]
        file_ext = seg.rsplit('.', 1)[-1].lower() if '.' in seg else ''

        req = item.get('request', {})
        resp = item.get('response', {})
        req_headers = req.get('headers', {})
        resp_headers = resp.get('headers', {})
        req_body = req.get('body', '')
        resp_body = resp.get('body', '')
        method = item.get('method', '')

        req_ct = d.header_get(req_headers, 'content-type').split(';', 1)[0].strip().lower()
        resp_ct = d.resp_media_type(resp_headers)
        param_names = d.extract_param_names(method, url, req_ct, req_body)
        reqf = d.request_features(method, url, req_headers, param_names)
        req_origin = d.header_get(req_headers, 'origin')

        status_code = d._to_int(item.get('status', ''))
        resp_class = d.classify_response(status_code, resp_headers, resp_body,
                                         resp_ct, file_ext, item.get('mimetype', ''))
        is_static = d.is_static_asset(item.get('mimetype', ''), file_ext, resp_ct)

        is_html = resp_class in ('html_document', 'spa_shell')
        a = {
            'url': url, 'method': method, 'status_code': status_code,
            'time': item.get('time', ''),
            'host': host, 'scheme': scheme, 'port': port,
            'endpoint': endpoint,
            'endpoint_template': d.templatize_path(endpoint),
            'path_depth': d.path_depth(endpoint),
            'file_ext': file_ext,
            'req_content_type': req_ct, 'resp_content_type': resp_ct,
            'param_names': param_names, 'param_count': len(param_names),
            'req_features': reqf,
            '_req_origin': req_origin,
            '_resp_headers': resp_headers,
            '_resp_body': resp_body,
            'resp_class': resp_class,
            'is_static': is_static,
            'resp_len': d._to_int(item.get('responselength', ''), len(resp_body)),
            'raw': reconstruct_raw(item),
            '_body_hash': d.md5(resp_body) if is_html else '',
            '_is_shell_heuristic': (is_html and d.is_spa_shell_html(resp_body)),
            '_html_blocks': d.html_text_blocks(resp_body) if resp_class == 'html_document' else set(),
        }
        annotated.append(a)
    return annotated


def pass_b_spa(annotated):
    """Mark shells: identical HTML body at many routes, or near-empty + mount point."""
    routes_per_hash = defaultdict(set)
    for a in annotated:
        if a['_body_hash']:
            routes_per_hash[(a['host'], a['_body_hash'])].add(a['endpoint'])

    shell_hashes = set()
    for a in annotated:
        if not a['_body_hash']:
            continue
        key = (a['host'], a['_body_hash'])
        if a['_is_shell_heuristic'] or len(routes_per_hash[key]) >= SPA_ROUTE_THRESHOLD:
            shell_hashes.add(key)

    for a in annotated:
        if a['_body_hash'] and (a['host'], a['_body_hash']) in shell_hashes:
            a['resp_class'] = 'spa_shell'
            a['_html_blocks'] = set()


def pass_c_boilerplate(annotated):
    """Per-host DOM blocks appearing on >50% of pages become boilerplate."""
    pages_by_host = defaultdict(list)
    for a in annotated:
        if a['resp_class'] == 'html_document':
            pages_by_host[a['host']].append(a)

    boilerplate = {}
    for host, pages in pages_by_host.items():
        if len(pages) < BOILERPLATE_MIN_PAGES:
            boilerplate[host] = set()
            continue
        freq = defaultdict(int)
        for a in pages:
            for block in a['_html_blocks']:
                freq[block] += 1
        cutoff = len(pages) * BOILERPLATE_FRACTION
        boilerplate[host] = {b for b, c in freq.items() if c > cutoff}
    return boilerplate


def pass_d_distill(annotated, boilerplate):
    for a in annotated:
        respf = d.response_features(a['_resp_headers'], a.get('_req_origin', ''))
        distilled, schema_sig = d.distill_response(
            a['resp_class'], a['_resp_body'], a['resp_content_type'],
            respf['redirect_location'], boilerplate.get(a['host'], set()))
        a['resp_features'] = respf
        a['resp_distilled'] = distilled
        a['resp_schema_sig'] = schema_sig
        # page title for structure page nodes
        a['page_title'] = ''
        if a['resp_class'] == 'html_document' and distilled.startswith('page: '):
            a['page_title'] = distilled[6:].split(' | ', 1)[0][:120]
        # drop bulky temp fields
        for k in ('_resp_headers', '_resp_body', '_body_hash',
                  '_is_shell_heuristic', '_html_blocks', '_req_origin'):
            a.pop(k, None)


def _cookie_name(entry: str) -> str:
    return entry.split('(', 1)[0]


def build_auth_models(annotated):
    models = {}
    hosts = defaultdict(list)
    for a in annotated:
        hosts[a['host']].append(a)

    for host, items in hosts.items():
        mechanisms = set()
        set_map = defaultdict(set)
        sent_map = defaultdict(set)
        token = ''
        cors = ''
        miss_count = defaultdict(int)
        total_dynamic = 0
        for a in items:
            reqf, respf = a['req_features'], a['resp_features']
            if reqf['auth_mechanism'] != 'none':
                mechanisms.add(reqf['auth_mechanism'])
            for c in reqf['cookie_names']:
                sent_map[c].add(a['endpoint_template'])
            for entry in respf['set_cookies']:
                set_map[_cookie_name(entry)].add(a['endpoint_template'])
            if not token and reqf['jwt']:
                token = "jwt " + reqf['jwt']
            if CORS_RANK.get(respf['cors'], 0) > CORS_RANK.get(cors, 0):
                cors = respf['cors']
            if not a['is_static'] and a['resp_class'] not in ('redirect', 'empty'):
                total_dynamic += 1
                for h in respf['security_headers_missing']:
                    miss_count[h] += 1

        app_missing = sorted(h for h, c in miss_count.items()
                             if total_dynamic and c / total_dynamic > 0.5)
        models[host] = {
            'auth_mechanisms': sorted(mechanisms),
            'cookies_set_map': {k: sorted(v) for k, v in set_map.items()},
            'cookies_sent_map': {k: sorted(v) for k, v in sent_map.items()},
            'token': token,
            'security_headers_missing': app_missing,
            'cors': cors,
        }
    return models


def main():
    ap = argparse.ArgumentParser(description="J.E.B. v2 Phase 2: normalise + annotate")
    ap.add_argument('input_file', nargs='?', default='parsed_traffic.json')
    ap.add_argument('-o', '--output', default=None)
    args = ap.parse_args()

    with open(args.input_file) as f:
        items = json.load(f)

    annotated = pass_a(items)
    pass_b_spa(annotated)
    boilerplate = pass_c_boilerplate(annotated)
    pass_d_distill(annotated, boilerplate)
    auth_models = build_auth_models(annotated)

    out = args.output
    if out is None:
        base, ext = os.path.splitext(args.input_file)
        out = f"{base}_annotated{ext or '.json'}"
    with open(out, 'w') as f:
        json.dump({'items': annotated, 'auth_models': auth_models}, f, indent=2, default=list)

    shells = sum(1 for a in annotated if a['resp_class'] == 'spa_shell')
    print(f"Annotated {len(annotated)} items across {len(auth_models)} host(s); "
          f"{shells} SPA-shell responses. Saved to {out}")


if __name__ == '__main__':
    main()
