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
from parse import analysis_text
from storage import origin as format_origin

SPA_ROUTE_THRESHOLD = 4       # identical HTML body across >= N routes => shell
BOILERPLATE_MIN_PAGES = 5     # need this many host pages to infer a template
BOILERPLATE_FRACTION = 0.5    # block on > this fraction of pages => boilerplate
CORS_RANK = {'*': 4, 'matches-origin': 3, 'null': 2, 'specific': 1, '': 0}


def _reconstruct_headers(headers: dict) -> str:
    lines = []
    for k, v in headers.items():
        for piece in str(v).split('\n'):       # repeated headers were joined by \n
            lines.append(f"{k}: {piece}")
    return "\n".join(lines)


def reconstruct_raw(item, full=False) -> str:
    req = item.get('request', {})
    resp = item.get('response', {})
    parts = ["--- REQUEST ---", req.get('line', '')]
    if req.get('headers'):
        parts.append(_reconstruct_headers(req['headers']))
    parts.append("")
    parts.append((analysis_text(req) if full and req.get('body_kind') == 'text'
                  else req.get('body', '')) or '')
    parts.append("")
    parts.append("--- RESPONSE ---")
    parts.append(resp.get('line', ''))
    if resp.get('headers'):
        parts.append(_reconstruct_headers(resp['headers']))
    parts.append("")
    parts.append((analysis_text(resp) if full and resp.get('body_kind') == 'text'
                  else resp.get('body', '')) or '')
    return "\n".join(parts)


def pass_a(items, auth_cookie_names=None):
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
        req_body = (req.get('analysis_body', '') if req.get('body_kind') == 'text'
                    else req.get('body', ''))
        resp_body = (resp.get('analysis_body', '') if resp.get('body_kind') == 'text'
                     else resp.get('body', ''))
        method = item.get('method', '')

        req_ct = d.header_get(req_headers, 'content-type').split(';', 1)[0].strip().lower()
        resp_ct = d.resp_media_type(resp_headers)
        param_names = d.extract_param_names(method, url, req_ct, req_body)
        graphql_operation = d.graphql_operation(req_body, url)
        req_semantic = (d.structured_semantic_values(req_body, d.VARIANT_KEY_VALUES)[:8]
                        if req_body and ('json' in req_ct or d._looks_json(req_body)) else [])
        cookies = (auth_cookie_names.get((scheme, host, port), set())
                   if isinstance(auth_cookie_names, dict) else auth_cookie_names)
        reqf = d.request_features(method, url, req_headers, param_names, cookies)
        req_origin = d.header_get(req_headers, 'origin')

        req_schema_sig, req_schema_keys = '', []
        if req_body and ('json' in req_ct or 'xml' in req_ct):
            req_schema_sig, _, req_schema_keys = d.structured_schema(req_body, req_ct)
        identifiers = d.extract_identifier_values(
            endpoint, [req_body, resp_body], url, [req_ct, resp_ct])

        status_code = d._to_int(item.get('status', ''))
        body_kind = resp.get('body_kind', 'text')
        if body_kind in ('binary', 'undecodable'):
            resp_class = body_kind
        else:
            resp_class = d.classify_response(status_code, resp_headers, resp_body,
                                             resp_ct, file_ext, item.get('mimetype', ''))
        is_static = d.is_static_asset(item.get('mimetype', ''), file_ext, resp_ct)

        is_html = resp_class in ('html_document', 'spa_shell')
        a = {
            'exchange_id': item.get('_exchange_id', ''),
            'capture_id': item.get('_capture_id', ''),
            'url': url, 'method': method, 'status_code': status_code,
            'time': item.get('time', ''),
            'host': host, 'scheme': scheme, 'port': port,
            'endpoint': endpoint,
            'endpoint_template': d.templatize_path(endpoint),
            'path_depth': d.path_depth(endpoint),
            'file_ext': file_ext,
            'req_content_type': req_ct, 'resp_content_type': resp_ct,
            'param_names': param_names, 'param_count': len(param_names),
            'graphql_operation': graphql_operation,
            'req_semantic': req_semantic,
            'req_schema_sig': req_schema_sig, 'req_schema_keys': req_schema_keys,
            'request_variant_sig': d.request_variant_signature(req_body, req_ct),
            'identifiers': identifiers,
            'req_features': reqf,
            '_req_origin': req_origin,
            '_resp_headers': resp_headers,
            '_resp_body': resp_body,
            'resp_class': resp_class,
            'response_variant_sig': d.response_variant_signature(
                resp_class, resp_body, resp_ct,
                d.header_get(resp_headers, 'location')),
            'is_static': is_static,
            'resp_len': d._to_int(item.get('responselength', ''), len(resp_body)),
            'req_body_sha256': req.get('body_sha256', ''),
            'resp_body_sha256': resp.get('body_sha256', ''),
            'req_body_length': req.get('body_length', len(req_body)),
            'resp_body_length': resp.get('body_length', len(resp_body)),
            'req_body_truncated': bool(req.get('truncated')),
            'resp_body_truncated': bool(resp.get('truncated')),
            'req_decode_error': req.get('decode_error', ''),
            'resp_decode_error': resp.get('decode_error', ''),
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
            routes_per_hash[(a['scheme'], a['host'], a['port'],
                             a['_body_hash'])].add(a['endpoint'])

    shell_hashes = set()
    for a in annotated:
        if not a['_body_hash']:
            continue
        key = (a['scheme'], a['host'], a['port'], a['_body_hash'])
        if a['_is_shell_heuristic'] or len(routes_per_hash[key]) >= SPA_ROUTE_THRESHOLD:
            shell_hashes.add(key)

    for a in annotated:
        if a['_body_hash'] and (a['scheme'], a['host'], a['port'],
                                a['_body_hash']) in shell_hashes:
            a['resp_class'] = 'spa_shell'
            a['_html_blocks'] = set()


def pass_c_boilerplate(annotated):
    """Per-host DOM blocks appearing on >50% of distinct routes are boilerplate."""
    pages_by_host = defaultdict(dict)
    for a in annotated:
        if a['resp_class'] == 'html_document':
            origin = (a['scheme'], a['host'], a['port'])
            pages_by_host[origin].setdefault(a['endpoint_template'], set()).update(
                a['_html_blocks'])

    boilerplate = {}
    for origin, route_blocks in pages_by_host.items():
        if len(route_blocks) < BOILERPLATE_MIN_PAGES:
            boilerplate[origin] = set()
            continue
        freq = defaultdict(int)
        for blocks in route_blocks.values():
            for block in blocks:
                freq[block] += 1
        cutoff = len(route_blocks) * BOILERPLATE_FRACTION
        boilerplate[origin] = {b for b, c in freq.items() if c > cutoff}
    return boilerplate


def pass_d_distill(annotated, boilerplate):
    for a in annotated:
        respf = d.response_features(a['_resp_headers'], a.get('_req_origin', ''))
        distilled, schema_sig, schema_keys = d.distill_response(
            a['resp_class'], a['_resp_body'], a['resp_content_type'],
             respf['redirect_location'], boilerplate.get(
                 (a['scheme'], a['host'], a['port']), set()))
        a['resp_features'] = respf
        a['resp_distilled'] = distilled
        a['resp_schema_sig'] = schema_sig
        a['resp_schema_keys'] = schema_keys
        # page title for structure page nodes
        a['page_title'] = ''
        page_marker = distilled.find('page: ')
        if a['resp_class'] in ('html_document', 'spa_shell') and page_marker >= 0:
            a['page_title'] = distilled[page_marker + 6:].split(' | ', 1)[0][:120]
        # drop bulky temp fields
        for k in ('_resp_headers', '_resp_body', '_body_hash',
                  '_is_shell_heuristic', '_html_blocks', '_req_origin', '_content_fp'):
            a.pop(k, None)


def _cookie_name(entry: str) -> str:
    return entry.split('(', 1)[0]


def build_auth_models(annotated):
    models = {}
    origins = defaultdict(list)
    for a in annotated:
        origins[(a['scheme'], a['host'], a['port'])].append(a)

    for (scheme, host, port), items in origins.items():
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
        origin = format_origin({'scheme': scheme, 'host': host, 'port': port})
        models[origin] = {
            'scheme': scheme,
            'host': host,
            'port': port,
            'auth_mechanisms': sorted(mechanisms),
            'cookies_set_map': {k: sorted(v) for k, v in set_map.items()},
            'cookies_sent_map': {k: sorted(v) for k, v in sent_map.items()},
            'token': token,
            'security_headers_missing': app_missing,
            'cors': cors,
        }
    return models


def _content_fp(a):
    """A comparable content fingerprint for the anon-vs-auth differential."""
    body = a.get('_resp_body', '')
    rc = a['resp_class']
    if rc == 'api_structured':
        return a.get('response_variant_sig', '')
    if rc == 'html_document':
        return d.md5(d.page_fingerprint(body) + '|' + d.html_page_summary(body))
    if rc == 'text_other':
        return d.md5(body)
    if rc in ('redirect', 'empty', 'binary', 'undecodable'):
        return a.get('resp_body_sha256', '') or d.md5(body)
    return ''


def _access_class(a, login_fps):
    """Classify what the response actually delivered (not just its status)."""
    sc = a['status_code']
    body = a.get('_resp_body', '')
    rc = a['resp_class']
    if sc in (401, 403):
        return 'denied'
    if rc == 'redirect':
        loc = d.header_get(a.get('_resp_headers', {}), 'location')
        return 'auth_wall' if d.login_redirect(loc) else 'redirect'
    if rc == 'spa_shell':
        return 'shell'
    if rc == 'empty':
        return 'empty'
    if rc == 'static_asset':
        return 'static'
    if rc == 'undecodable':
        return 'unknown'
    if rc == 'binary':
        if a.get('is_static'):
            return 'static'
        return 'data' if 200 <= sc < 300 else 'other'
    if rc == 'html_document':
        # extract_features already fingerprinted this body and persisted it as
        # _login_fp, so reuse it rather than re-parsing the page here.
        fp = a.get('_login_fp')
        if fp is None:
            fp = d.page_fingerprint(body)
        if (fp and fp in login_fps) or d.html_login_signals(body)['is_login']:
            return 'auth_wall'
        return 'data' if 200 <= sc < 300 else 'other'
    if rc in ('api_structured', 'text_other'):
        if d.json_auth_wall(body):
            return 'auth_wall'
        return 'data' if 200 <= sc < 300 else 'other'
    return 'other'


def pass_access(annotated):
    """Content-aware access classification, so a '200 + login page' soft auth
    wall is not mistaken for anonymous access (broken access control)."""
    # Step 1: learn each host's login/auth-wall page fingerprints.
    login_fps = defaultdict(set)
    for a in annotated:
        body = a.get('_resp_body', '')
        if a['resp_class'] in ('html_document', 'spa_shell') and body:
            if d.html_login_signals(body)['is_login'] or d.is_login_path(a['endpoint']):
                fp = d.page_fingerprint(body)
                if fp:
                    login_fps[(a['scheme'], a['host'], a['port'])].add(fp)

    # Step 2: per-item access_class + anonymous outcome flags.
    for a in annotated:
        origin = (a['scheme'], a['host'], a['port'])
        a['access_class'] = _access_class(a, login_fps[origin])
        a['_content_fp'] = _content_fp(a)
        authed = a['req_features']['authenticated']
        a['anon_data_served'] = (not authed) and a['access_class'] == 'data'
        a['soft_denied'] = ((not authed) and a['status_code'] < 400
                            and a['access_class'] in ('auth_wall', 'shell'))

    # Step 3: distinguish shape similarity from exact same-resource content.
    # The comparison request merely carried a credential; acceptance is unknown.
    groups = defaultdict(list)
    for a in annotated:
        groups[(a['scheme'], a['host'], a['port'], a['method'],
                a['endpoint_template'])].append(a)
    for items in groups.values():
        credentialed_schemas = {a['response_variant_sig'] for a in items
                                if a['req_features']['credential_present']
                                and a['access_class'] == 'data'}
        authed_fps = {(a['url'], a.get('req_body_sha256'), a.get('resp_body_sha256')) for a in items
                       if a['req_features']['authenticated'] and a['access_class'] == 'data'
                       and a.get('resp_body_sha256')}
        for a in items:
            a['anon_schema_matches_credentialed'] = bool(
                not a['req_features']['credential_present'] and a['access_class'] == 'data'
                and a['response_variant_sig'] in credentialed_schemas)
            a['anon_matches_auth'] = bool(
                (not a['req_features']['authenticated']) and a['access_class'] == 'data'
                and a.get('resp_body_sha256') and
                (a['url'], a.get('req_body_sha256'), a.get('resp_body_sha256')) in authed_fps)


def annotate(items, auth_cookies=(), auto_detect=True):
    """Shared normalization entry point for cumulative and standalone imports."""
    custom = d.normalize_auth_cookie_names(auth_cookies)
    by_origin = defaultdict(list)
    for item in items:
        p = urlparse(item['url'])
        by_origin[(p.scheme, (p.hostname or '').lower(),
                   p.port or (443 if p.scheme == 'https' else 80))].append(item)
    cookies = {origin: custom | (d.detect_login_cookie_names(group) if auto_detect else set())
               for origin, group in by_origin.items()}
    annotated = pass_a(items, cookies)
    pass_b_spa(annotated)
    boilerplate = pass_c_boilerplate(annotated)
    pass_access(annotated)
    pass_d_distill(annotated, boilerplate)
    return annotated, build_auth_models(annotated)


def main():
    ap = argparse.ArgumentParser(description="J.E.B. v2 Phase 2: normalise + annotate")
    ap.add_argument('input_file', nargs='?', default='parsed_traffic.json')
    ap.add_argument('-o', '--output', required=True, help='explicit export destination')
    ap.add_argument('--auth-cookies', action='append', default=[],
                    help='additional authentication/session cookie names; '
                         'repeat or comma-separate')
    ap.add_argument('--no-auto-detect-auth-cookies', dest='auto_detect_auth_cookies',
                    action='store_false', default=True,
                    help='disable automatic detection of session cookies set by a '
                         'successful login POST (enabled by default)')
    args = ap.parse_args()

    with open(args.input_file) as f:
        items = json.load(f)

    annotated, auth_models = annotate(items, args.auth_cookies, args.auto_detect_auth_cookies)

    out = args.output
    with open(out, 'w') as f:
        json.dump({'items': annotated, 'auth_models': auth_models}, f, indent=2, default=list)

    shells = sum(1 for a in annotated if a['resp_class'] == 'spa_shell')
    walls = sum(1 for a in annotated if a['access_class'] == 'auth_wall')
    print(f"Annotated {len(annotated)} items across {len(auth_models)} host(s); "
          f"{shells} SPA-shell, {walls} auth-wall responses. Saved to {out}")


if __name__ == '__main__':
    main()
