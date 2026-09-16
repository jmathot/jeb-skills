"""Compact corpus passes; full HTTP is read one observation at a time."""
from collections import defaultdict

import distill as d
import normalize as n
from storage import origin

FEATURE_VERSION = 'features-v2'
IDENTIFIER_VERSION = 'identifiers-v2'
PARSER_VERSION = 'parser-v2'


def extract_features(item):
    a = n.pass_a([item])[0]
    body = a['_resp_body']
    a['_login_fp'] = d.page_fingerprint(body) if a['resp_class'] in ('html_document', 'spa_shell') else ''
    a['_login_page'] = bool(a['_login_fp'] and (
        d.html_login_signals(body)['is_login'] or d.is_login_path(a['endpoint'])))
    a['_base_access'] = n._access_class(a, set())
    a['_detected_cookies'] = sorted(d.detect_login_cookie_names([item]))
    # Keep bounded credential features for reclassification, never raw token values.
    a['_cookie_names'] = d.cookie_names_from_request(item.get('request', {}).get('headers', {}))
    a['_html_blocks'] = sorted(a['_html_blocks'])
    for key in ('raw', '_resp_body', '_resp_headers', '_req_origin', 'identifiers'):
        a.pop(key, None)
    return a


def identifier_pairs(item):
    pairs = [('url.' + field, value) for field, value in
             d.extract_identifier_values(d.urlparse(item['url']).path, [], item['url'])]
    for side in ('request', 'response'):
        http = item.get(side, {})
        pairs += [(side + '.' + field, value) for field, value in
                  d.extract_identifier_values('', [http.get('analysis_body', '')], content_types=[
                      d.header_get(http.get('headers', {}), 'content-type')])]
    return pairs


def annotate_features(records, load_item, config):
    """Only compact feature records remain resident across global passes."""
    cookies, login_fps = defaultdict(set), defaultdict(set)
    custom = set(config['auth_cookies'])
    for a in records:
        if config['auto_detect']:
            cookies[origin(a)].update(a['_detected_cookies'])
        if a['_login_page']:
            login_fps[origin(a)].add(a['_login_fp'])
    n.pass_b_spa(records)
    boilerplate = n.pass_c_boilerplate(records)
    for a in records:
        # Refresh request credential inference with the actual request, scoped to origin.
        item = load_item(a['exchange_id'])
        a['req_features'] = d.request_features(a['method'], a['url'],
            item.get('request', {}).get('headers', {}), a['param_names'],
            custom | cookies[origin(a)])
        response = item.get('response', {})
        a['_resp_body'] = (response.get('analysis_body', '') if response.get('body_kind') == 'text'
                           else response.get('body', ''))
        a['_resp_headers'] = response.get('headers', {})
        a['_req_origin'] = d.header_get(item.get('request', {}).get('headers', {}), 'origin')
        a['access_class'] = n._access_class(a, login_fps[origin(a)])
        credential = a['req_features']['credential_present']
        a['anon_data_served'] = not credential and a['access_class'] == 'data'
        a['soft_denied'] = not credential and a['status_code'] < 400 and a['access_class'] in ('auth_wall', 'shell')
        n.pass_d_distill([a], boilerplate)
        a['raw'] = ''  # Hydrated only when emitting a canonical/variant batch.
        a['identifiers'] = []  # Exact occurrences have their own incremental index.
        for key in ('_login_fp', '_login_page', '_base_access', '_detected_cookies', '_cookie_names'):
            a.pop(key, None)
    groups = defaultdict(list)
    for a in records:
        groups[(origin(a), a['method'], a['endpoint_template'])].append(a)
    for group in groups.values():
        contents, schemas = defaultdict(list), defaultdict(list)
        for a in group:
            if a['req_features']['credential_present'] and a['access_class'] == 'data':
                if a.get('resp_body_sha256'):
                    contents[(a['url'], a.get('req_body_sha256'), a['resp_body_sha256'])].append(a['exchange_id'])
                if a.get('resp_schema_sig'):
                    schemas[a['resp_schema_sig']].append(a['exchange_id'])
        for a in group:
            eligible = not a['req_features']['credential_present'] and a['access_class'] == 'data'
            a['content_match_ids'] = contents.get((a['url'], a.get('req_body_sha256'), a.get('resp_body_sha256')), []) if eligible else []
            a['schema_match_ids'] = schemas.get(a.get('resp_schema_sig'), []) if eligible else []
            a['content_match_count'] = len(a['content_match_ids'])
            a['schema_match_count'] = len(a['schema_match_ids'])
            a['content_match_ids'] = a['content_match_ids'][:5]
            a['schema_match_ids'] = a['schema_match_ids'][:5]
            a['anon_matches_auth'] = bool(a['content_match_ids'])
            a['anon_schema_matches_credentialed'] = bool(a['schema_match_ids'])
    return records, n.build_auth_models(records)


def hydrate_chunks(chunks, load_item):
    """Attach bounded HTTP only for records which actually display evidence."""
    for chunk in chunks:
        meta = chunk['metadata']
        if meta.get('granularity') in ('parent', 'variant') and meta.get('exchange_id'):
            raw = n.reconstruct_raw(load_item(meta['exchange_id']))
            chunk['page_content'] = raw + chunk['page_content']
        yield chunk
