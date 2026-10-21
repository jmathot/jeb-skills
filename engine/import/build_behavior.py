"""
Behavior grouping helpers for `build_graph`.

Annotated items collapse to *distinct behaviors* (method + template + status +
auth role + access class + credential presence). The group's most informative
exchange is its representative; its differing responses are variants, recorded as
`OBSERVED_IN` edges rather than embedded records.
"""
import json
from collections import OrderedDict

import distill as d


def _csv(v):
    return ",".join(v) if isinstance(v, (list, tuple)) else (v or "")


def _representative(items):
    """Choose the most analyzable and information-rich exchange."""
    return min(items, key=lambda i: (
        bool(i.get('resp_decode_error')),
        bool(i.get('resp_body_truncated')),
        -len(i.get('resp_schema_keys', [])),
        -len(i.get('resp_distilled', '')),
        -int(i.get('resp_body_length', len(i.get('raw', '')))),
        i.get('time', ''),
    ))


def _variant_groups(items):
    groups = OrderedDict()
    for item in items:
        groups.setdefault(d.behavior_variant_key(item), []).append(item)
    return groups


# Variants beneath one behavior that get an `OBSERVED_IN` edge. Every variant is
# still an exchange in `exchanges`; this only bounds the edges when a response
# differs in nearly every instance.
MAX_VARIANTS_PER_PARENT = 12


def _selected_variants(items):
    """The variant groups that get records, most-evidenced first (ties: first seen)."""
    groups = _variant_groups(items)
    if len(groups) <= MAX_VARIANTS_PER_PARENT:
        return groups
    ranked = sorted(enumerate(groups.items()), key=lambda e: (-len(e[1][1]), e[0]))
    kept = {k for _, (k, _) in ranked[:MAX_VARIANTS_PER_PARENT]}
    return OrderedDict((k, v) for k, v in groups.items() if k in kept)


def _variant_id(parent_id, key):
    return d.md5(parent_id + '|variant|' + json.dumps(key, sort_keys=True))


def _parent_metadata(rep, items, variant_count):
    """Metadata of one behavior node, derived from its representative and the
    exchanges collapsed beneath it."""
    reqf, respf = rep['req_features'], rep['resp_features']
    return {
        'evidence_count': len(items),
        'exchange_id': rep.get('exchange_id', ''),
        'capture_id': rep.get('capture_id', ''),
        'credential_present': reqf.get('credential_present', reqf['authenticated']),
        'auth_state': reqf.get('auth_state', 'unknown'),
        'doc_kind': 'behavior',
        'scheme': rep['scheme'],
        'host': rep['host'],
        'port': rep['port'],
        'endpoint_template': rep['endpoint_template'],
        'method': rep['method'],
        'status_code': rep['status_code'],
        'param_names': _csv(rep['param_names']),
        'param_count': rep['param_count'],
        'req_content_type': rep['req_content_type'],
        'req_schema_sig': rep.get('req_schema_sig', ''),
        'req_schema_keys': _csv(rep.get('req_schema_keys', [])),
        'graphql_operation': rep.get('graphql_operation', ''),
        'resp_content_type': rep['resp_content_type'],
        'resp_class': rep.get('resp_class', ''),
        'is_static': rep['is_static'],
        'resp_len': rep['resp_len'],
        'instance_count': len(items),
        'time': rep['time'],
        # access control
        'access_class': rep.get('access_class', ''),
        'anon_matches_auth': any(i.get('anon_matches_auth') for i in items),
        'anon_schema_matches_credentialed': any(i.get('anon_schema_matches_credentialed') for i in items),
        'content_match_example': next((i['exchange_id'] for i in items if i.get('anon_matches_auth')), ''),
        'schema_match_example': next((i['exchange_id'] for i in items if i.get('anon_schema_matches_credentialed')), ''),
        # security (compact)
        'authenticated': reqf['authenticated'],
        'auth_role': reqf['auth_role'],
        'auth_mechanism': reqf['auth_mechanism'],
        'cookie_names': _csv(reqf['cookie_names']),
        'set_cookies': _csv(respf['set_cookies']),
        'cookie_issues': _csv(respf['cookie_issues']),
        'security_headers_missing': _csv(respf['security_headers_missing']),
        'tech': _csv(respf.get('tech', [])),
        'cors': respf['cors'] + (" creds" if respf['cors_credentials'] else ""),
        'req_features': _csv(reqf['req_features_csv']),
        'jwt': reqf['jwt'],
        'redirect_location': respf['redirect_location'],
        'resp_body_sha256': rep.get('resp_body_sha256', ''),
        'resp_body_truncated': rep.get('resp_body_truncated', False),
        'req_body_truncated': rep.get('req_body_truncated', False),
        'resp_decode_error': rep.get('resp_decode_error', ''),
        'variant_count': variant_count,
        'summary': d.behavior_summary(rep),
    }


def _group_metadata(items):
    rep = _representative(items)
    groups = _variant_groups(items)
    selected = _selected_variants(items)
    parent_id = d.behavior_id(rep)
    return rep, parent_id, _parent_metadata(rep, items, len(groups)), groups, selected
