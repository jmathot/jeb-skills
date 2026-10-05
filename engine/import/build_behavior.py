"""
J.E.B. v2 — Phase 3a: build the `behavior` collection.

Collapses annotated items to *distinct behaviors* (one doc per
method+template+status+auth-role+response-schema) and emits, per doc:
  embed_text   distilled, value-suppressed request/response + security clause
  page_content raw HTTP of the representative (+ collapsed example URLs)
  metadata     lean functional scalars + compact security features
"""
import argparse
import json
import os
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


def _variant_id(parent_id, key):
    return d.md5(parent_id + '|variant|' + json.dumps(key, sort_keys=True))


def build(annotated):
    groups = OrderedDict()
    for a in annotated:
        key = d.behavior_collapse_key(a)
        groups.setdefault(key, []).append(a)

    chunks = []
    for key, items in groups.items():
        rep = _representative(items)
        variant_groups = _variant_groups(items)
        variant_ids = ([_variant_id(d.behavior_id(rep), variant_key)
                        for variant_key in variant_groups]
                       if len(variant_groups) > 1 else [])
        reqf, respf = rep['req_features'], rep['resp_features']
        example_urls = list(OrderedDict.fromkeys(i['url'] for i in items))[:5]
        instance_count = len(items)

        embed_text = d.behavior_embed_text(rep)
        summary = d.behavior_summary(rep)

        page_content = rep['raw']
        if instance_count > 1:
            page_content += (f"\n\n--- COLLAPSED: {instance_count} instances; "
                             f"examples ---\n" + "\n".join(example_urls))

        metadata = {
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
            'instance_count': instance_count,
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
            'cors': respf['cors'] + (" creds" if respf['cors_credentials'] else ""),
            'req_features': _csv(reqf['req_features_csv']),
            'jwt': reqf['jwt'],
            'redirect_location': respf['redirect_location'],
            'resp_body_sha256': rep.get('resp_body_sha256', ''),
            'resp_body_truncated': rep.get('resp_body_truncated', False),
            'req_body_truncated': rep.get('req_body_truncated', False),
            'resp_decode_error': rep.get('resp_decode_error', ''),
            'variant_count': len(variant_groups),
            'variant_ids': _csv(variant_ids),
            'granularity': 'parent',
            'summary': summary,
        }
        chunks.append({'id': d.behavior_id(rep), 'embed_text': embed_text,
                       'embedding_title': rep.get('page_title', ''),
                       'page_content': page_content, 'metadata': metadata})
    return chunks


def build_segments(annotated, parents=None):
    groups = OrderedDict()
    for a in annotated:
        groups.setdefault(d.behavior_collapse_key(a), []).append(a)

    chunks = []
    parent_metadata = {p['id']: p['metadata'] for p in (parents or [])}
    for items in groups.values():
        rep = _representative(items)
        parent_id = d.behavior_id(rep)
        parent_meta = parent_metadata.get(parent_id) or build(items)[0]['metadata']
        rep = dict(rep, anon_matches_auth=parent_meta['anon_matches_auth'])
        for representation, text in d.behavior_segment_texts(rep).items():
            metadata = segment_metadata(parent_meta)
            metadata.update({'parent_id': parent_id, 'representation': representation,
                             'granularity': 'segment'})
            chunks.append({
                'id': d.md5(f"{parent_id}|{representation}"),
                'embed_text': text,
                'embedding_title': rep.get('page_title', ''),
                'page_content': text,
                'metadata': metadata,
            })
    return chunks


def build_variants(annotated):
    groups = OrderedDict()
    for a in annotated:
        groups.setdefault(d.behavior_collapse_key(a), []).append(a)

    chunks = []
    for items in groups.values():
        parent_rep = _representative(items)
        parent_id = d.behavior_id(parent_rep)
        variants = _variant_groups(items)
        if len(variants) <= 1:
            continue
        for key, variant_items in variants.items():
            rep = _representative(variant_items)
            metadata = dict(build([rep])[0]['metadata'])
            metadata.update({
                'parent_id': parent_id,
                'representation': 'variant',
                'granularity': 'variant',
                'instance_count': len(variant_items),
                'evidence_count': len(variant_items),
                'anon_matches_auth': any(i.get('anon_matches_auth') for i in variant_items),
                'anon_schema_matches_credentialed': any(i.get('anon_schema_matches_credentialed') for i in variant_items),
                'content_match_example': next((i['exchange_id'] for i in variant_items if i.get('anon_matches_auth')), ''),
                'schema_match_example': next((i['exchange_id'] for i in variant_items if i.get('anon_schema_matches_credentialed')), ''),
                'param_names': _csv(rep.get('param_names', [])),
                'req_content_type': rep.get('req_content_type', ''),
                'req_schema_sig': rep.get('req_schema_sig', ''),
                'req_schema_keys': _csv(rep.get('req_schema_keys', [])),
                'graphql_operation': rep.get('graphql_operation', ''),
                'resp_content_type': rep.get('resp_content_type', ''),
                'resp_class': rep.get('resp_class', ''),
                'resp_body_sha256': rep.get('resp_body_sha256', ''),
                'resp_body_truncated': rep.get('resp_body_truncated', False),
                'resp_decode_error': rep.get('resp_decode_error', ''),
                'summary': d.behavior_summary(rep),
            })
            chunks.append({
                'id': _variant_id(parent_id, key),
                'embed_text': d.behavior_embed_text(rep),
                'embedding_title': rep.get('page_title', ''),
                'page_content': rep['raw'],
                'metadata': metadata,
            })
    return chunks


def segment_metadata(meta):
    """Searchable scalar facets, without aggregate evidence/variant payloads."""
    excluded = {'evidence_ids', 'variant_ids', 'summary', 'resp_body_sha256',
                'exchange_id', 'capture_id', 'time', 'example_ids', 'entity_ids',
                'produced_by', 'consumed_by'}
    return {k: v for k, v in meta.items() if k not in excluded and not k.startswith('_')}


def main():
    ap = argparse.ArgumentParser(description="J.E.B. v3 Phase 3a: build behavior docs")
    ap.add_argument('input_file', nargs='?', default='annotated_traffic.json')
    ap.add_argument('-o', '--output', required=True, help='explicit export destination')
    args = ap.parse_args()

    with open(args.input_file) as f:
        data = json.load(f)
    annotated = data['items'] if isinstance(data, dict) else data

    chunks = build(annotated)
    n_parents = len(chunks)
    chunks += build_segments(annotated)
    n_segments = len(chunks) - n_parents
    chunks += build_variants(annotated)

    with open(args.output, 'w') as f:
        json.dump(chunks, f, indent=2)
    print(f"Built {n_parents} canonical behavior docs + {n_segments} semantic "
          f"segments + {len(chunks) - n_parents - n_segments} raw variants. "
          f"Saved to {args.output}")


if __name__ == '__main__':
    main()
