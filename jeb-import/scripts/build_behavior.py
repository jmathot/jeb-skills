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
    """Choose the response nearest the group's median size, then the richest."""
    lengths = sorted(i.get('resp_len', 0) for i in items)
    median = lengths[len(lengths) // 2]
    return min(items, key=lambda i: (
        abs(i.get('resp_len', 0) - median),
        -len(i.get('resp_distilled', '')),
        -len(i.get('raw', '')),
    ))


def build(annotated):
    groups = OrderedDict()
    for a in annotated:
        key = d.behavior_collapse_key(a)
        groups.setdefault(key, []).append(a)

    chunks = []
    for key, items in groups.items():
        rep = _representative(items)
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
            'resp_content_type': rep['resp_content_type'],
            'is_static': rep['is_static'],
            'resp_len': rep['resp_len'],
            'instance_count': instance_count,
            'time': rep['time'],
            # access control
            'access_class': rep.get('access_class', ''),
            'anon_matches_auth': rep.get('anon_matches_auth', False),
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
            'summary': summary,
        }
        chunks.append({'id': d.behavior_id(rep), 'embed_text': embed_text,
                       'page_content': page_content, 'metadata': metadata})
    return chunks


def build_segments(annotated):
    groups = OrderedDict()
    for a in annotated:
        groups.setdefault(d.behavior_collapse_key(a), []).append(a)

    chunks = []
    for items in groups.values():
        rep = _representative(items)
        parent_id = d.behavior_id(rep)
        parent_meta = build(items)[0]['metadata']
        for representation, text in d.behavior_segment_texts(rep).items():
            metadata = dict(parent_meta)
            metadata.update({'parent_id': parent_id, 'representation': representation})
            chunks.append({
                'id': d.md5(f"{parent_id}|{representation}"),
                'embed_text': text,
                'page_content': text,
                'metadata': metadata,
            })
    return chunks


def main():
    ap = argparse.ArgumentParser(description="J.E.B. v2 Phase 3a: build behavior docs")
    ap.add_argument('input_file', nargs='?', default='annotated_traffic.json')
    ap.add_argument('-o', '--output', default='behavior_chunks.json')
    ap.add_argument('--segments-output')
    args = ap.parse_args()

    with open(args.input_file) as f:
        data = json.load(f)
    annotated = data['items'] if isinstance(data, dict) else data

    chunks = build(annotated)
    with open(args.output, 'w') as f:
        json.dump(chunks, f, indent=2)
    print(f"Built {len(chunks)} distinct-behavior docs. Saved to {args.output}")
    if args.segments_output:
        segments = build_segments(annotated)
        with open(args.segments_output, 'w') as f:
            json.dump(segments, f, indent=2)
        print(f"Built {len(segments)} behavior semantic segments. "
              f"Saved to {args.segments_output}")


if __name__ == '__main__':
    main()
