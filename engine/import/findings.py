"""Structured finding evidence and idempotent identifier repair."""
import json
from urllib.parse import urlparse
import distill as d
from parse import parse_http, decode_transfer, decode_content, decode_text, _header
from storage import scan, sync_identifiers


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
        if not force and row['metadatas'].get('identifier_state') in ('complete', 'legacy-unstructured'):
            continue
        data = parse_finding(row['documents'])
        if data is None:
            # Legacy free-form evidence is retained, with explicit repair limits.
            col.update(ids=[row['id']], metadatas=[{'identifier_state': 'legacy-unstructured'}])
            continue
        sync_identifiers(client, 'attacks', [{'id': row['id'],
                          'identifier_pairs': pairs_for_finding(data)}], replace=True)
        col.update(ids=[row['id']], metadatas=[{'identifier_state': 'complete'}])
