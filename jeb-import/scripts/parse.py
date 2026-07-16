"""
J.E.B. v2 — Phase 1: parse a Burp Suite XML export into normalised items.

Differences from the v1 `ingest.py`:
  * No web-code corpus retention (client-side code analysis was dropped).
  * Headers are retained *broadly* (only pure browser-hint noise is stripped),
    because headers are never embedded in v2 — they live in the retrieval
    document and power `--where-document` substring filtering. Fidelity here is
    what makes cookie/header attack analysis possible.
  * Deduplicates identical requests by (method, normalized_url, body_hash).

Output: parsed_<name>.json — a list of items:
  {url, method, status, mimetype, responselength, time,
   request:  {line, headers{}, body},
   response: {line, headers{}, body, truncated}}
"""
import argparse
import base64
import hashlib
import json
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Only strip pure browser-hint / fetch-metadata noise; keep everything else.
IGNORE_HEADER_PREFIX = ('sec-ch-', 'sec-fetch-')

# Cap the stored response body so a single huge page can't bloat the DB. The
# body is for deep-dive only (never embedded); headers are always kept in full.
MAX_STORED_BODY = 16000

BINARY_CT = ('image/', 'application/pdf', 'audio/', 'video/',
             'application/octet-stream', 'font/')


def should_keep_header(name: str) -> bool:
    h = name.lower()
    return not any(h.startswith(p) for p in IGNORE_HEADER_PREFIX)


def parse_http(raw: bytes, is_request: bool):
    try:
        if b'\r\n\r\n' in raw:
            head, _, body = raw.partition(b'\r\n\r\n')
            nl = '\r\n'
        elif b'\n\n' in raw:
            head, _, body = raw.partition(b'\n\n')
            nl = '\n'
        else:
            head, body, nl = raw, b'', '\n'
        lines = head.decode('utf-8', errors='ignore').split(nl)
        if not lines:
            return {'line': '', 'headers': {}, 'body': body}
        headers = {}
        for line in lines[1:]:
            if ':' in line:
                k, v = line.split(':', 1)
                if should_keep_header(k.strip()):
                    # Preserve repeated headers (e.g. multiple Set-Cookie).
                    key = k.strip()
                    if key in headers:
                        headers[key] = headers[key] + '\n' + v.strip()
                    else:
                        headers[key] = v.strip()
        return {'line': lines[0], 'headers': headers, 'body': body}
    except Exception as e:
        print(f"  warn: HTTP parse error: {e}")
        return None


def normalize_url(url: str) -> str:
    p = urlparse(url)
    if p.query:
        params = parse_qs(p.query, keep_blank_values=True)
        params.pop('_', None)
        query = urlencode(params, doseq=True)
    else:
        query = ''
    return urlunparse((p.scheme, p.netloc, p.path, p.params, query, p.fragment))


def process_item(item, seen):
    url = item.findtext('url', '')
    method = item.findtext('method', '')

    result = {
        'url': url,
        'method': method,
        'status': item.findtext('status', ''),
        'mimetype': item.findtext('mimetype', ''),
        'responselength': item.findtext('responselength', ''),
        'time': item.findtext('time', ''),
    }

    req_body_str = ''
    req_el = item.find('request')
    if req_el is not None and req_el.text:
        raw = (base64.b64decode(req_el.text) if req_el.get('base64') == 'true'
               else req_el.text.encode('utf-8'))
        parsed = parse_http(raw, is_request=True)
        if parsed:
            req_body_str = parsed['body'].decode('utf-8', errors='ignore')
            result['request'] = {'line': parsed['line'],
                                 'headers': parsed['headers'],
                                 'body': req_body_str}

    # Dedup identical requests.
    body_hash = hashlib.md5(req_body_str.encode('utf-8')).hexdigest() if req_body_str else ''
    sig = (method, normalize_url(url), body_hash)
    if sig in seen:
        return None
    seen.add(sig)

    resp_el = item.find('response')
    if resp_el is not None and resp_el.text:
        raw = (base64.b64decode(resp_el.text) if resp_el.get('base64') == 'true'
               else resp_el.text.encode('utf-8'))
        parsed = parse_http(raw, is_request=False)
        if parsed:
            ct = ''
            for k, v in parsed['headers'].items():
                if k.lower() == 'content-type':
                    ct = v.lower()
                    break
            truncated = False
            if any(b in ct for b in BINARY_CT):
                body_str = '<BINARY_DATA_FILTERED>'
            else:
                body_str = parsed['body'].decode('utf-8', errors='ignore')
                if len(body_str) > MAX_STORED_BODY:
                    body_str = body_str[:MAX_STORED_BODY] + '\n<TRUNCATED>'
                    truncated = True
            result['response'] = {'line': parsed['line'],
                                  'headers': parsed['headers'],
                                  'body': body_str,
                                  'truncated': truncated}
    return result


def main():
    ap = argparse.ArgumentParser(description="J.E.B. v2 Phase 1: parse Burp XML")
    ap.add_argument('xml_file')
    ap.add_argument('-o', '--output', default='parsed_traffic.json')
    args = ap.parse_args()

    root = ET.parse(args.xml_file).getroot()
    seen, items = set(), []
    for item in root.findall('item'):
        r = process_item(item, seen)
        if r is not None:
            items.append(r)

    with open(args.output, 'w') as f:
        json.dump(items, f, indent=2)
    print(f"Parsed {len(items)} unique items. Saved to {args.output}")


if __name__ == '__main__':
    main()
