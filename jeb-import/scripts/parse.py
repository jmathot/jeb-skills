"""
J.E.B. v2 — Phase 1: parse a Burp Suite XML export into normalised items.

Differences from the v1 `ingest.py`:
  * No web-code corpus retention (client-side code analysis was dropped).
  * Headers are retained *broadly* (only pure browser-hint noise is stripped),
    because headers are never embedded in v2 — they live in the retrieval
    document and power `--where-document` substring filtering. Fidelity here is
    what makes cookie/header attack analysis possible.
  * No dedup at this stage: every item is kept, even exact repeats of the same
    method/URL/body. A different response to an identical request (race
    conditions, non-deterministic authz, rate limiting) is a real signal, and
    the downstream behavior-collapse key (distill.py::behavior_collapse_key)
    already merges genuinely identical request/response pairs correctly.

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

# Only strip pure browser-hint / fetch-metadata noise; keep everything else.
IGNORE_HEADER_PREFIX = ('sec-ch-', 'sec-fetch-')

# Cap the stored response body so a single huge page can't bloat the DB. The
# body is for deep-dive only (never embedded); headers are always kept in full.
MAX_STORED_BODY = 16000

BINARY_CT = ('image/', 'application/pdf', 'audio/', 'video/',
             'application/octet-stream', 'font/')

# For bodies too large to store in full and not structured JSON/XML: keep this
# many chars from the head and the rest of the budget from the tail, so
# trailing content (stack traces, closing error detail) isn't always lost.
TAIL_KEEP = 4000


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


def structured_json_preview(body: str) -> str:
    """Keep large JSON valid and structurally useful for later distillation."""
    try:
        parsed = json.loads(body)
    except Exception:
        return ''

    budget = {'nodes': 0}

    def prune(value, depth=0):
        budget['nodes'] += 1
        if budget['nodes'] > 300 or depth > 5:
            return '<OMITTED>'
        if isinstance(value, dict):
            return {str(k): prune(v, depth + 1)
                    for k, v in list(value.items())[:60]}
        if isinstance(value, list):
            return [prune(v, depth + 1) for v in value[:3]]
        if isinstance(value, str):
            return value[:200]
        return value

    preview = json.dumps(prune(parsed), ensure_ascii=True, separators=(',', ':'))
    return preview if len(preview) <= MAX_STORED_BODY else ''


def structured_xml_preview(body: str) -> str:
    """Keep a bounded, valid XML tree for later element-path distillation."""
    try:
        root = ET.fromstring(body)
    except Exception:
        return ''

    budget = {'nodes': 0}

    def prune(element, depth=0):
        budget['nodes'] += 1
        element.text = (element.text or '')[:200]
        element.tail = None
        for key in list(element.attrib)[20:]:
            del element.attrib[key]
        children = list(element)
        for child in children:
            if budget['nodes'] >= 300 or depth >= 5:
                element.remove(child)
            else:
                prune(child, depth + 1)

    prune(root)
    preview = ET.tostring(root, encoding='unicode')
    return preview if len(preview) <= MAX_STORED_BODY else ''


def process_item(item):
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
                digest = hashlib.sha256(parsed['body']).hexdigest()[:16]
                body_str = f'<BINARY_DATA_FILTERED sha256={digest} len={len(parsed["body"])}>'
            else:
                body_str = parsed['body'].decode('utf-8', errors='ignore')
                if len(body_str) > MAX_STORED_BODY:
                    preview = (structured_xml_preview(body_str)
                               if 'xml' in ct or body_str.lstrip().startswith('<?xml')
                               else structured_json_preview(body_str))
                    if preview:
                        body_str = preview
                    else:
                        head_keep = MAX_STORED_BODY - TAIL_KEEP
                        body_str = (body_str[:head_keep] + '\n<TRUNCATED>\n' +
                                    body_str[-TAIL_KEEP:])
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
    items = [process_item(item) for item in root.findall('item')]
    items = [r for r in items if r is not None]

    with open(args.output, 'w') as f:
        json.dump(items, f, indent=2)
    print(f"Parsed {len(items)} items. Saved to {args.output}")


if __name__ == '__main__':
    main()
