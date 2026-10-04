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
import gzip
import hashlib
import json
import re
import xml.etree.ElementTree as ET
import zlib

# Only strip pure browser-hint / fetch-metadata noise; keep everything else.
IGNORE_HEADER_PREFIX = ('sec-ch-', 'sec-fetch-')

# Cap the stored response body so a single huge page can't bloat the DB. The
# body is for deep-dive only (never embedded); headers are always kept in full.
MAX_STORED_BODY = 65536

BINARY_CT = ('application/pdf', 'application/octet-stream', 'application/zip',
             'application/gzip', 'application/wasm', 'application/x-protobuf',
             'audio/', 'video/', 'font/')
TEXT_CT = ('text/', 'json', 'xml', 'javascript', 'x-www-form-urlencoded',
           'graphql', 'multipart/', 'svg')

# For bodies too large to store in full and not structured JSON/XML: keep this
# many chars from the head and the rest of the budget from the tail, so
# trailing content (stack traces, closing error detail) isn't always lost.
TAIL_KEEP = 12000


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
                    key = k.strip().lower()
                    if key in headers:
                        headers[key] = headers[key] + '\n' + v.strip()
                    else:
                        headers[key] = v.strip()
        return {'line': lines[0], 'headers': headers, 'body': body}
    except Exception as e:
        print(f"  warn: HTTP parse error: {e}")
        return None


def _header(headers, name):
    name = name.lower()
    return next((str(v) for k, v in headers.items() if k.lower() == name), '')


def decode_content(body: bytes, headers: dict):
    """Decode HTTP content encoding before any textual analysis."""
    encodings = [part.strip().lower() for part in
                 _header(headers, 'content-encoding').split(',') if part.strip()]
    for encoding in reversed(encodings):
        try:
            if encoding == 'gzip':
                body = gzip.decompress(body)
            elif encoding == 'deflate':
                try:
                    body = zlib.decompress(body)
                except zlib.error:
                    body = zlib.decompress(body, -zlib.MAX_WBITS)
            elif encoding == 'br':
                import brotli
                body = brotli.decompress(body)
            elif encoding != 'identity':
                return body, f'unsupported content-encoding: {encoding}'
        except ImportError:
            return body, f'{encoding} support unavailable'
        except Exception as e:
            return body, f'{encoding} decode failed: {e}'
    return body, ''


def decode_transfer(body: bytes, headers: dict):
    """Remove HTTP/1.1 chunk framing before content decoding."""
    encodings = [part.strip().lower() for part in
                 _header(headers, 'transfer-encoding').split(',') if part.strip()]
    if 'chunked' not in encodings:
        return body, ''
    output = bytearray()
    position = 0
    try:
        while True:
            line_end = body.find(b'\r\n', position)
            separator = 2
            if line_end < 0:
                line_end = body.find(b'\n', position)
                separator = 1
            if line_end < 0:
                raise ValueError('missing chunk-size terminator')
            size_text = body[position:line_end].split(b';', 1)[0].strip()
            size = int(size_text, 16)
            position = line_end + separator
            if size == 0:
                return bytes(output), ''
            output.extend(body[position:position + size])
            position += size
            if body[position:position + 2] == b'\r\n':
                position += 2
            elif body[position:position + 1] == b'\n':
                position += 1
            else:
                raise ValueError('missing chunk-data terminator')
    except Exception as e:
        return body, f'chunked decode failed: {e}'


def is_textual(content_type: str, body: bytes) -> bool:
    ct = (content_type or '').lower()
    if any(marker in ct for marker in TEXT_CT):
        return True
    if any(marker in ct for marker in BINARY_CT) or ct.startswith('image/'):
        return False
    sample = body[:1024]
    if not sample:
        return True
    if b'\x00' in sample:
        return False
    control = sum(byte < 9 or 13 < byte < 32 for byte in sample)
    return control / len(sample) < 0.05


def decode_text(body: bytes, content_type: str) -> str:
    match = re.search(r'charset\s*=\s*["\']?([^;"\'\s]+)', content_type or '', re.I)
    charset = match.group(1) if match else 'utf-8'
    try:
        return body.decode(charset, errors='replace')
    except LookupError:
        return body.decode('utf-8', errors='replace')


def bounded_preview(body: str, content_type: str):
    if len(body) <= MAX_STORED_BODY:
        return body, False
    preview = (structured_xml_preview(body)
               if 'xml' in content_type or body.lstrip().startswith('<?xml')
               else structured_json_preview(body))
    if preview:
        return preview, True
    head_keep = MAX_STORED_BODY - TAIL_KEEP
    return body[:head_keep] + '\n<TRUNCATED>\n' + body[-TAIL_KEEP:], True


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
            if len(value) <= 10:
                sample = value
            else:
                indices = sorted({round(i * (len(value) - 1) / 9) for i in range(10)})
                sample = [value[index] for index in indices]
            return [prune(v, depth + 1) for v in sample]
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
            req_ct = _header(parsed['headers'], 'content-type')
            transferred, decode_error = decode_transfer(parsed['body'], parsed['headers'])
            decoded, content_error = decode_content(transferred, parsed['headers'])
            decode_error = decode_error or content_error
            if is_textual(req_ct, decoded) and not decode_error:
                req_analysis = decode_text(decoded, req_ct)
                req_body_str, req_truncated = bounded_preview(req_analysis, req_ct)
                req_body_kind = 'text'
            else:
                digest = hashlib.sha256(decoded).hexdigest()[:16]
                req_analysis = ''
                req_body_str = f'<BINARY_DATA sha256={digest} len={len(decoded)}>'
                req_truncated = True
                req_body_kind = 'undecodable' if decode_error else 'binary'
            result['request'] = {'line': parsed['line'],
                                  'raw_base64': base64.b64encode(raw).decode('ascii'),
                                  'headers': parsed['headers'],
                                  'body': req_body_str,
                                  'analysis_body': req_analysis,
                                  'truncated': req_truncated,
                                  'body_sha256': hashlib.sha256(decoded).hexdigest(),
                                  'body_length': len(decoded),
                                  'body_kind': req_body_kind,
                                  'decode_error': decode_error}

    resp_el = item.find('response')
    if resp_el is not None and resp_el.text:
        raw = (base64.b64decode(resp_el.text) if resp_el.get('base64') == 'true'
               else resp_el.text.encode('utf-8'))
        parsed = parse_http(raw, is_request=False)
        if parsed:
            ct = _header(parsed['headers'], 'content-type').lower()
            transferred, decode_error = decode_transfer(parsed['body'], parsed['headers'])
            decoded, content_error = decode_content(transferred, parsed['headers'])
            decode_error = decode_error or content_error
            digest = hashlib.sha256(decoded).hexdigest()
            if is_textual(ct, decoded) and not decode_error:
                analysis_body = decode_text(decoded, ct)
                body_str, truncated = bounded_preview(analysis_body, ct)
                body_kind = 'text'
            else:
                analysis_body = ''
                reason = f' decode_error={decode_error}' if decode_error else ''
                body_str = (f'<BINARY_DATA sha256={digest[:16]} len={len(decoded)}'
                            f'{reason}>')
                truncated = True
                body_kind = 'undecodable' if decode_error else 'binary'
            result['response'] = {'line': parsed['line'],
                                  'raw_base64': base64.b64encode(raw).decode('ascii'),
                                  'headers': parsed['headers'],
                                  'body': body_str,
                                  'analysis_body': analysis_body,
                                  'truncated': truncated,
                                  'body_sha256': digest,
                                  'body_length': len(decoded),
                                  'body_kind': body_kind,
                                  'decode_error': decode_error}
    return result


def iter_items(xml_file):
    """Release completed XML records instead of retaining the full export tree."""
    context = ET.iterparse(xml_file, events=('start', 'end'))
    _, root = next(context)
    for event, element in context:
        if event == 'end' and element.tag == 'item':
            yield process_item(element)
            element.clear()
            root.clear()


def main():
    ap = argparse.ArgumentParser(description="J.E.B. v2 Phase 1: parse Burp XML")
    ap.add_argument('xml_file')
    ap.add_argument('-o', '--output', required=True, help='explicit export destination')
    args = ap.parse_args()

    count = 0
    with open(args.output, 'w') as f:
        f.write('[')
        for item in iter_items(args.xml_file):
            if count:
                f.write(',')
            json.dump(item, f)
            count += 1
        f.write(']')
    print(f"Parsed {count} items. Saved to {args.output}")


if __name__ == '__main__':
    main()
