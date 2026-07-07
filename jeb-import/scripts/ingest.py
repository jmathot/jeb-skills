import xml.etree.ElementTree as ET
import base64
import argparse
import json
import os
from bs4 import BeautifulSoup
import re

# Custom (non-Authorization) request headers that carry credentials.
# Keep this in sync with AUTH_HEADERS in chunker.py.
AUTH_HEADERS = {
    'x-api-key', 'api-key', 'x-auth-token', 'x-access-token', 'x-session-token',
    'loginid', 'authentication', 'currentrole',
}

# Substrings that flag a header name as auth-related, so unknown custom
# auth headers on future engagements are retained generically.
AUTH_HEADER_SIGNALS = (
    'auth', 'login', 'token', 'session', 'api-key', 'apikey', 'credential',
)

# Headers to keep in requests (lowercased for matching). Must be a superset of
# every request header that chunker.py reads for metadata (cookie, content-type,
# referer, authorization) plus all credential-bearing headers.
KEEP_REQ_HEADERS = {
    'host', 'authorization', 'cookie', 'content-type', 'origin', 'referer',
} | AUTH_HEADERS

# Headers to keep in responses (lowercased for matching).
# Includes security headers so their presence/absence can drive findings.
KEEP_RESP_HEADERS = {
    'set-cookie', 'content-type', 'location', 'www-authenticate',
    'access-control-allow-origin', 'access-control-allow-credentials',
    'strict-transport-security', 'content-security-policy',
    'content-security-policy-report-only', 'x-frame-options',
    'x-content-type-options', 'referrer-policy', 'permissions-policy',
    'cache-control',
}

# Substrings for headers we always want to keep
ALWAYS_KEEP_HEADER_PREFIX = ('x-', 'sec-') # sec- headers might be noisy, but some are security related (sec-websocket, etc). Let's ignore sec-fetch/sec-ch
IGNORE_HEADER_PREFIX = ('sec-ch-', 'sec-fetch-', 'accept-', 'connection', 'upgrade-insecure-requests')

def should_keep_header(header_name: str, is_request: bool) -> bool:
    h = header_name.lower()
    if any(h.startswith(prefix) for prefix in IGNORE_HEADER_PREFIX):
        return False
    if h.startswith('x-'):
        return True
    
    if is_request:
        if h in KEEP_REQ_HEADERS:
            return True
        # Retain unknown custom auth headers (e.g. Loginid, Authentication).
        return any(sig in h for sig in AUTH_HEADER_SIGNALS)
    else:
        return h in KEEP_RESP_HEADERS

def parse_http(raw_data: bytes, is_request: bool):
    try:
        # Split headers and body, handle both \r\n\r\n and \n\n
        if b'\r\n\r\n' in raw_data:
            parts = raw_data.split(b'\r\n\r\n', 1)
            newline = '\r\n'
        elif b'\n\n' in raw_data:
            parts = raw_data.split(b'\n\n', 1)
            newline = '\n'
        else:
            parts = [raw_data, b'']
            newline = '\n'
            
        header_block = parts[0].decode('utf-8', errors='ignore')
        body = parts[1] if len(parts) > 1 else b''
        
        lines = header_block.split(newline)
        if not lines:
            return {"first_line": "", "headers": {}, "body": body}
            
        first_line = lines[0]
        headers = {}
        for line in lines[1:]:
            if ':' in line:
                k, v = line.split(':', 1)
                h_name = k.strip()
                if should_keep_header(h_name, is_request):
                    headers[h_name] = v.strip()
                    
        return {
            "first_line": first_line,
            "headers": headers,
            "body": body
        }
    except Exception as e:
        print(f"Error parsing HTTP: {e}")
        return None

def minify_html(body_bytes: bytes) -> str:
    html_str = body_bytes.decode('utf-8', errors='ignore')
    soup = BeautifulSoup(html_str, 'html.parser')
    
    # Strip noisy tags
    for tag in soup(['style', 'svg', 'script', 'noscript', 'meta', 'link']):
        # If it's a script but has no src (inline) we might want to keep it if it's small, 
        # but for Phase 1 we can just strip all or just keep small inline scripts.
        # Let's strip all large scripts/styles to save tokens
        if tag.name == 'script' and tag.string and len(tag.string) < 200:
            continue # Keep small inline scripts
        tag.decompose()
        
    return str(soup)

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import hashlib

seen_js_urls = set()
seen_requests = set()  # Track all requests by (method, url, request_body_hash)

# One canonical copy of every unique HTML/JS/CSS artifact, keyed by content hash.
# Value: {"body": str, "code_type": str, "source_urls": [str, ...],
#         "host": str, "mimetype": str}
webcode_artifacts = {}


def classify_code_type(content_type: str, mimetype: str, file_ext: str) -> str:
    """Return 'html', 'javascript', 'css', or '' for a response body."""
    ct = (content_type or '').lower()
    mt = (mimetype or '').lower()
    ext = (file_ext or '').lower()
    if 'text/html' in ct or mt == 'html' or ext in ('html', 'htm'):
        return 'html'
    if ('javascript' in ct or 'ecmascript' in ct or mt == 'script'
            or ext in ('js', 'mjs')):
        return 'javascript'
    if 'text/css' in ct or mt == 'css' or ext == 'css':
        return 'css'
    return ''


def record_webcode(body_str: str, code_type: str, url: str, host: str, mimetype: str):
    """Store one canonical copy of an HTML/JS/CSS artifact, deduped by content hash."""
    if not body_str or not body_str.strip():
        return
    h = hashlib.md5(body_str.encode('utf-8')).hexdigest()
    entry = webcode_artifacts.get(h)
    if entry is None:
        webcode_artifacts[h] = {
            "hash": h,
            "body": body_str,
            "code_type": code_type,
            "source_urls": [url],
            "host": host,
            "mimetype": mimetype,
        }
    elif url not in entry["source_urls"]:
        entry["source_urls"].append(url)

def normalize_url(url):
    """Remove debug parameters like '_' from URL for deduplication"""
    parsed = urlparse(url)
    
    # Parse query parameters
    if parsed.query:
        params = parse_qs(parsed.query, keep_blank_values=True)
        # Remove the '_' parameter (debug/request ID)
        params.pop('_', None)
        # Reconstruct query string
        normalized_query = urlencode(params, doseq=True)
    else:
        normalized_query = ""
    
    # Reconstruct URL without the '_' parameter
    normalized = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        normalized_query,
        parsed.fragment
    ))
    return normalized

def get_request_signature(method, url, req_body):
    """Create a unique signature for a request to detect duplicates"""
    import hashlib
    # Normalize URL by removing debug parameters
    normalized_url = normalize_url(url)
    body_hash = hashlib.md5(req_body.encode('utf-8')).hexdigest() if req_body else ""
    return (method, normalized_url, body_hash)

def process_item(item_xml):
    global seen_js_urls, seen_requests
    url = item_xml.findtext('url', '')
    mimetype = item_xml.findtext('mimetype', '')
    method = item_xml.findtext('method', '')
    
    parsed_url = urlparse(url)
    endpoint = parsed_url.path
    file_ext = endpoint.rsplit('.', 1)[-1].lower() if '.' in endpoint.rsplit('/', 1)[-1] else ''
    host = parsed_url.hostname or ''

    if mimetype.lower() == 'script':
        if endpoint in seen_js_urls:
            return None
        seen_js_urls.add(endpoint)

    result = {
        'url': url,
        'method': method,
        'status': item_xml.findtext('status', ''),
        'mimetype': mimetype,
        'responselength': item_xml.findtext('responselength', ''),
        'time': item_xml.findtext('time', '')
    }
    
    req_el = item_xml.find('request')
    req_body_str = ""
    if req_el is not None and req_el.text:
        raw_req = base64.b64decode(req_el.text) if req_el.get('base64') == 'true' else req_el.text.encode('utf-8')
        parsed_req = parse_http(raw_req, is_request=True)
        if parsed_req:
            # We assume request bodies are mostly text/json for now
            req_body_str = parsed_req['body'].decode('utf-8', errors='ignore')
            result['request'] = {
                'line': parsed_req['first_line'],
                'headers': parsed_req['headers'],
                'body': req_body_str
            }
    
    # Check for duplicate requests (same method, URL, and body)
    request_sig = get_request_signature(method, url, req_body_str)
    if request_sig in seen_requests:
        return None  # Skip duplicate
    seen_requests.add(request_sig)
            
    resp_el = item_xml.find('response')
    if resp_el is not None and resp_el.text:
        raw_resp = base64.b64decode(resp_el.text) if resp_el.get('base64') == 'true' else resp_el.text.encode('utf-8')
        parsed_resp = parse_http(raw_resp, is_request=False)
        
        if parsed_resp:
            resp_body = parsed_resp['body']
            content_type = parsed_resp['headers'].get('Content-Type', '').lower()

            # Classify HTML/JS/CSS and retain ONE canonical copy (deduped by
            # content hash) as web application code for the separate code corpus.
            code_type = classify_code_type(content_type, mimetype, file_ext)
            raw_body_str = resp_body.decode('utf-8', errors='ignore') if resp_body else ''
            if code_type:
                record_webcode(raw_body_str, code_type, url, host, mimetype)

            # Filter binary
            if any(b in content_type for b in ['image/', 'application/pdf', 'audio/', 'video/']):
                resp_body_str = "<BINARY_DATA_FILTERED>"
            elif 'text/html' in content_type or result['mimetype'].lower() == 'html':
                # Traffic docs stay lean; full copy lives in the web_code corpus.
                resp_body_str = minify_html(resp_body)
            else:
                resp_body_str = raw_body_str
                
            result['response'] = {
                'line': parsed_req['first_line'] if 'parsed_req' in locals() and parsed_req else "", # Will fix in actual code
                'headers': parsed_resp['headers'],
                'body': resp_body_str
            }
            # Fix response first line
            result['response']['line'] = parsed_resp['first_line']

    return result

def main():
    parser = argparse.ArgumentParser(description="Phase 1: Ingest Burp XML and filter")
    parser.add_argument("xml_file", help="Path to the Burp Suite XML export")
    parser.add_argument("-o", "--output", help="Output JSON file", default="parsed_traffic.json")
    parser.add_argument("--webcode-output", help="Output JSON file for the web application code corpus", default=None)
    args = parser.parse_args()
    
    tree = ET.parse(args.xml_file)
    root = tree.getroot()
    
    items = []
    for item in root.findall('item'):
        processed = process_item(item)
        if processed is not None:
            items.append(processed)
        
    with open(args.output, 'w') as f:
        json.dump(items, f, indent=2)
        
    print(f"Processed {len(items)} items. Saved to {args.output}")

    # Write the deduplicated web application code corpus.
    webcode_output = args.webcode_output
    if webcode_output is None:
        base, ext = os.path.splitext(args.output)
        webcode_output = f"{base}_webcode{ext or '.json'}"
    artifacts = list(webcode_artifacts.values())
    with open(webcode_output, 'w') as f:
        json.dump(artifacts, f, indent=2)
    print(f"Retained {len(artifacts)} unique web-code artifacts. Saved to {webcode_output}")

if __name__ == '__main__':
    main()
