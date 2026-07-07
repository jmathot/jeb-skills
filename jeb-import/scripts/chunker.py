import json
import argparse
import os
import base64
from urllib.parse import urlparse, parse_qs

# Extensions treated as static assets (noise) for the is_static flag.
STATIC_EXTS = {
    'css', 'js', 'mjs', 'map',
    'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'bmp', 'webp',
    'woff', 'woff2', 'ttf', 'eot', 'otf',
}
STATIC_MIMETYPES = {'script', 'css', 'image', 'font'}

# Cookie names that indicate a session/auth credential (case-insensitive exact key).
AUTH_COOKIE_NAMES = {
    'session', 'sessionid', 'session_id', 'sid', 'jsessionid', 'phpsessid',
    'asp.net_sessionid', 'connect.sid', 'laravel_session', 'ci_session',
    'token', 'auth', 'auth_token', 'access_token', 'accesstoken', 'jwt',
    'id_token', 'remember_token', 'oauth_token', 'apikey', 'api_key',
}

# Custom (non-Authorization) request headers that carry credentials.
# Keep this in sync with AUTH_HEADERS in ingest.py.
AUTH_HEADERS = {
    'x-api-key', 'api-key', 'x-auth-token', 'x-access-token', 'x-session-token',
    'loginid', 'authentication', 'currentrole',
}

# Substrings that flag an (otherwise unknown) header name as auth-related.
AUTH_HEADER_SIGNALS = (
    'auth', 'login', 'token', 'session', 'api-key', 'apikey', 'credential',
)

def _to_int(value):
    try:
        return int(str(value).strip())
    except (ValueError, TypeError):
        return 0

def _looks_like_jwt(value):
    parts = value.split('.')
    if len(parts) != 3:
        return False
    # A JWT's header segment is base64url of a JSON object -> always starts "eyJ".
    if not parts[0].startswith('eyJ'):
        return False
    return all(p and all(c.isalnum() or c in '-_' for c in p) for p in parts)

def detect_credentials(req_headers_dict):
    """
    Return True if the request carries authentication credentials via any of:
    Authorization header, a curated session/auth cookie name, a JWT-shaped cookie
    value, or a custom API-key/auth header.
    """
    for k, v in req_headers_dict.items():
        kl = k.lower()
        if kl == 'authorization' and v.strip():
            return True
        if kl in AUTH_HEADERS and v.strip():
            return True
        if kl != 'cookie' and v.strip() and any(sig in kl for sig in AUTH_HEADER_SIGNALS):
            # Unknown custom auth header (e.g. Loginid, Authentication).
            return True
        if kl == 'cookie':
            for part in v.split(';'):
                part = part.strip()
                if '=' not in part:
                    continue
                name, val = part.split('=', 1)
                if name.strip().lower() in AUTH_COOKIE_NAMES:
                    return True
                if _looks_like_jwt(val.strip()):
                    return True
    return False

def process_chunk(item):
    url = item.get('url', '')
    parsed_url = urlparse(url)
    endpoint = parsed_url.path
    url_params = list(parse_qs(parsed_url.query).keys())

    host = parsed_url.hostname or ''
    scheme = parsed_url.scheme or ''
    port = parsed_url.port or (443 if scheme == 'https' else 80)
    file_ext = os.path.splitext(endpoint)[1].lstrip('.').lower()

    method = item.get('method', '')
    status = item.get('status', '')
    status_code = _to_int(status)
    status_class = f"{status_code // 100}xx" if status_code else ""
    
    # Text content for vector storage
    req = item.get('request', {})
    resp = item.get('response', {})
    
    req_line = req.get('line', '')
    req_headers = "\n".join(f"{k}: {v}" for k, v in req.get('headers', {}).items())
    req_body = req.get('body', '')
    
    resp_line = resp.get('line', '')
    resp_headers = "\n".join(f"{k}: {v}" for k, v in resp.get('headers', {}).items())
    resp_body = resp.get('body', '')
    
    text_content = f"--- REQUEST ---\n{req_line}\n{req_headers}\n\n{req_body}\n\n--- RESPONSE ---\n{resp_line}\n{resp_headers}\n\n{resp_body}"
    
    req_headers_dict = req.get('headers', {})
    
    # Extract Cookies
    cookies = []
    for k, v in req_headers_dict.items():
        if k.lower() == 'cookie':
            cookie_parts = v.split(';')
            for part in cookie_parts:
                part = part.strip()
                if '=' in part:
                    cookies.append(part.split('=', 1)[0])
            break
            
    # Extract Body params
    body_params = []
    req_content_type = ""
    for k, v in req_headers_dict.items():
        if k.lower() == 'content-type':
            # Strip charset/boundary parameters -> keep the bare media type.
            req_content_type = v.split(';', 1)[0].strip().lower()
            break

    if method in ['POST', 'PUT', 'PATCH']:
        if 'application/x-www-form-urlencoded' in req_content_type:
            body_params = list(parse_qs(req_body).keys())
        elif 'application/json' in req_content_type:
            try:
                parsed_json = json.loads(req_body)
                if isinstance(parsed_json, dict):
                    body_params = list(parsed_json.keys())
            except:
                pass
    
    # Extract Referer
    referer = ""
    for k, v in req_headers_dict.items():
        if k.lower() == 'referer':
            referer = v
            break
            
    # Extract CORS Wildcard
    cors_wildcard = False
    resp_headers_dict = resp.get('headers', {})
    for k, v in resp_headers_dict.items():
        if k.lower() == 'access-control-allow-origin' and v.strip() == '*':
            cors_wildcard = True
            break
            
    # Auth and Roles
    authenticated = detect_credentials(req_headers_dict)

    # Try to extract a bearer/JWT token to resolve a specific role.
    auth_token = ""
    for k, v in req_headers_dict.items():
        if k.lower() == 'authorization':
            auth_token = v
            break

    if not auth_token:
        for k, v in req_headers_dict.items():
            if k.lower() == 'cookie':
                for part in v.split(';'):
                    part = part.strip()
                    if '=' not in part:
                        continue
                    name, val = part.split('=', 1)
                    val = val.strip()
                    if name.strip().lower() in AUTH_COOKIE_NAMES or _looks_like_jwt(val):
                        auth_token = val
                        break
                break

    # Default role: authenticated if credentials present, else anonymous.
    auth_role = "authenticated" if authenticated else "anonymous"

    if auth_token:
        if 'Bearer ' in auth_token:
            auth_token = auth_token.split('Bearer ')[1]
        parts = auth_token.split('.')
        if len(parts) == 3:
            try:
                payload = parts[1]
                payload += '=' * (-len(payload) % 4)
                decoded = base64.b64decode(payload).decode('utf-8')
                parsed = json.loads(decoded)
                if 'data' in parsed and 'role' in parsed['data']:
                    auth_role = parsed['data']['role']
                elif 'role' in parsed:
                    auth_role = parsed['role']
            except:
                pass

    mimetype = item.get('mimetype', '')
    is_static = mimetype.lower() in STATIC_MIMETYPES or file_ext in STATIC_EXTS

    metadata = {
        "url": url,
        "endpoint": endpoint,
        "host": host,
        "scheme": scheme,
        "port": port,
        "method": method,
        "status": status,
        "status_code": status_code,
        "status_class": status_class,
        "url_params": url_params,
        "cookies": cookies,
        "body_params": body_params,
        "param_count": len(url_params) + len(body_params),
        "req_content_type": req_content_type,
        "mimetype": mimetype,
        "file_ext": file_ext,
        "is_static": is_static,
        "referer": referer,
        "cors_wildcard": cors_wildcard,
        "auth_role": auth_role,
        "authenticated": authenticated,
        "time": item.get('time', ''),
        "responselength": item.get('responselength', ''),
        "resp_len": _to_int(item.get('responselength', '')),
    }
    
    return {
        "page_content": text_content,
        "metadata": metadata
    }

def main():
    parser = argparse.ArgumentParser(description="Phase 2: Chunk and structure parsed traffic")
    parser.add_argument("input_file", help="Path to parsed_traffic.json", nargs='?', default="parsed_traffic.json")
    parser.add_argument("-o", "--output", help="Output JSON file", default="rag_chunks.json")
    args = parser.parse_args()
    
    try:
        with open(args.input_file, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: Could not find {args.input_file}")
        return
        
    chunks = []
    for item in data:
        chunks.append(process_chunk(item))
        
    with open(args.output, 'w') as f:
        json.dump(chunks, f, indent=2)
        
    print(f"Processed {len(chunks)} items into chunks. Saved to {args.output}")

if __name__ == '__main__':
    main()
