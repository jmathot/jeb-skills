"""
J.E.B. v2 shared distillation library.

Pure functions (no I/O) used by the ingestion pipeline to turn raw HTTP into:
  * canonical endpoint templates (site-structure keys),
  * value-suppressed credential / cookie / header *features* (attack context
    without the high-cardinality values that used to dominate the vectors),
  * distilled response text routed by response type (API schema, MPA page,
    SPA shell, static, redirect), and
  * the compact `embed_text` (what gets vectorised) + `summary` (snippet) for
    each collection.

Design principle: suppress *values* (cookie jars, tokens, header blobs) from
the embedded text; surface *features* (names, flags, presence/absence). The raw
values are retained verbatim in the retrieval document by the callers.
"""
import base64
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, parse_qs

from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Caps
# ---------------------------------------------------------------------------
EMBED_TEXT_CAP = 1500          # max chars of any embed_text
SUMMARY_CAP = 200              # max chars of any summary one-liner
SCHEMA_KEY_CAP = 40            # max response schema key-paths in embed text
SCHEMA_DEPTH_CAP = 4           # recursion depth for JSON schema walk
SCHEMA_NODE_CAP = 250          # total nodes visited in JSON schema walk
SAMPLE_SCALAR_CAP = 5          # sample scalar values kept from a JSON body
PARAM_CAP = 40                 # max parameter names collected
HTML_HEADING_CAP = 8
HTML_LINK_CAP = 25
HTML_TEXT_LEAD_CAP = 400
SPA_TEXT_THRESHOLD = 200       # visible-text chars below which HTML may be a shell

# ---------------------------------------------------------------------------
# Auth vocabulary (kept cross-target; ported from v1 chunker/ingest)
# ---------------------------------------------------------------------------
AUTH_COOKIE_NAMES = {
    'session', 'sessionid', 'session_id', 'sid', 'jsessionid', 'phpsessid',
    'asp.net_sessionid', 'connect.sid', 'laravel_session', 'ci_session',
    'token', 'auth', 'auth_token', 'access_token', 'accesstoken', 'jwt',
    'id_token', 'remember_token', 'oauth_token', 'apikey', 'api_key',
}
AUTH_HEADERS = {
    'x-api-key', 'api-key', 'x-auth-token', 'x-access-token', 'x-session-token',
    'loginid', 'authentication', 'currentrole',
}
AUTH_HEADER_SIGNALS = (
    'auth', 'login', 'token', 'session', 'api-key', 'apikey', 'credential',
)
CSRF_SIGNALS = ('csrf', 'xsrf')

# Signals that a response is a login / auth-wall page rather than real content.
# A 200 that serves one of these is a *soft* access denial, not broken access.
LOGIN_TEXT_SIGNALS = (
    'sign in', 'signin', 'sign-in', 'log in', 'login', 'log on', 'logon',
    'session expired', 'session has expired', 'please log in', 'please sign in',
    'access denied', 'not authorized', 'unauthorized', 'authentication required',
    'you must be logged in', 'forgot password', 'remember me',
)
LOGIN_PATH_SIGNALS = (
    'login', 'signin', 'sign-in', 'sso', 'authenticate', 'session', 'account/login',
    'auth/login', 'user/login',
)
JSON_AUTHWALL_SIGNALS = (
    'unauth', 'not authorized', 'not authenticated', 'forbidden', 'login required',
    'please log in', 'please sign in', 'sign in', 'access denied', 'permission denied',
    'invalid token', 'token expired', 'session expired', 'authentication required',
)


# Response security headers whose *absence* is a finding.
SECURITY_HEADERS = {
    'content-security-policy': 'csp',
    'strict-transport-security': 'hsts',
    'x-frame-options': 'xfo',
    'x-content-type-options': 'xcto',
    'referrer-policy': 'referrer-policy',
    'permissions-policy': 'permissions-policy',
}

MESSAGE_KEYS = {
    'message', 'error', 'msg', 'detail', 'title', 'status', 'type',
    'description', 'reason', 'code', 'errors',
}

STATIC_EXTS = {
    'css', 'js', 'mjs', 'map', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico',
    'bmp', 'webp', 'woff', 'woff2', 'ttf', 'eot', 'otf',
}
STATIC_MIMETYPES = {'script', 'css', 'image', 'font'}


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def md5(text: str) -> str:
    return hashlib.md5(text.encode('utf-8', errors='ignore')).hexdigest()


def _to_int(value, default=0):
    try:
        return int(str(value).strip())
    except (ValueError, TypeError):
        return default


def _truncate(text: str, cap: int) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= cap else text[:cap] + "…"


def status_class(status_code: int) -> str:
    return f"{status_code // 100}xx" if status_code else ""


def header_get(headers: dict, name: str) -> str:
    """Case-insensitive header lookup. `headers` is a plain dict."""
    name = name.lower()
    for k, v in headers.items():
        if k.lower() == name:
            return v
    return ""


def header_all(headers: dict, name: str):
    name = name.lower()
    return [v for k, v in headers.items() if k.lower() == name]


# ---------------------------------------------------------------------------
# Endpoint templating
# ---------------------------------------------------------------------------
_NUM_RE = re.compile(r'^\d+$')
_UUID_RE = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
                      r'[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
_DATE_RE = re.compile(r'^\d{4}-\d{2}-\d{2}$')
_HEX_RE = re.compile(r'^[0-9a-fA-F]{16,}$')
_LONGTOKEN_RE = re.compile(r'^(?=.*\d)[A-Za-z0-9_\-]{16,}$')  # long mixed alnum w/ a digit


def _templatize_segment(seg: str) -> str:
    if not seg:
        return seg
    if _NUM_RE.match(seg):
        return '{id}'
    if _UUID_RE.match(seg):
        return '{uuid}'
    if _DATE_RE.match(seg):
        return '{date}'
    if _HEX_RE.match(seg):
        return '{hash}'
    if _LONGTOKEN_RE.match(seg):
        return '{token}'
    return seg


def templatize_path(path: str) -> str:
    """Normalise volatile path segments (ids/uuids/hashes/dates/tokens)."""
    if not path:
        return '/'
    parts = path.split('/')
    return '/'.join(_templatize_segment(p) for p in parts) or '/'


def path_words(template: str) -> str:
    """Human/word form of a path template for the embedding text."""
    words = re.split(r'[/_\-.]', template)
    words = [w for w in words if w and not (w.startswith('{') and w.endswith('}'))]
    return ' '.join(words)


def path_depth(path: str) -> int:
    return len([p for p in path.split('/') if p])


# ---------------------------------------------------------------------------
# Parameters
# ---------------------------------------------------------------------------
def _json_keys(obj, prefix, depth, out, cap):
    if len(out) >= cap or depth > SCHEMA_DEPTH_CAP:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            out.append(key)
            if isinstance(v, (dict, list)):
                _json_keys(v, key, depth + 1, out, cap)
            if len(out) >= cap:
                return
    elif isinstance(obj, list) and obj:
        _json_keys(obj[0], f"{prefix}[]", depth + 1, out, cap)


def extract_param_names(method, url, req_content_type, req_body):
    """Union of query + body parameter *names* (values suppressed)."""
    names = []
    q = urlparse(url).query
    if q:
        names.extend(parse_qs(q, keep_blank_values=True).keys())

    ct = (req_content_type or '').lower()
    body = req_body or ''
    if method in ('POST', 'PUT', 'PATCH', 'DELETE') and body:
        if 'application/x-www-form-urlencoded' in ct:
            names.extend(parse_qs(body, keep_blank_values=True).keys())
        elif 'json' in ct:
            try:
                parsed = json.loads(body)
                keys = []
                _json_keys(parsed, '', 1, keys, PARAM_CAP)
                names.extend(keys)
            except Exception:
                pass
        elif 'multipart/form-data' in ct:
            names.extend(re.findall(r'name="([^"]+)"', body))
        else:
            # Best-effort: try JSON even without a matching content-type.
            try:
                parsed = json.loads(body)
                keys = []
                _json_keys(parsed, '', 1, keys, PARAM_CAP)
                names.extend(keys)
            except Exception:
                pass

    seen, out = set(), []
    for n in names:
        n = n.strip()
        if n and n not in seen:
            seen.add(n)
            out.append(n)
        if len(out) >= PARAM_CAP:
            break
    return sorted(out)


# ---------------------------------------------------------------------------
# Cookies / JWT
# ---------------------------------------------------------------------------
def _looks_like_jwt(value: str) -> bool:
    parts = value.split('.')
    if len(parts) != 3 or not parts[0].startswith('eyJ'):
        return False
    return all(p and all(c.isalnum() or c in '-_' for c in p) for p in parts)


def cookie_names_from_request(headers: dict):
    names = []
    for v in header_all(headers, 'cookie'):
        for part in v.split(';'):
            part = part.strip()
            if '=' in part:
                names.append(part.split('=', 1)[0].strip())
    seen, out = set(), []
    for n in names:
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return out


def parse_jwt(token: str) -> dict:
    """Return {alg, claims:[names], role} for a JWT; values suppressed."""
    out = {'alg': '', 'claims': [], 'role': ''}
    if 'Bearer ' in token:
        token = token.split('Bearer ', 1)[1]
    token = token.strip()
    parts = token.split('.')
    if len(parts) != 3:
        return out

    def _b64(seg):
        seg += '=' * (-len(seg) % 4)
        return base64.urlsafe_b64decode(seg.encode('utf-8'))

    try:
        header = json.loads(_b64(parts[0]))
        out['alg'] = str(header.get('alg', ''))
    except Exception:
        pass
    try:
        payload = json.loads(_b64(parts[1]))
        if isinstance(payload, dict):
            out['claims'] = sorted(str(k) for k in payload.keys())
            role = payload.get('role')
            if not role and isinstance(payload.get('data'), dict):
                role = payload['data'].get('role')
            if role:
                out['role'] = str(role)
    except Exception:
        pass
    return out


def _primary_credential(headers: dict):
    """Return (mechanism, token_or_value) for the strongest credential seen."""
    authz = header_get(headers, 'authorization')
    if authz:
        low = authz.lower()
        if low.startswith('bearer'):
            tok = authz.split(' ', 1)[1].strip() if ' ' in authz else ''
            return ('bearer-jwt' if _looks_like_jwt(tok) else 'bearer-opaque', tok)
        if low.startswith('basic'):
            return ('basic', '')
        return ('custom-header', '')

    for h in AUTH_HEADERS:
        val = header_get(headers, h)
        if val:
            return ('api-key-header', val)

    # Custom/unknown auth header by signal.
    for k, v in headers.items():
        kl = k.lower()
        if kl not in ('cookie',) and v.strip() and any(s in kl for s in AUTH_HEADER_SIGNALS):
            return ('custom-header', '')

    # Session/auth cookie.
    for v in header_all(headers, 'cookie'):
        for part in v.split(';'):
            part = part.strip()
            if '=' not in part:
                continue
            name, val = part.split('=', 1)
            if name.strip().lower() in AUTH_COOKIE_NAMES or _looks_like_jwt(val.strip()):
                return ('cookie-session', val.strip())
    return ('none', '')


def request_features(method: str, url: str, headers: dict, param_names):
    """Value-suppressed request credential/header features."""
    req_host = (urlparse(url).hostname or '').lower()
    mechanism, token = _primary_credential(headers)
    authenticated = mechanism != 'none'

    role = ''
    jwt_str = ''
    if token and _looks_like_jwt(token):
        info = parse_jwt(token)
        role = info['role']
        claims = ",".join(info['claims'][:12])
        jwt_str = f"alg={info['alg'] or '?'};claims={claims}" if (info['alg'] or claims) else ''
    if not role:
        role = 'authenticated' if authenticated else 'anonymous'

    cookie_names = cookie_names_from_request(headers)

    # Origin / Referer cross-site.
    origin = header_get(headers, 'origin')
    origin_host = (urlparse(origin).hostname or '').lower() if origin else ''
    origin_cross_site = bool(origin_host and req_host and origin_host != req_host)

    host_header = header_get(headers, 'host')

    # CSRF token presence (cookie / header / param name).
    header_names = [k.lower() for k in headers.keys()]
    csrf_pool = cookie_names + header_names + list(param_names)
    has_csrf = any(sig in n.lower() for n in csrf_pool for sig in CSRF_SIGNALS)

    custom_auth_headers = sorted({
        k for k in headers
        if k.lower() in AUTH_HEADERS or (
            k.lower() not in ('cookie', 'authorization')
            and any(s in k.lower() for s in AUTH_HEADER_SIGNALS))
    })

    feats = []
    if origin_cross_site:
        feats.append('origin-cross-site')
    if has_csrf:
        feats.append('csrf-token')
    if custom_auth_headers:
        feats.append('custom-auth-header')
    if host_header:
        feats.append(f"host={host_header}")

    return {
        'auth_mechanism': mechanism,
        'authenticated': authenticated,
        'auth_role': role,
        'cookie_names': cookie_names,
        'jwt': jwt_str,
        'origin_cross_site': origin_cross_site,
        'host_header': host_header,
        'has_csrf_token': has_csrf,
        'custom_auth_headers': custom_auth_headers,
        'req_features_csv': feats,
    }


# ---------------------------------------------------------------------------
# Response security posture
# ---------------------------------------------------------------------------
def _parse_set_cookie(value: str):
    """Return (name, flags_list) for a Set-Cookie header value; value dropped."""
    parts = [p.strip() for p in value.split(';')]
    if not parts or '=' not in parts[0]:
        return None
    name = parts[0].split('=', 1)[0].strip()
    flags = []
    samesite = ''
    for attr in parts[1:]:
        al = attr.lower()
        if al == 'httponly':
            flags.append('HttpOnly')
        elif al == 'secure':
            flags.append('Secure')
        elif al.startswith('samesite='):
            samesite = attr.split('=', 1)[1].strip()
            flags.append(f"SameSite={samesite}")
        elif al.startswith('domain='):
            flags.append('Domain')
        elif al.startswith('path='):
            flags.append('Path')
    return name, flags


def response_features(resp_headers: dict, req_origin: str = ''):
    set_cookies = []       # "NAME(HttpOnly,Secure)"
    cookie_issues = []     # "NAME:no-httponly,no-samesite"
    for v in header_all(resp_headers, 'set-cookie'):
        parsed = _parse_set_cookie(v)
        if not parsed:
            continue
        name, flags = parsed
        set_cookies.append(f"{name}({','.join(flags)})" if flags else f"{name}()")
        issues = []
        if 'HttpOnly' not in flags:
            issues.append('no-httponly')
        if 'Secure' not in flags:
            issues.append('no-secure')
        if not any(f.startswith('SameSite') for f in flags):
            issues.append('no-samesite')
        if issues:
            cookie_issues.append(f"{name}:{','.join(issues)}")

    present = {k.lower() for k in resp_headers}
    missing = [short for hdr, short in SECURITY_HEADERS.items() if hdr not in present]

    acao = header_get(resp_headers, 'access-control-allow-origin')
    creds = header_get(resp_headers, 'access-control-allow-credentials').lower() == 'true'
    cors = ''
    if acao:
        if acao.strip() == '*':
            cors = '*'
        elif acao.strip().lower() == 'null':
            cors = 'null'
        elif req_origin and acao.strip().lower() == req_origin.strip().lower():
            cors = 'reflected'
        else:
            cors = 'specific'

    return {
        'sets_cookie': bool(set_cookies),
        'set_cookies': set_cookies,
        'cookie_issues': cookie_issues,
        'security_headers_missing': missing,
        'cors': cors,
        'cors_credentials': creds,
        'redirect_location': header_get(resp_headers, 'location'),
    }


# ---------------------------------------------------------------------------
# Response classification + distillation (the router)
# ---------------------------------------------------------------------------
def resp_media_type(resp_headers: dict) -> str:
    return header_get(resp_headers, 'content-type').split(';', 1)[0].strip().lower()


def is_static_asset(mimetype: str, file_ext: str, resp_ct: str) -> bool:
    mt = (mimetype or '').lower()
    ext = (file_ext or '').lower()
    ct = (resp_ct or '').lower()
    if mt in STATIC_MIMETYPES or ext in STATIC_EXTS:
        return True
    return bool(ct and (ct.startswith('image/') or ct.startswith('font/')
                        or ct in ('text/css', 'application/javascript',
                                  'text/javascript')))


def _looks_json(body: str) -> bool:
    s = body.lstrip()[:1]
    return s in ('{', '[')


def is_spa_shell_html(body: str) -> bool:
    """Per-response heuristic: near-empty visible text + a JS mount point."""
    try:
        soup = BeautifulSoup(body, 'html.parser')
    except Exception:
        return False
    for t in soup(['script', 'style', 'noscript', 'svg']):
        t.decompose()
    text = " ".join(soup.get_text(" ").split())
    if len(text) >= SPA_TEXT_THRESHOLD:
        return False
    low = body.lower()
    mount_signals = ('id="root"', "id='root'", 'id="app"', "id='app'",
                     'data-reactroot', '<app-root', 'ng-app', 'ng-version',
                     'id="__next"', 'id="__nuxt"')
    has_mount = any(sig in low for sig in mount_signals)
    has_bundle = bool(re.search(r'<script[^>]+src=', low))
    return has_mount or has_bundle


# ---------------------------------------------------------------------------
# Access classification (login / auth-wall detection)
# ---------------------------------------------------------------------------
def is_login_path(path: str) -> bool:
    p = (path or '').lower()
    return any(sig in p for sig in LOGIN_PATH_SIGNALS)


def login_redirect(location: str) -> bool:
    """True if a redirect/Location points at a login/auth destination."""
    return is_login_path(location or '')


def json_auth_wall(body: str, messages=None) -> bool:
    """True if a JSON/text body is really an 'unauthorized' / 'log in' response."""
    hay = (" ".join(messages) if messages else "").lower()
    if not hay:
        hay = (body or '')[:600].lower()
    if any(sig in hay for sig in JSON_AUTHWALL_SIGNALS):
        return True
    # {"authenticated": false} / {"loggedIn": false} style envelopes.
    return bool(re.search(r'"(?:authenticated|logged_?in|isauthenticated)"\s*:\s*false',
                          (body or '')[:600], re.I))


def html_login_signals(body: str) -> dict:
    """Detect a login page. A password input is required for the heuristic to
    fire (so a mere 'Login' nav link on a public page does not match)."""
    low = (body or '').lower()
    password_field = bool(re.search(r'<input[^>]+type=["\']?password', low))
    login_form = password_field and bool(re.search(
        r'<form[^>]+action=["\'][^"\']*(?:login|signin|sign-in|authenticate|session)', low))
    # Visible text signals (title / short body) — used to raise confidence.
    text_signal = any(sig in low for sig in LOGIN_TEXT_SIGNALS)
    is_login = password_field and (login_form or text_signal)
    return {'password_field': password_field, 'login_form': login_form,
            'text_signal': text_signal, 'is_login': is_login}


def classify_response(status_code, resp_headers, resp_body, resp_ct, file_ext,

                      mimetype=''):
    if 300 <= status_code < 400 or header_get(resp_headers, 'location'):
        return 'redirect'
    if not (resp_body or '').strip():
        return 'empty'
    if is_static_asset(mimetype, file_ext, resp_ct):
        return 'static_asset'
    ct = resp_ct or ''
    if 'json' in ct or 'xml' in ct or _looks_json(resp_body):
        return 'api_structured'
    if 'html' in ct or '<html' in resp_body[:2000].lower() or \
            '<!doctype html' in resp_body[:200].lower():
        return 'spa_shell' if is_spa_shell_html(resp_body) else 'html_document'
    return 'text_other'


def json_schema(body: str):
    """Return (schema_sig, distilled_str) for a JSON/structured body."""
    try:
        obj = json.loads(body)
    except Exception:
        return '', _truncate(body, 200)

    keys, samples, messages = [], [], []
    counter = {'n': 0}

    def walk(o, prefix, depth):
        if counter['n'] >= SCHEMA_NODE_CAP or depth > SCHEMA_DEPTH_CAP:
            return
        counter['n'] += 1
        if isinstance(o, dict):
            for k, v in o.items():
                key = f"{prefix}.{k}" if prefix else str(k)
                keys.append(key)
                if str(k).lower() in MESSAGE_KEYS and isinstance(v, (str, int, float)):
                    sval = _truncate(str(v), 80)
                    if sval:
                        messages.append(f"{k}={sval}")
                elif isinstance(v, (str, int, float, bool)) and v not in (None, '') \
                        and len(samples) < SAMPLE_SCALAR_CAP and str(k).lower() not in MESSAGE_KEYS:
                    sval = _truncate(str(v), 40)
                    if sval and not _looks_like_jwt(sval):
                        samples.append(f"{k}={sval}")
                if isinstance(v, (dict, list)):
                    walk(v, key, depth + 1)
        elif isinstance(o, list) and o:
            walk(o[0], f"{prefix}[]", depth + 1)

    walk(obj, '', 1)
    uniq_keys = sorted(dict.fromkeys(keys))
    sig = md5("|".join(uniq_keys))
    bits = []
    if uniq_keys:
        bits.append("keys: " + ", ".join(uniq_keys[:SCHEMA_KEY_CAP]))
    if messages:
        bits.append("; ".join(messages[:3]))
    if samples:
        bits.append("sample: " + ", ".join(samples))
    return sig, _truncate(" | ".join(bits), 800)


def xml_schema(body: str):
    """Return a bounded element-path schema and useful leaf text for XML."""
    try:
        root = ET.fromstring(body)
    except Exception:
        return '', _truncate(body, 200)

    paths, samples = [], []

    def local_name(tag):
        return str(tag).rsplit('}', 1)[-1]

    def walk(element, prefix='', depth=1):
        if len(paths) >= SCHEMA_NODE_CAP or depth > SCHEMA_DEPTH_CAP:
            return
        name = local_name(element.tag)
        path = f"{prefix}.{name}" if prefix else name
        paths.append(path)
        for attr in sorted(element.attrib)[:10]:
            paths.append(f"{path}.@{local_name(attr)}")
        text = (element.text or '').strip()
        if text and len(samples) < SAMPLE_SCALAR_CAP:
            samples.append(f"{name}={_truncate(text, 60)}")
        for child in list(element):
            walk(child, path, depth + 1)

    walk(root)
    uniq_paths = sorted(dict.fromkeys(paths))
    bits = []
    if uniq_paths:
        bits.append("elements: " + ", ".join(uniq_paths[:SCHEMA_KEY_CAP]))
    if samples:
        bits.append("sample: " + ", ".join(samples))
    return md5("|".join(uniq_paths)), _truncate(" | ".join(bits), 800)


def structured_schema(body: str, content_type=''):
    if 'xml' in (content_type or '').lower() or body.lstrip().startswith('<?xml'):
        return xml_schema(body)
    return json_schema(body)


# ---- HTML distillation + boilerplate -------------------------------------
_CHROME_TAGS = ('nav', 'header', 'footer', 'aside')


def _strip_for_page(body: str):
    soup = BeautifulSoup(body, 'html.parser')
    for t in soup(['script', 'style', 'noscript', 'svg']):
        t.decompose()
    return soup


def html_text_blocks(body: str):
    """Normalised text blocks of an HTML page, for cross-page boilerplate freq."""
    soup = _strip_for_page(body)
    blocks = set()
    for el in soup.find_all(['h1', 'h2', 'h3', 'h4', 'li', 'p', 'a', 'button',
                             'label', 'td', 'th', 'span']):
        txt = " ".join(el.get_text(" ").split())
        if 3 <= len(txt) <= 200:
            blocks.add(txt)
    return blocks


def page_fingerprint(body: str) -> str:
    """Structural skeleton hash of an HTML page: tag sequence + form field
    names/types + <title>, with all text and attribute *values* dropped. Stable
    across CSRF tokens / per-request values, so two renders of the same login
    page collapse to one fingerprint."""
    try:
        soup = _strip_for_page(body)
    except Exception:
        return ''
    tokens = []
    title = soup.title.string if (soup.title and soup.title.string) else ''
    if title:
        tokens.append('title:' + " ".join(title.split()).lower())
    for el in soup.find_all(True):
        name = el.name
        if name in ('input', 'select', 'textarea', 'button'):
            tokens.append(f"{name}:{(el.get('name') or el.get('id') or '')}"
                          f":{el.get('type') or ''}".lower())
        elif name == 'form':
            tokens.append('form')
        else:
            tokens.append(name)
    return md5("|".join(tokens))



def html_page_summary(body: str, boilerplate=None) -> str:
    """Distil an MPA page to its discriminating parts (chrome + boilerplate removed)."""
    boilerplate = boilerplate or set()
    soup = _strip_for_page(body)

    title = ""
    if soup.title and soup.title.string:
        title = " ".join(soup.title.string.split())

    # Remove chrome before harvesting headings/links/text.
    chrome = soup.find_all(_CHROME_TAGS) + soup.find_all(attrs={'role': 'navigation'})
    for el in chrome:
        el.decompose()

    headings = []
    for h in soup.find_all(['h1', 'h2', 'h3']):
        t = " ".join(h.get_text(" ").split())
        if t and t not in boilerplate:
            headings.append(t)
        if len(headings) >= HTML_HEADING_CAP:
            break

    forms = []
    for form in soup.find_all('form'):
        action = form.get('action', '')
        method = (form.get('method', 'GET') or 'GET').upper()
        fields = []
        for inp in form.find_all(['input', 'select', 'textarea', 'button']):
            nm = inp.get('name') or inp.get('id')
            if nm:
                fields.append(nm)
        forms.append(f"form {method} {action} ({','.join(fields)})")

    main = soup.find('main') or soup.find(attrs={'role': 'main'}) or \
        soup.find('article') or soup.body or soup
    lead = " ".join(main.get_text(" ").split()) if main else ""
    if boilerplate:
        for b in boilerplate:
            if b in lead:
                lead = lead.replace(b, ' ')
    lead = _truncate(lead, HTML_TEXT_LEAD_CAP)

    links = []
    for a in soup.find_all('a', href=True):
        href = a['href']
        if href.startswith('/') and href not in links:
            links.append(href)
        if len(links) >= HTML_LINK_CAP:
            break

    bits = []
    if title:
        bits.append(f"page: {title}")
    if headings:
        bits.append("headings: " + " / ".join(headings))
    if forms:
        bits.append(" ; ".join(forms))
    if links:
        bits.append("links: " + ", ".join(links))
    if lead:
        bits.append(lead)
    return _truncate(" | ".join(bits), 900)


def distill_response(resp_class, body, resp_ct, redirect_location, boilerplate=None):
    """Route a response to the right distiller. Returns (distilled_str, schema_sig)."""
    if resp_class == 'api_structured':
        sig, summary = structured_schema(body, resp_ct)
        return summary, sig
    if resp_class == 'html_document':
        return html_page_summary(body, boilerplate), ''
    if resp_class == 'spa_shell':
        return 'SPA application shell', ''
    if resp_class == 'static_asset':
        return f"static asset {resp_ct or ''}".strip(), ''
    if resp_class == 'redirect':
        return f"redirect -> {redirect_location}".strip(), ''
    if resp_class == 'empty':
        return 'empty body', ''
    return _truncate(body, 200), ''


# ---------------------------------------------------------------------------
# embed_text / summary formatters
# ---------------------------------------------------------------------------
def _security_clause(reqf, respf):
    sec = []
    if reqf.get('cookie_names'):
        sec.append("cookies: " + ",".join(reqf['cookie_names'][:8]))
    if respf.get('set_cookies'):
        sec.append("sets: " + ",".join(respf['set_cookies'][:6]))
    if respf.get('security_headers_missing'):
        sec.append("sec-missing: " + ",".join(respf['security_headers_missing']))
    if respf.get('cors'):
        sec.append("cors: " + respf['cors'] + (" creds" if respf.get('cors_credentials') else ""))
    if reqf.get('origin_cross_site'):
        sec.append("origin: cross-site")
    if reqf.get('jwt'):
        sec.append("jwt: " + reqf['jwt'])
    return sec


def behavior_embed_text(a) -> str:
    reqf, respf = a['req_features'], a['resp_features']
    parts = [f"{a['method']} {a['endpoint_template']}"]
    if a['param_names']:
        parts.append("params: " + ", ".join(a['param_names']))
    if a['req_content_type']:
        parts.append("req: " + a['req_content_type'])
    parts.append(f"status: {a['status_code']} {status_class(a['status_code'])}".strip())
    if a['resp_distilled']:
        parts.append("resp: " + a['resp_distilled'])
    parts.append("auth: " + (reqf.get('auth_role') or 'anonymous'))
    parts.extend(_security_clause(reqf, respf))
    return _truncate(" | ".join(parts), EMBED_TEXT_CAP)


def behavior_segment_texts(a):
    """Protocol-aware child representations used by hybrid retrieval."""
    reqf, respf = a['req_features'], a['resp_features']
    route = [f"request route {a['method']} {path_words(a['endpoint_template'])}",
             a['endpoint_template'], f"host: {a['host']}"]
    if a['param_names']:
        route.append("parameters: " + ", ".join(a['param_names']))
    if a['req_content_type']:
        route.append("request content: " + a['req_content_type'])

    response = [f"response for {a['method']} {a['endpoint_template']}",
                f"status: {a['status_code']} {status_class(a['status_code'])}",
                f"type: {a['resp_content_type'] or a['resp_class']}"]
    if a['resp_distilled']:
        response.append(a['resp_distilled'])
    if a.get('access_class'):
        response.append("access outcome: " + a['access_class'])

    security = [f"access and session behavior on {a['method']} {a['endpoint_template']}",
                "auth role: " + (reqf.get('auth_role') or 'anonymous'),
                "auth mechanism: " + (reqf.get('auth_mechanism') or 'none')]
    security.extend(_security_clause(reqf, respf))
    if a.get('anon_matches_auth'):
        security.append("anonymous response matches authenticated response")
    return {
        'route': _truncate(" | ".join(route), EMBED_TEXT_CAP),
        'response': _truncate(" | ".join(response), EMBED_TEXT_CAP),
        'security': _truncate(" | ".join(security), EMBED_TEXT_CAP),
    }


def behavior_summary(a) -> str:
    reqf = a['req_features']
    ptop = ",".join(a['param_names'][:3])
    s = (f"{a['method']} {a['endpoint_template']} \u2192 {a['status_code']} · "
         f"{a['param_count']}p" + (f" [{ptop}]" if ptop else "") +
         (f" · {a['resp_content_type']}" if a['resp_content_type'] else "") +
         f" · {reqf.get('auth_role') or 'anonymous'}")
    return _truncate(s, SUMMARY_CAP)


def structure_embed_text(node) -> str:
    parts = [f"{node['node_kind']}: {node['method']} {path_words(node['endpoint_template'])}".strip()]
    parts.append(node['endpoint_template'])
    if node['param_names']:
        parts.append("params: " + ", ".join(node['param_names']))
    if node.get('produces'):
        parts.append("produces: " + ", ".join(node['produces']))
    if node.get('status_codes'):
        parts.append("statuses: " + ", ".join(str(s) for s in node['status_codes']))
    if node.get('auth_mechanisms'):
        parts.append("auth: " + ", ".join(node['auth_mechanisms']))
    if node.get('cookies_set'):
        parts.append("sets: " + ", ".join(node['cookies_set'][:6]))
    if node.get('security_headers_missing'):
        parts.append("sec-missing: " + ", ".join(node['security_headers_missing']))
    if node.get('cors'):
        parts.append("cors: " + node['cors'])
    if node.get('access_control') and node['access_control'] != 'unknown':
        parts.append("access: " + node['access_control'])
    if node.get('page_title'):
        parts.append("title: " + node['page_title'])
    return _truncate(" | ".join(parts), EMBED_TEXT_CAP)


def structure_segment_texts(node):
    identity = [f"{node['node_kind']} route {node['method']} "
                f"{path_words(node['endpoint_template'])}",
                node['endpoint_template'], f"host: {node['host']}"]
    if node['param_names']:
        identity.append("parameters: " + ", ".join(node['param_names']))
    if node.get('produces'):
        identity.append("produces: " + ", ".join(node['produces']))

    posture = [f"access posture for {node['method']} {node['endpoint_template']}"]
    if node.get('status_codes'):
        posture.append("statuses: " + ", ".join(str(s) for s in node['status_codes']))
    if node.get('access_control'):
        posture.append("access: " + node['access_control'])
    if node.get('auth_mechanisms'):
        posture.append("authentication: " + ", ".join(node['auth_mechanisms']))
    if node.get('cookies_set'):
        posture.append("sets cookies: " + ", ".join(node['cookies_set']))
    if node.get('security_headers_missing'):
        posture.append("security headers missing: " +
                       ", ".join(node['security_headers_missing']))
    if node.get('cors'):
        posture.append("cors: " + node['cors'])
    return {
        'identity': _truncate(" | ".join(identity), EMBED_TEXT_CAP),
        'posture': _truncate(" | ".join(posture), EMBED_TEXT_CAP),
    }


def structure_summary(node) -> str:
    access = node.get('access_control', '')
    tail = f" · access:{access}" if access and access != 'unknown' else \
        (" · anon:yes" if node.get('anon_allowed') else "")
    s = (f"{node['node_kind']}: {node['method']} {node['endpoint_template']} · "
         f"{len(node['param_names'])}p · seen {node['instance_count']}×{tail}")
    return _truncate(s, SUMMARY_CAP)


def auth_model_embed_text(host, model) -> str:
    parts = [f"auth model {host}"]
    if model.get('auth_mechanisms'):
        parts.append("mechanisms: " + ", ".join(model['auth_mechanisms']))
    if model.get('cookies_set_map'):
        setmap = ", ".join(f"{c}@{','.join(sorted(ep)[:3])}"
                           for c, ep in list(model['cookies_set_map'].items())[:8])
        parts.append("set: " + setmap)
    if model.get('cookies_sent_map'):
        sentmap = ", ".join(f"{c}@[{','.join(sorted(ep)[:4])}]"
                            for c, ep in list(model['cookies_sent_map'].items())[:8])
        parts.append("consumed: " + sentmap)
    if model.get('token'):
        parts.append("token: " + model['token'])
    if model.get('security_headers_missing'):
        parts.append("posture: sec-missing " + ", ".join(model['security_headers_missing']))
    if model.get('cors'):
        parts.append("cors: " + model['cors'])
    return _truncate(" | ".join(parts), EMBED_TEXT_CAP)


def auth_model_summary(host, model) -> str:
    s = (f"auth model {host} · mechanisms: "
         f"{','.join(model.get('auth_mechanisms', []) or ['none'])} · "
         f"{len(model.get('cookies_set_map', {}))} cookies set")
    return _truncate(s, SUMMARY_CAP)


def attack_embed_text(m) -> str:
    parts = [f"{m['vuln_class']} on {m['method']} {m['endpoint_template']}"]
    if m.get('param'):
        parts.append("param " + m['param'])
    if m.get('payload'):
        parts.append("payload: " + _truncate(m['payload'], 120))
    resp = f"resp: {m.get('status_code', '')}".strip()
    if m.get('evidence'):
        resp += " " + _truncate(m['evidence'], 160)
    parts.append(resp)
    parts.append("verdict: " + m.get('verdict', ''))
    return _truncate(" | ".join(parts), EMBED_TEXT_CAP)


def attack_summary(m) -> str:
    s = (f"{m['vuln_class']} {m.get('param', '')} on {m['method']} "
         f"{m['endpoint_template']} \u2192 {m.get('verdict', '')} "
         f"({m.get('status_code', '')})")
    return _truncate(s, SUMMARY_CAP)


# ---------------------------------------------------------------------------
# Behavior collapse identity (shared by the structure + behavior builders)
# ---------------------------------------------------------------------------
def behavior_collapse_key(a):
    """Distinct-behavior identity. Deliberately includes status_code, auth role,
    response schema, and access outcome so security-relevant variations (e.g. a
    data response vs a login-wall response to the same endpoint) never merge."""
    return (a.get('scheme', ''), a['host'], a.get('port', 0), a['method'],
            a['endpoint_template'], a['status_code'],
            a['req_features']['auth_role'], a.get('resp_schema_sig', ''),
            a.get('access_class', ''))


def behavior_id(a) -> str:
    return md5("|".join(str(x) for x in behavior_collapse_key(a)))
