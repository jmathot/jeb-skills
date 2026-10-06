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
from collections import Counter
from functools import lru_cache
from urllib.parse import urlparse, parse_qs

from bs4 import BeautifulSoup, Comment

# ---------------------------------------------------------------------------
# Caps
# ---------------------------------------------------------------------------
EMBED_TEXT_CAP = 1500          # max chars of any embed_text
SUMMARY_CAP = 200              # max chars of any summary one-liner
SCHEMA_KEY_CAP = 40            # max response schema key-paths in embed text
SCHEMA_DEPTH_CAP = 8           # recursion depth for JSON schema walk
SCHEMA_NODE_CAP = 250          # total nodes visited in JSON schema walk
SAMPLE_SCALAR_CAP = 5          # sample scalar values kept from a JSON body
PARAM_CAP = 40                 # max parameter names collected *per source* (query / body)
HTML_HEADING_CAP = 8
HTML_LINK_CAP = 25
HTML_TEXT_LEAD_CAP = 300
HTML_SUMMARY_CAP = 1000        # whole-summary budget; every part below has its own share
HTML_TITLE_CAP = 100
HTML_HEADINGS_CHARS = 200
HTML_FORMS_CHARS = 160
HTML_LINKS_CHARS = 120
HTML_ARTIFACT_CHARS = 140
HTML_ARTIFACT_CAP = 12         # comments / script endpoints / meta kept per page
STATIC_ENDPOINT_CAP = 15       # endpoint-like strings kept from a JS asset
STATIC_SCAN_CHARS = 2_000_000  # bytes of a JS asset scanned for endpoints
TEXT_OTHER_CAP = 500
TECH_CAP = 6                   # technology / framework response headers kept
VARIANT_KEY_VALUES = frozenset({
    'message', 'error', 'msg', 'errors', 'reason', 'code', 'status', 'type',
    'action', 'category', 'kind', 'mode', 'operation', 'result', 'role', 'state'})
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
SEMANTIC_VALUE_KEYS = {
    'action', 'category', 'kind', 'mode', 'operation', 'result', 'role',
    'state', 'status', 'type',
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


# Loss ledger: every cap that silently discards data counts itself here, so an
# import can report how much was cut instead of leaving it invisible. Counts are
# per process; the rebuild resets them and stores the snapshot with the project.
LEDGER = Counter()


def ledger_reset():
    LEDGER.clear()


def ledger_snapshot():
    return dict(sorted(LEDGER.items()))


def _truncate(text: str, cap: int, field: str = '') -> str:
    text = " ".join((text or "").split())
    if len(text) <= cap:
        return text
    if field:
        LEDGER['truncated.' + field] += 1
    return text[:cap] + "…"


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
_WORD_RE = re.compile(r'^[A-Za-z]{2,}$')


def _is_opaque_token(seg: str) -> bool:
    """Long mixed alphanumeric that is an identifier rather than a readable slug.

    A hyphen/underscore-separated run of dictionary-looking words with a number
    in it (`top-10-tips-for-2024`) is a slug naming one distinct page; templating
    it would merge every article under one route. Two or more word-like parts
    mean slug; a nanoid or base62 id has at most one by chance.
    """
    if not _LONGTOKEN_RE.match(seg):
        return False
    return sum(bool(_WORD_RE.match(part)) for part in re.split(r'[-_]', seg)) < 2


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
    if _is_opaque_token(seg):
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
# Identifier values (for cross-endpoint instance correlation)
# ---------------------------------------------------------------------------
IDENTIFIER_CAP = 1000
IDENTIFIER_NODE_BUDGET = 50000   # JSON nodes visited per body when hunting identifiers
# snake_case / bare (`id`, `user_id`) case-insensitively, plus camelCase
# (`userId`, `accountID`, `orderUuid`), which is the convention of most JSON APIs.
_IDENTIFIER_KEY_RE = re.compile(
    r'(?:(?i:(?:^|_)(?:id|uuid|guid))|(?<=[a-z0-9])(?:Id|ID|Uuid|UUID|Guid|GUID))$')
_IDENTIFIER_LIST_KEY_RE = re.compile(
    r'(?:(?i:(?:^|_)(?:ids|uuids|guids))|(?<=[a-z0-9])(?:Ids|IDs|Uuids|UUIDs|Guids|GUIDs))$')
_PREFIXED_IDENTIFIER_RE = re.compile(r'^[A-Za-z][A-Za-z0-9-]{0,15}_[A-Za-z0-9_-]{3,64}$')
_ULID_RE = re.compile(r'^[0-9A-HJKMNP-TV-Z]{26}$', re.IGNORECASE)


def _sample_list(items, cap=10):
    """Deterministically cover the beginning, middle, and end of a large list."""
    if len(items) <= cap:
        return items
    indices = sorted({round(i * (len(items) - 1) / (cap - 1)) for i in range(cap)})
    return [items[index] for index in indices]


def _looks_like_identifier_value(v) -> bool:
    s = str(v)
    if not s or len(s) > 64:
        return False
    return bool(_NUM_RE.match(s) or _UUID_RE.match(s) or _HEX_RE.match(s)
                or _PREFIXED_IDENTIFIER_RE.match(s) or _ULID_RE.match(s)
                or _is_opaque_token(s))


def _walk_identifier_values(obj, out, cap, depth=0, budget=None):
    """Collect (key, value) identifier pairs.

    Unlike the schema walk this is not sampled: an identifier on the 37th item of
    a 500-item list is as exact-matchable as one on the first, and the lookup
    index only works if it is there. Work is bounded by `budget` nodes instead.
    """
    budget = budget if budget is not None else {'n': IDENTIFIER_NODE_BUDGET}
    if len(out) >= cap or depth > SCHEMA_DEPTH_CAP or budget['n'] <= 0:
        return
    budget['n'] -= 1
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                if isinstance(v, list) and _IDENTIFIER_LIST_KEY_RE.search(str(k)):
                    out.extend((str(k), str(x)) for x in v
                               if not isinstance(x, (dict, list, bool))
                               and _looks_like_identifier_value(x))
                _walk_identifier_values(v, out, cap, depth + 1, budget)
            elif _IDENTIFIER_KEY_RE.search(str(k)) and not isinstance(v, bool) \
                    and _looks_like_identifier_value(v):
                out.append((str(k), str(v)))
            if len(out) >= cap or budget['n'] <= 0:
                return
    elif isinstance(obj, list):
        for item in obj:
            _walk_identifier_values(item, out, cap, depth + 1, budget)
            if len(out) >= cap or budget['n'] <= 0:
                return


def extract_identifier_values(path: str, bodies, url: str = '', content_types=None) -> list:
    """(field, value) pairs for id/uuid/hash-like values in a URL path and any
    number of JSON bodies (pass request + response bodies together). `field`
    is the URL path segment preceding the value ('path' if it's the first
    segment) or the JSON key name. Values are kept verbatim (never templated)
    so callers can exact-match the same identifier across different
    endpoints/collections -- this is deliberately excluded from embed_text and
    Chroma metadata; it belongs in a side exact-match index only."""
    out = []
    segs = [s for s in (path or '').split('/') if s]
    for i, seg in enumerate(segs):
        if len(out) >= IDENTIFIER_CAP:
            break
        if _looks_like_identifier_value(seg):
            field = segs[i - 1] if i > 0 else 'path'
            out.append((field, seg))
    if url:
        for field, values in parse_qs(urlparse(url).query, keep_blank_values=True).items():
            if _IDENTIFIER_KEY_RE.search(field):
                out.extend((field, value) for value in values
                           if _looks_like_identifier_value(value))
    content_types = list(content_types or [])
    for index, body in enumerate(bodies):
        if len(out) >= IDENTIFIER_CAP or not body:
            continue
        content_type = content_types[index] if index < len(content_types) else ''
        try:
            obj = json.loads(body)
        except Exception:
            obj = None
        if obj is not None:
            _walk_identifier_values(obj, out, IDENTIFIER_CAP)
        elif 'x-www-form-urlencoded' in content_type:
            for field, values in parse_qs(body, keep_blank_values=True).items():
                if _IDENTIFIER_KEY_RE.search(field):
                    out.extend((field, value) for value in values
                               if _looks_like_identifier_value(value))
        elif 'xml' in content_type:
            try:
                root = ET.fromstring(body)
                for element in root.iter():
                    name = str(element.tag).rsplit('}', 1)[-1]
                    value = (element.text or '').strip()
                    if _IDENTIFIER_KEY_RE.search(name) and _looks_like_identifier_value(value):
                        out.append((name, value))
            except Exception:
                pass
    seen, uniq = set(), []
    for pair in out:
        if pair not in seen:
            seen.add(pair)
            uniq.append(pair)
    LEDGER['identifiers_dropped'] += max(0, len(uniq) - IDENTIFIER_CAP)
    return uniq[:IDENTIFIER_CAP]


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
    elif isinstance(obj, list):
        for item in _sample_list(obj):
            _json_keys(item, f"{prefix}[]", depth + 1, out, cap)
            if len(out) >= cap:
                return


def _dedupe_cap(names, cap):
    seen, out = set(), []
    for n in names:
        n = n.strip() if isinstance(n, str) else str(n)
        if n and n not in seen:
            seen.add(n)
            out.append(n)
        if len(out) >= cap:
            break
    return out


def extract_param_names(method, url, req_content_type, req_body):
    """Union of query + body parameter *names* (values suppressed).

    Query and body names are capped separately: a wide JSON body must not crowd
    out the handful of query parameters that usually drive the route.
    """
    query_names = []
    q = urlparse(url).query
    if q:
        query_names.extend(parse_qs(q, keep_blank_values=True).keys())

    body_names = []
    ct = (req_content_type or '').lower()
    body = req_body or ''
    if method in ('POST', 'PUT', 'PATCH', 'DELETE') and body:
        if 'application/x-www-form-urlencoded' in ct:
            body_names.extend(parse_qs(body, keep_blank_values=True).keys())
        elif 'multipart/form-data' in ct:
            body_names.extend(re.findall(
                r'content-disposition\s*:[^\r\n]*?\bname\s*=\s*(?:"([^"]+)"|\'([^\']+)\'|([^;\s]+))',
                body, re.I))
            body_names = [next((part for part in n if part), '')
                          if isinstance(n, tuple) else n for n in body_names]
        else:
            # JSON, or best-effort JSON without a matching content-type.
            try:
                parsed = json.loads(body)
                keys = []
                _json_keys(parsed, '', 1, keys, PARAM_CAP)
                body_names.extend(keys)
            except Exception:
                pass

    out = _dedupe_cap(query_names, PARAM_CAP)
    seen = set(out)
    out += [n for n in _dedupe_cap(body_names, PARAM_CAP) if n not in seen]
    LEDGER['param_names_dropped'] += max(0, len(set(query_names)) - PARAM_CAP) \
        + max(0, len(set(body_names)) - PARAM_CAP)
    return sorted(out)


def graphql_operation(req_body: str, url: str = '') -> str:
    """Bounded GraphQL operation identity without variable values."""
    query = ''
    try:
        obj = json.loads(req_body or '')
        if isinstance(obj, dict):
            query = str(obj.get('query', ''))
    except Exception:
        query = req_body or ''
    if not query:
        query = parse_qs(urlparse(url).query).get('query', [''])[0]
    query = re.sub(r'#[^\r\n]*', ' ', query)
    match = re.search(r'\b(query|mutation|subscription)\s*([A-Za-z_][A-Za-z0-9_]*)?', query)
    if match:
        kind, name, start = match.group(1), match.group(2) or 'anonymous', match.end()
    elif query.lstrip().startswith('{'):
        kind, name, start = 'query', 'anonymous', query.find('{') + 1
    else:
        return ''
    fields = re.findall(r'(?<![$.])\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:\([^)]*\))?\s*\{?',
                        query[start:])
    fields = [field for field in fields if field not in ('query', 'mutation', 'fragment')]
    return f"{kind}:{name}:" + ','.join(dict.fromkeys(fields[:12]))


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


def normalize_auth_cookie_names(names):
    """Return validated, lowercased custom authentication cookie names."""
    out = set()
    for value in names or ():
        for name in str(value).split(','):
            name = name.strip()
            if not name:
                continue
            if '=' in name or ';' in name:
                raise ValueError(
                    f"invalid authentication cookie name {name!r}: "
                    "names must not contain '=' or ';'")
            out.add(name.lower())
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
            role = payload.get('role') or payload.get('roles') or payload.get('groups') \
                or payload.get('authorities')
            if not role and isinstance(payload.get('data'), dict):
                role = payload['data'].get('role') or payload['data'].get('roles')
            realm = payload.get('realm_access')
            if not role and isinstance(realm, dict):
                role = realm.get('roles')
            if not role:
                role = next((v for k, v in payload.items()
                             if str(k).lower().endswith(('/role', '/roles'))), '')
            if isinstance(role, (list, tuple, set)):
                role = ','.join(str(v) for v in role[:10])
            if role:
                out['role'] = _truncate(str(role), 120)
    except Exception:
        pass
    return out


AUTH_COOKIE_SIGNALS = ('sess', 'auth', 'token', 'login', 'logged', 'jwt', 'credential')
# CSRF / anti-forgery cookies carry "token" or "auth" in their names but are not
# credentials; `authenticity_token` and `__RequestVerificationToken` are the usual ones.
NON_AUTH_COOKIE_SIGNALS = ('csrf', 'xsrf', 'antiforgery', 'verification', 'authenticity')


def looks_like_auth_cookie_name(name: str) -> bool:
    """Name-shape heuristic for session cookies the exact-name list cannot know
    (`.AspNetCore.Identity.Application`, `next-auth.session-token`, `rack.session`,
    `wordpress_logged_in_*`). A cookie wrongly treated as anonymous would be read
    as an unauthenticated request that was served data."""
    low = (name or '').lower()
    if not low or any(sig in low for sig in NON_AUTH_COOKIE_SIGNALS):
        return False
    if any(sig in low for sig in AUTH_COOKIE_SIGNALS):
        return True
    return 'sid' in re.split(r'[^a-z0-9]+', low) or low.endswith('identity.application')


def _primary_credential(headers: dict, auth_cookie_names=None):
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

    # Session/auth cookie. Custom names are scoped to the current import.
    recognized_cookie_names = AUTH_COOKIE_NAMES | set(auth_cookie_names or ())
    for v in header_all(headers, 'cookie'):
        for part in v.split(';'):
            part = part.strip()
            if '=' not in part:
                continue
            name, val = part.split('=', 1)
            if name.strip().lower() in recognized_cookie_names or _looks_like_jwt(val.strip()) \
                    or looks_like_auth_cookie_name(name):
                return ('cookie-session', val.strip())
    return ('none', '')


def request_features(method: str, url: str, headers: dict, param_names,
                     auth_cookie_names=None):
    """Value-suppressed request credential/header features."""
    req_host = (urlparse(url).hostname or '').lower()
    mechanism, token = _primary_credential(headers, auth_cookie_names)
    authenticated = mechanism != 'none'

    role = ''
    jwt_str = ''
    if token and _looks_like_jwt(token):
        info = parse_jwt(token)
        role = info['role']
        claims = ",".join(info['claims'][:12])
        jwt_str = f"alg={info['alg'] or '?'};claims={claims}" if (info['alg'] or claims) else ''
    if not role:
        role = header_get(headers, 'currentrole').strip()
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
        'credential_present': authenticated,
        'auth_state': 'credential-observed' if authenticated else 'no-recognized-credential',
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


TECH_HEADERS = ('server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version',
                'x-generator', 'x-drupal-cache', 'x-runtime', 'via')


def tech_facts(resp_headers: dict):
    """Stack-fingerprinting response headers, as `name=value`, plus the auth
    challenge scheme and attachment disposition. These are standard recon facts
    that the other response features do not carry."""
    out = []
    for name in TECH_HEADERS:
        value = " ".join(header_get(resp_headers, name).split())
        if value:
            out.append(f"{name}={value[:60]}")
    challenge = header_get(resp_headers, 'www-authenticate').strip()
    if challenge:
        out.append(f"www-authenticate={challenge.split(None, 1)[0][:30]}")
    if header_get(resp_headers, 'content-disposition').lower().lstrip().startswith('attachment'):
        out.append("content-disposition=attachment")
    return out[:TECH_CAP]


def response_features(resp_headers: dict, req_origin: str = ''):
    set_cookies = []       # "NAME(HttpOnly,Secure)"
    cookie_issues = []     # "NAME:no-httponly,no-samesite"
    for v in header_all(resp_headers, 'set-cookie'):
        for value in v.split('\n'):
            parsed = _parse_set_cookie(value)
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
            cors = 'matches-origin'
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
        'tech': tech_facts(resp_headers),
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
    if _html_view(body)['text_len'] >= SPA_TEXT_THRESHOLD:
        return False
    low = body.lower()
    mount_signals = ('id="root"', "id='root'", 'id="app"', "id='app'",
                     'data-reactroot', '<app-root', 'ng-app', 'ng-version',
                     'id="__next"', 'id="__nuxt"')
    return any(sig in low for sig in mount_signals)


# ---------------------------------------------------------------------------
# Access classification (login / auth-wall detection)
# ---------------------------------------------------------------------------
def is_login_path(path: str) -> bool:
    p = (path or '').lower()
    return any(sig in p for sig in LOGIN_PATH_SIGNALS)


def is_login_post_path(path: str) -> bool:
    """Wider than is_login_path, for choosing which POSTs establish a session.

    Token endpoints (`/oauth/token`, `/connect/token`, `/api/auth`) are logins in
    effect. They stay out of is_login_path itself because that also classifies
    redirect targets and pages, where `token` / `auth` would be far too loose.
    """
    p = (path or '').lower().rstrip('/')
    return (is_login_path(p) or '/oauth' in p
            or p.endswith(('/auth', '/token', '/authorize', '/connect/token')))


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


def _cookie_is_cleared(value: str) -> bool:
    """True if a Set-Cookie value clears/expires a cookie (Max-Age<=0, or an
    Expires date in the past — deletions conventionally use the Unix epoch)
    rather than establishing a session."""
    for attr in value.split(';')[1:]:
        attr = attr.strip()
        low = attr.lower()
        if low.startswith('max-age='):
            try:
                if int(attr.split('=', 1)[1].strip()) <= 0:
                    return True
            except ValueError:
                pass
        elif low.startswith('expires=') and '1970' in attr:
            return True
    return False


def detect_login_cookie_names(items):
    """Auto-detect session-cookie names established by a successful login.

    Moderate-strictness heuristic, run as a pre-pass over raw parsed items
    (before pass_a): a candidate is a POST to a login-like path
    (is_login_path). Its paired response (Burp pairs request/response 1:1
    per item) counts as a successful login if the status is not 4xx/5xx and
    the body does not itself still look like a login/auth-wall page
    (html_login_signals / json_auth_wall), excluding a failed-login
    re-render of the form. Every Set-Cookie name from that response is
    registered, unless the cookie is being cleared (Max-Age<=0 / epoch
    Expires). Only cookie names are returned — never values.
    """
    detected = set()
    for item in items:
        if (item.get('method') or '').upper() != 'POST':
            continue
        path = urlparse(item.get('url', '')).path
        if not is_login_post_path(path):
            continue

        status = _to_int(item.get('status', ''))
        if not 200 <= status < 400:
            continue

        resp = item.get('response', {}) or {}
        resp_headers = resp.get('headers', {}) or {}
        if resp.get('decode_error'):
            continue
        if login_redirect(header_get(resp_headers, 'location')):
            continue
        resp_body = resp.get('analysis_body', resp.get('body', '')) or ''

        if html_login_signals(resp_body)['is_login']:
            continue
        if json_auth_wall(resp_body):
            continue

        for raw in header_all(resp_headers, 'set-cookie'):
            # parse.py joins repeated Set-Cookie header instances into one
            # '\n'-joined dict value; split them back out before parsing.
            for value in raw.split('\n'):
                value = value.strip()
                if not value:
                    continue
                parsed = _parse_set_cookie(value)
                if not parsed:
                    continue
                if _cookie_is_cleared(value):
                    continue
                name, _flags = parsed
                if name:
                    detected.add(name.strip().lower())
    return detected


def classify_response(status_code, resp_headers, resp_body, resp_ct, file_ext,

                      mimetype=''):
    if resp_body.startswith('<BINARY_DATA'):
        return 'undecodable' if 'decode_error=' in resp_body else 'binary'
    if 300 <= status_code < 400:
        return 'redirect'
    if not (resp_body or '').strip():
        return 'empty'
    ct = resp_ct or ''
    # Content before extension: `/config.js` that returns JSON is an API response.
    if is_static_asset(mimetype, file_ext, resp_ct) and not (
            'json' in ct or (not ct and _looks_json(resp_body))):
        return 'static_asset'
    if 'json' in ct or 'xml' in ct or _looks_json(resp_body):
        return 'api_structured'
    if 'html' in ct or '<html' in resp_body[:2000].lower() or \
            '<!doctype html' in resp_body[:200].lower():
        return 'spa_shell' if is_spa_shell_html(resp_body) else 'html_document'
    return 'text_other'


def _ranked_keys(keys):
    """Unique keys, shallowest first, discovery order within a depth.

    Capping an alphabetically sorted list keeps whichever names start with a-c;
    ranking by depth keeps the structural skeleton of the document instead.
    """
    uniq = list(dict.fromkeys(keys))
    return sorted(uniq, key=lambda k: k.count('.'))


def json_schema(body: str):
    """Return (schema_sig, distilled_str, uniq_keys) for a JSON/structured body."""
    try:
        obj = json.loads(body)
    except Exception:
        return '', _truncate(body, 200), []

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
                        and len(samples) < SAMPLE_SCALAR_CAP \
                        and str(k).lower() in SEMANTIC_VALUE_KEYS:
                    sval = _truncate(str(v), 40)
                    if sval and not _looks_like_jwt(sval):
                        samples.append(f"{k}={sval}")
                if isinstance(v, (dict, list)):
                    walk(v, key, depth + 1)
        elif isinstance(o, list):
            for item in _sample_list(o):
                walk(item, f"{prefix}[]", depth + 1)
                if counter['n'] >= SCHEMA_NODE_CAP:
                    return

    walk(obj, '', 1)
    uniq_keys = _ranked_keys(keys)
    sig = md5("|".join(sorted(uniq_keys)))
    LEDGER['schema_keys_dropped'] += max(0, len(uniq_keys) - SCHEMA_KEY_CAP)
    if counter['n'] >= SCHEMA_NODE_CAP:
        LEDGER['schema_walk_node_cap_hit'] += 1
    bits = []
    if uniq_keys:
        bits.append("keys: " + ", ".join(uniq_keys[:SCHEMA_KEY_CAP]))
    if messages:
        bits.append("; ".join(messages[:3]))
    if samples:
        bits.append("sample: " + ", ".join(samples))
    return sig, _truncate(" | ".join(bits), 800, 'resp.schema_summary'), uniq_keys[:SCHEMA_KEY_CAP]


def xml_schema(body: str):
    """Return a bounded element-path schema and useful leaf text for XML."""
    try:
        root = ET.fromstring(body)
    except Exception:
        return '', _truncate(body, 200), []

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
    uniq_paths = _ranked_keys(paths)
    bits = []
    if uniq_paths:
        bits.append("elements: " + ", ".join(uniq_paths[:SCHEMA_KEY_CAP]))
    if samples:
        bits.append("sample: " + ", ".join(samples))
    return (md5("|".join(sorted(uniq_paths))), _truncate(" | ".join(bits), 800),
            uniq_paths[:SCHEMA_KEY_CAP])


def structured_schema(body: str, content_type=''):
    """Return (schema_sig, distilled_str, uniq_keys) for a JSON or XML body."""
    if 'xml' in (content_type or '').lower() or body.lstrip().startswith('<?xml'):
        return xml_schema(body)
    return json_schema(body)


def structured_semantic_values(body: str, keys=None):
    """Bounded message/enum values that distinguish behavior without IDs.

    `keys` restricts which fields contribute; the variant signatures pass
    VARIANT_KEY_VALUES so record content (`title`, `description`, `detail`) does
    not turn every list response into its own embedded variant.
    """
    values = []
    try:
        obj = json.loads(body)
    except Exception:
        return values

    def collect(value, depth=0):
        if depth > SCHEMA_DEPTH_CAP or len(values) >= 20:
            return
        if isinstance(value, dict):
            for key, item in value.items():
                name = str(key).lower()
                if name in (keys if keys is not None else MESSAGE_KEYS | SEMANTIC_VALUE_KEYS) \
                        and isinstance(item, (str, int, float, bool)):
                    values.append(f'{key}={_truncate(str(item), 120)}')
                elif isinstance(item, (dict, list)):
                    collect(item, depth + 1)
        elif isinstance(value, list):
            for item in _sample_list(value):
                collect(item, depth + 1)
    collect(obj)
    return sorted(dict.fromkeys(values))


def request_variant_signature(body: str, content_type='') -> str:
    if not body:
        return ''
    if 'json' in (content_type or '').lower() or _looks_json(body):
        sig, _summary, keys = structured_schema(body, content_type)
        return md5('|'.join([sig, ','.join(keys),
                             *structured_semantic_values(body, VARIANT_KEY_VALUES)]))
    if 'xml' in (content_type or '').lower():
        sig, _summary, keys = structured_schema(body, content_type)
        return md5('|'.join([sig, ','.join(keys)]))
    return ''


def response_variant_signature(resp_class, body, content_type='', redirect_location=''):
    """Stable discriminator for materially different responses, suppressing IDs."""
    if resp_class == 'redirect':
        parsed = urlparse(redirect_location or '')
        target = templatize_path(parsed.path or redirect_location or '')
        return md5(f'redirect|{target}')
    if resp_class == 'api_structured':
        sig, _summary, keys = structured_schema(body, content_type)
        semantic = structured_semantic_values(body, VARIANT_KEY_VALUES)
        return md5('|'.join([resp_class, content_type, sig, ','.join(keys), *semantic]))
    if resp_class in ('html_document', 'spa_shell'):
        return md5(page_fingerprint(body) + '|' + html_page_summary(body))
    if resp_class in ('binary', 'undecodable', 'empty'):
        return md5(f'{resp_class}|{body}')
    return md5(f'{resp_class}|{content_type}|{body}')


# ---- HTML distillation + boilerplate -------------------------------------
# One parse per body. Every HTML-derived fact (structural fingerprint, text
# blocks, SPA-shell heuristic, summary parts, page artifacts) comes out of a
# single BeautifulSoup tree, built once and cached as plain data. The tree is
# never shared: it is consumed while the view is built.
try:  # lxml is several times faster; html.parser is the dependency-free fallback
    import lxml  # noqa: F401
    _HTML_PARSER = 'lxml'
except ImportError:  # pragma: no cover
    _HTML_PARSER = 'html.parser'

_SCRIPT_ENDPOINT_RE = re.compile(
    r'''["'`](/[A-Za-z0-9_\-./{}:$]*[A-Za-z][A-Za-z0-9_\-./{}:$]*(?:\?[A-Za-z0-9_\-=&%.{}$]*)?)["'`]''')
_ASSET_SUFFIXES = ('.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff',
                   '.woff2', '.ttf', '.eot', '.map', '.webp', '.html', '.htm')
_CREDENTIAL_ASSIGN_RE = re.compile(
    r'''["']?(api[_-]?key|client[_-]?secret|secret|access[_-]?token|auth[_-]?token|password|passwd)["']?\s*[:=]\s*["'][^"'\s]{8,}''',
    re.I)
_BLOCK_TAGS = ['h1', 'h2', 'h3', 'h4', 'li', 'p', 'a', 'button', 'label', 'td', 'th', 'span']
_LEAD_SCAN_CHARS = 20000


def block_hash(text: str) -> str:
    """Short stable key of a text block. Boilerplate is tracked by this hash so the
    per-exchange feature record stays small; the text is re-derived from the page."""
    return md5(text)[:12]


def _script_endpoints(text: str, cap: int):
    out = []
    for match in _SCRIPT_ENDPOINT_RE.finditer(text or ''):
        value = match.group(1)
        if len(value) < 3 or value.startswith('//') or value.lower().split('?', 1)[0].endswith(_ASSET_SUFFIXES):
            continue
        if value not in out:
            out.append(value)
            if len(out) >= cap:
                break
    return out


def _link_form(href: str) -> str:
    """Link as `path?param,names`: query *values* (per-request tokens) suppressed."""
    href = (href or '').strip()
    if not href or href.startswith('#'):
        return ''
    parsed = urlparse(href)
    if parsed.scheme in ('javascript', 'mailto', 'tel', 'data', 'sms'):
        return ''
    base = (f"//{parsed.netloc}" if parsed.netloc else '') + parsed.path
    names = ','.join(sorted(parse_qs(parsed.query, keep_blank_values=True)))
    return (base or '/') + (f"?{names}" if names else '')


def _page_artifacts(soup) -> list:
    """Comments, meta, script sources/endpoints and iframes: the parts of a page a
    reader never sees but a tester wants. Must run before scripts are removed."""
    comments, endpoints, metas, scripts, frames = [], [], [], [], []
    for node in soup.find_all(string=lambda t: isinstance(t, Comment)):
        text = " ".join(str(node).split())
        if len(text) >= 3 and not text.startswith('[if') and len(comments) < 4:
            comments.append('comment: ' + text[:100])
    for script in soup.find_all('script'):
        src = script.get('src')
        if src:
            parsed = urlparse(src)
            if len(scripts) < 3:
                scripts.append('script ' + ((parsed.netloc + parsed.path) if parsed.netloc else parsed.path))
        else:
            for endpoint in _script_endpoints((script.string or script.get_text() or '')[:200000], 6):
                if endpoint not in endpoints and len(endpoints) < 6:
                    endpoints.append(endpoint)
    for meta in soup.find_all('meta'):
        name = (meta.get('name') or '').lower()
        if name in ('generator', 'robots', 'application-name') and meta.get('content') and len(metas) < 3:
            metas.append(f"{name}: {' '.join(meta['content'].split())[:50]}")
    for frame in soup.find_all('iframe', src=True):
        if len(frames) < 2:
            frames.append('iframe ' + _link_form(frame['src']))
    out = comments + (['script endpoints: ' + ', '.join(endpoints)] if endpoints else []) \
        + metas + frames + scripts
    return out[:HTML_ARTIFACT_CAP]


@lru_cache(maxsize=4)
def _html_view(body: str) -> dict:
    view = {'fingerprint': '', 'blocks': {}, 'text_len': 0, 'title': '', 'headings': [],
            'forms': [], 'links': [], 'artifacts': [], 'lead': ''}
    try:
        soup = BeautifulSoup(body, _HTML_PARSER)
        view['artifacts'] = _page_artifacts(soup)
        for t in soup(['script', 'style', 'noscript', 'svg']):
            t.decompose()
    except Exception:
        return view

    # Structural skeleton (before chrome removal, so it matches the whole page).
    title = soup.title.string if (soup.title and soup.title.string) else ''
    tokens = []
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
    view['fingerprint'] = md5("|".join(tokens))
    view['title'] = " ".join(title.split())
    view['text_len'] = len(" ".join(soup.get_text(" ").split()))

    for el in soup.find_all(_BLOCK_TAGS):
        txt = " ".join(el.get_text(" ").split())
        if 3 <= len(txt) <= 200:
            view['blocks'].setdefault(block_hash(txt), txt)

    # Remove chrome. A <header> that holds a real heading is page content (its <h1>),
    # so only heading-less headers go; nav/footer/aside are navigation by definition.
    for el in soup.find_all(['nav', 'footer', 'aside']) + soup.find_all(attrs={'role': 'navigation'}):
        el.decompose()
    for el in soup.find_all('header'):
        if el.find(['h1', 'h2', 'h3']) is None:
            el.decompose()

    seen = set()
    for h in soup.find_all(['h1', 'h2', 'h3']):
        t = " ".join(h.get_text(" ").split())
        if t and t not in seen:
            seen.add(t)
            view['headings'].append((block_hash(t), t))
        if len(view['headings']) >= HTML_HEADING_CAP * 3:
            break

    for form in soup.find_all('form')[:6]:
        action = _truncate(form.get('action', ''), 80)
        method = (form.get('method', 'GET') or 'GET').upper()
        fields = []
        for inp in form.find_all(['input', 'select', 'textarea', 'button']):
            nm = inp.get('name') or inp.get('id')
            if nm:
                kind = (inp.get('type') or '').lower()
                fields.append(f"{nm}:{kind}" if kind and kind not in ('text', 'submit') else nm)
        view['forms'].append(f"form {method} {action} ({','.join(fields)})")

    main = soup.find('main') or soup.find(attrs={'role': 'main'}) or \
        soup.find('article') or soup.body or soup
    view['lead'] = (" ".join(main.get_text(" ").split())[:_LEAD_SCAN_CHARS]) if main else ""

    for a in soup.find_all('a', href=True):
        link = _link_form(a['href'])
        if link and link not in view['links']:
            view['links'].append(link)
        if len(view['links']) >= HTML_LINK_CAP:
            break
    return view


def html_text_blocks(body: str):
    """Hashes of the normalised text blocks of an HTML page, for cross-page
    boilerplate frequency."""
    return set(_html_view(body)['blocks'])


def page_fingerprint(body: str) -> str:
    """Structural skeleton hash of an HTML page: tag sequence + form field
    names/types + <title>, with all text and attribute *values* dropped. Stable
    across CSRF tokens / per-request values, so two renders of the same login
    page collapse to one fingerprint."""
    return _html_view(body)['fingerprint']


def _drop_blocks(text: str, blocks) -> str:
    """Remove whole boilerplate blocks from `text`, never a fragment of a word."""
    blocks = sorted(set(blocks), key=lambda b: (-len(b), b))
    if not blocks:
        return text
    pattern = re.compile(r'(?<!\w)(?:' + '|'.join(re.escape(b) for b in blocks) + r')(?!\w)')
    return pattern.sub(' ', text)


def html_page_summary(body: str, boilerplate=None) -> str:
    """Distil an MPA page to its discriminating parts (chrome + boilerplate removed).

    `boilerplate` is a set of block hashes (see block_hash). Each part has its own
    character budget: a single tail truncation used to cut the page text -- the
    only part that says what the page is *about* -- before anything else.
    """
    boilerplate = boilerplate or ()
    view = _html_view(body)

    bits = []
    if view['title']:
        bits.append(f"page: {_truncate(view['title'], HTML_TITLE_CAP)}")
    headings = [t for h, t in view['headings'] if h not in boilerplate][:HTML_HEADING_CAP]
    if headings:
        bits.append(_truncate("headings: " + " / ".join(headings), HTML_HEADINGS_CHARS, 'html.headings'))
    if view['forms']:
        bits.append(_truncate(" ; ".join(view['forms']), HTML_FORMS_CHARS, 'html.forms'))
    if view['links']:
        bits.append(_truncate("links: " + ", ".join(view['links']), HTML_LINKS_CHARS, 'html.links'))
    if view['artifacts']:
        bits.append(_truncate("notes: " + " ; ".join(view['artifacts']), HTML_ARTIFACT_CHARS, 'html.notes'))

    lead = view['lead']
    if boilerplate:
        lead = _drop_blocks(lead, (t for h, t in view['blocks'].items() if h in boilerplate))
    if lead.strip():
        used = len(" | ".join(bits)) + 3
        budget = min(600, max(HTML_TEXT_LEAD_CAP, HTML_SUMMARY_CAP - used))
        bits.append(_truncate(lead, budget, 'html.lead'))
    return _truncate(" | ".join(bits), HTML_SUMMARY_CAP + 150, 'html.summary')


def distill_response(resp_class, body, resp_ct, redirect_location, boilerplate=None):
    """Route a response to the right distiller. Returns (distilled_str, schema_sig, schema_keys)."""
    if resp_class == 'api_structured':
        sig, summary, keys = structured_schema(body, resp_ct)
        return summary, sig, keys
    if resp_class == 'html_document':
        return html_page_summary(body, boilerplate), '', []
    if resp_class == 'spa_shell':
        summary = html_page_summary(body, boilerplate)
        return _truncate("SPA application shell" +
                         (" | " + summary if summary else ""), HTML_SUMMARY_CAP + 150), '', []
    if resp_class == 'static_asset':
        return static_asset_summary(body, resp_ct), '', []
    if resp_class == 'redirect':
        return f"redirect -> {redirect_location}".strip(), '', []
    if resp_class == 'empty':
        return 'empty body', '', []
    if resp_class in ('binary', 'undecodable'):
        return body, '', []
    return _truncate(body, TEXT_OTHER_CAP), '', []


def static_asset_summary(body: str, resp_ct: str) -> str:
    """Label a static asset; for JavaScript also surface what the code talks to.

    A bundle names the API routes the client calls and sometimes embeds
    credential-shaped assignments. Routes are kept, credential assignments are
    reduced to their *names* (the value stays in the stored exchange).
    """
    label = f"static asset {resp_ct or ''}".strip()
    ct = (resp_ct or '').lower()
    if not ('javascript' in ct or 'ecmascript' in ct or ct.endswith('/js')) or not body:
        return label
    scan_text = body[:STATIC_SCAN_CHARS]
    bits = [label]
    endpoints = _script_endpoints(scan_text, STATIC_ENDPOINT_CAP)
    if endpoints:
        bits.append("endpoints: " + ", ".join(endpoints))
    names = list(dict.fromkeys(m.group(1).lower()
                               for m in _CREDENTIAL_ASSIGN_RE.finditer(scan_text)))[:6]
    if names:
        bits.append("credential-like assignments: " + ", ".join(names))
    return _truncate(" | ".join(bits), 400)


# ---------------------------------------------------------------------------
# embed_text / summary formatters
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Retrieval vocabulary
# ---------------------------------------------------------------------------
# These expansions apply to embed_text ONLY. `page_content` and `summary` stay
# in compact operator shorthand: they are read by someone who already knows the
# vocabulary, whereas the embedding has to match the words a person actually
# types. The facts were always recorded -- they were just spelled in a form with
# no overlap with a natural-language query: `cors: *` is punctuation, and
# `sets: session(Path,HttpOnly)` never contains the word "cookie". On the
# benchmark query set, expanding them moved three unretrievable facets from
# ranks 7 / 71 / 46 to rank 1 (cosine distance -0.04 / -0.10 / -0.11), taking
# recall@8 from 0.648 to 0.878 and nDCG@8 from 0.621 to 0.824 with no query
# scoring below its previous value. Changing any of this needs a project
# rebuild; `store` re-embeds only the documents whose text actually moved.
HEADER_WORDS = {short: full for full, short in SECURITY_HEADERS.items()}

CORS_WORDS = {
    '*': 'wildcard, access-control-allow-origin * allows any origin',
    '* creds': 'wildcard with credentials, any origin plus '
               'access-control-allow-credentials',
    'null': 'null origin allowed',
    'null creds': 'null origin allowed with credentials',
    'matches-origin': 'reflects the request origin back in '
                      'access-control-allow-origin',
    'specific': 'one specific allowed origin',
}

ACCESS_CONTROL_WORDS = {
    'open-data': 'anonymous requests are served real data, reachable with no '
                 'credential, unauthenticated access allowed',
    'soft-auth-wall': 'anonymous requests get a login page or redirect instead '
                      'of a denial, soft authentication wall',
    'enforced': 'anonymous requests are denied with 401 or 403, authentication '
                'enforced',
}

# What the response actually delivered, from normalize._access_class.
ACCESS_CLASS_WORDS = {
    'data': 'real data was returned',
    'auth_wall': 'an authentication wall, login page or login redirect was '
                 'returned instead of data',
    'shell': 'an empty single-page-application shell was returned, not data',
    'denied': 'access was denied with 401 or 403',
    'redirect': 'a redirect that is not a login redirect',
    'empty': 'an empty response body',
    'static': 'a static asset',
    'other': 'a non-success response',
    'unknown': 'the response body could not be classified',
}

# A method name is a verb the searcher does not necessarily type. Only the
# mutating methods are expanded: GET is the majority of any capture, so glossing
# it adds the same tokens to most documents, which dilutes without
# discriminating. Measured on the benchmark set, including GET cost two queries
# more than the mutating verbs gained.
METHOD_WORDS = {
    'POST': 'creates, submits, sends new data',
    'PUT': 'replaces, updates an existing record in place',
    'PATCH': 'partially updates an existing record',
    'DELETE': 'removes, deletes a record',
    'OPTIONS': 'preflight, advertises allowed methods',
}

AUTH_MECHANISM_WORDS = {
    'cookie-session': 'session cookie',
    'bearer-jwt': 'bearer token, json web token in the authorization header',
    'bearer-opaque': 'opaque bearer token in the authorization header',
    'basic': 'http basic authentication',
    'api-key-header': 'api key header',
    'custom-header': 'custom authentication header',
    'none': 'no credential',
}


def header_words(names):
    """csp -> content-security-policy, so the header is searchable by name."""
    return [HEADER_WORDS.get(name, name) for name in names]


def auth_words(mechanisms):
    return [AUTH_MECHANISM_WORDS.get(m, m) for m in mechanisms]


def access_class_words(value):
    return ACCESS_CLASS_WORDS.get(value, value)


def method_words(method):
    return METHOD_WORDS.get((method or '').upper(), '')


def cookie_words(entries):
    """'session(Path,HttpOnly)' -> 'session cookie (path, httponly)'."""
    out = []
    for entry in entries:
        name, _, flags = str(entry).partition('(')
        flags = flags.rstrip(')').replace(',', ', ').strip().lower()
        out.append(f"{name} cookie" + (f" ({flags})" if flags else ''))
    return out


def cors_words(value, credentials=False):
    full = value + (' creds' if credentials else '')
    return CORS_WORDS.get(full, full)


def _fit(parts, cap=EMBED_TEXT_CAP, sep=" | ", floor=80):
    """Join (text, soft_cap) parts into at most `cap` characters.

    Each part is first held to its own soft cap. If the whole is still too long,
    the longest part gives way, never below `floor`. A single tail cut instead
    removes whichever clause happens to come last -- for behavior text that was
    the security posture -- no matter how little the long parts above it matter.
    """
    texts = [_truncate(t, c, 'embed_part') for t, c in parts if t and t.strip()]

    def total():
        return sum(len(t) for t in texts) + len(sep) * max(len(texts) - 1, 0)

    while texts and total() > cap:
        i = max(range(len(texts)), key=lambda k: len(texts[k]))
        target = max(floor, len(texts[i]) - (total() - cap))
        if target >= len(texts[i]):
            break
        LEDGER['truncated.embed_shrunk'] += 1
        texts[i] = _truncate(texts[i], target)
    return _truncate(sep.join(texts), cap, 'embed_text')


def _security_clause(reqf, respf):
    sec = []
    if reqf.get('cookie_names'):
        sec.append("sends cookies: " + ", ".join(
            f"{name} cookie" for name in reqf['cookie_names'][:8]))
    if respf.get('set_cookies'):
        sec.append("sets cookies with the set-cookie response header: "
                   + ", ".join(cookie_words(respf['set_cookies'][:6])))
    if respf.get('security_headers_missing'):
        sec.append("missing security headers: "
                   + ", ".join(header_words(respf['security_headers_missing'])))
    if respf.get('cors'):
        sec.append("cors: " + cors_words(respf['cors'],
                                         respf.get('cors_credentials')))
    if reqf.get('origin_cross_site'):
        sec.append("cross-site request origin")
    if reqf.get('jwt'):
        sec.append("jwt: " + reqf['jwt'])
    if respf.get('tech'):
        sec.append("technology: " + ", ".join(respf['tech']))
    return sec


def behavior_embed_text(a) -> str:
    reqf, respf = a['req_features'], a['resp_features']
    parts = [(f"{a['method']} {a['endpoint_template']}", 200)]
    if a['param_names']:
        parts.append(("params: " + ", ".join(a['param_names']), 240))
    if a['req_content_type']:
        parts.append(("req: " + a['req_content_type'], 60))
    if a.get('req_schema_keys'):
        parts.append(("request keys: " + ", ".join(a['req_schema_keys'][:20]), 240))
    if a.get('req_semantic'):
        parts.append(("request values: " + ", ".join(a['req_semantic'][:8]), 160))
    if a.get('graphql_operation'):
        parts.append(("graphql: " + a['graphql_operation'], 160))
    parts.append((f"status: {a['status_code']} {status_class(a['status_code'])}".strip(), 40))
    if a['resp_distilled']:
        parts.append(("resp: " + a['resp_distilled'], 700))
    parts.append(("auth: " + (reqf.get('auth_role') or 'anonymous'), 80))
    security = _security_clause(reqf, respf)
    if security:
        parts.append((" | ".join(security), 450))
    return _fit(parts)


def behavior_segment_texts(a):
    """Protocol-aware child representations used by hybrid retrieval."""
    reqf, respf = a['req_features'], a['resp_features']
    route = [f"request route {a['method']} {path_words(a['endpoint_template'])}"
             + (f" ({method_words(a['method'])})" if method_words(a['method']) else ''),
             a['endpoint_template'], f"host: {a['host']}"]
    if a['param_names']:
        route.append("parameters: " + ", ".join(a['param_names']))
    if a['req_content_type']:
        route.append("request content: " + a['req_content_type'])
    if a.get('req_schema_keys'):
        route.append("request keys: " + ", ".join(a['req_schema_keys'][:20]))
    if a.get('req_semantic'):
        route.append("request values: " + ", ".join(a['req_semantic'][:8]))
    if a.get('graphql_operation'):
        route.append("graphql: " + a['graphql_operation'])

    response = [f"response for {a['method']} {a['endpoint_template']}",
                f"status: {a['status_code']} {status_class(a['status_code'])}",
                f"type: {a['resp_content_type'] or a['resp_class']}"]
    if a['resp_distilled']:
        response.append(a['resp_distilled'])
    if a.get('access_class'):
        response.append("access outcome: " + access_class_words(a['access_class']))

    security = [f"access and session behavior on {a['method']} {a['endpoint_template']}",
                "auth role: " + (reqf.get('auth_role') or 'anonymous'),
                "auth mechanism: "
                + ", ".join(auth_words([reqf.get('auth_mechanism') or 'none']))]
    security.extend(_security_clause(reqf, respf))
    if a.get('anon_matches_auth'):
        security.append("anonymous response matches authenticated response")
    return {
        'route': _truncate(" | ".join(route), EMBED_TEXT_CAP, 'embed_text'),
        'response': _truncate(" | ".join(response), EMBED_TEXT_CAP, 'embed_text'),
        'security': _truncate(" | ".join(security), EMBED_TEXT_CAP, 'embed_text'),
    }


def behavior_summary(a) -> str:
    reqf = a['req_features']
    ptop = ",".join(a['param_names'][:3])
    s = (f"{a['method']} {a['endpoint_template']} \u2192 {a['status_code']} · "
         f"{a['param_count']}p" + (f" [{ptop}]" if ptop else "") +
         (f" · {a['resp_content_type']}" if a['resp_content_type'] else "") +
         f" · {reqf.get('auth_role') or 'anonymous'}")
    return _truncate(s, SUMMARY_CAP)


def graphql_operation_names(operations):
    """`query:Name:fields` -> `query Name`, de-duplicated."""
    names = []
    for op in operations or ():
        kind, _, rest = str(op).partition(':')
        name = rest.partition(':')[0]
        entry = f"{kind} {name}".strip()
        if entry and entry not in names:
            names.append(entry)
    return names


def structure_embed_text(node) -> str:
    parts = [f"{node['node_kind']}: {node['method']} {path_words(node['endpoint_template'])}".strip()]
    parts.append(node['endpoint_template'])
    if node.get('graphql_operations'):
        parts.append("graphql operations: " + ", ".join(
            graphql_operation_names(node['graphql_operations'])[:12]))
    if node['param_names']:
        parts.append("params: " + ", ".join(node['param_names']))
    if node.get('produces'):
        parts.append("produces: " + ", ".join(node['produces']))
    if node.get('resp_schema_keys'):
        parts.append("response fields: " + ", ".join(node['resp_schema_keys'][:20]))
    if node.get('req_schema_keys'):
        parts.append("request fields: " + ", ".join(node['req_schema_keys'][:20]))
    if node.get('status_codes'):
        parts.append("statuses: " + ", ".join(str(s) for s in node['status_codes']))
    if node.get('auth_mechanisms'):
        parts.append("auth: " + ", ".join(auth_words(node['auth_mechanisms'])))
    if node.get('cookies_set'):
        parts.append("sets cookies: " + ", ".join(
            f"{name} cookie" for name in node['cookies_set'][:6]))
    if node.get('security_headers_missing'):
        parts.append("missing security headers: "
                     + ", ".join(header_words(node['security_headers_missing'])))
    if node.get('cors'):
        parts.append("cors: " + cors_words(node['cors']))
    if node.get('tech'):
        parts.append("technology: " + ", ".join(node['tech'][:TECH_CAP]))
    if node.get('access_control') and node['access_control'] != 'unknown':
        parts.append("access: " + ACCESS_CONTROL_WORDS[node['access_control']])
    return _fit([(p, 300) for p in parts])


def structure_segment_texts(node):
    identity = [f"{node['node_kind']} route {node['method']} "
                f"{path_words(node['endpoint_template'])}"
                + (f" ({method_words(node['method'])})"
                   if method_words(node['method']) else ''),
                node['endpoint_template'], f"host: {node['host']}"]
    if node['param_names']:
        identity.append("parameters: " + ", ".join(node['param_names']))
    if node.get('produces'):
        identity.append("produces: " + ", ".join(node['produces']))
    if node.get('resp_schema_keys'):
        identity.append("response fields: " + ", ".join(node['resp_schema_keys'][:20]))
    if node.get('req_schema_keys'):
        identity.append("request fields: " + ", ".join(node['req_schema_keys'][:20]))
    if node.get('graphql_operations'):
        identity.append("graphql operations: " + ", ".join(
            graphql_operation_names(node['graphql_operations'])[:12]))

    posture = [f"access posture for {node['method']} {node['endpoint_template']}"]
    if node.get('status_codes'):
        posture.append("statuses: " + ", ".join(str(s) for s in node['status_codes']))
    if node.get('access_control') in ACCESS_CONTROL_WORDS:
        posture.append("access: " + ACCESS_CONTROL_WORDS[node['access_control']])
    if node.get('auth_mechanisms'):
        posture.append("authentication: "
                       + ", ".join(auth_words(node['auth_mechanisms'])))
    if node.get('cookies_set'):
        posture.append("sets cookies with the set-cookie response header: "
                       + ", ".join(f"{name} cookie" for name in node['cookies_set']))
    if node.get('security_headers_missing'):
        posture.append("missing security headers: "
                       + ", ".join(header_words(node['security_headers_missing'])))
    if node.get('cors'):
        posture.append("cors: " + cors_words(node['cors']))
    if node.get('tech'):
        posture.append("technology: " + ", ".join(node['tech'][:TECH_CAP]))
    return {
        'identity': _truncate(" | ".join(identity), EMBED_TEXT_CAP, 'embed_text'),
        'posture': _truncate(" | ".join(posture), EMBED_TEXT_CAP, 'embed_text'),
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
        parts.append("mechanisms: " + ", ".join(auth_words(model['auth_mechanisms'])))
    if model.get('cookies_set_map'):
        setmap = ", ".join(f"{c} cookie@{','.join(sorted(ep)[:3])}"
                           for c, ep in list(model['cookies_set_map'].items())[:8])
        parts.append("sets session cookies with the set-cookie header: " + setmap)
    if model.get('cookies_sent_map'):
        sentmap = ", ".join(f"{c} cookie@[{','.join(sorted(ep)[:4])}]"
                            for c, ep in list(model['cookies_sent_map'].items())[:8])
        parts.append("consumes cookies: " + sentmap)
    if model.get('token'):
        parts.append("token: " + model['token'])
    if model.get('security_headers_missing'):
        parts.append("posture: missing security headers "
                     + ", ".join(header_words(model['security_headers_missing'])))
    if model.get('cors'):
        parts.append("cors: " + cors_words(model['cors']))
    return _truncate(" | ".join(parts), EMBED_TEXT_CAP, 'embed_text')


def auth_model_summary(host, model) -> str:
    s = (f"auth model {host} · mechanisms: "
         f"{','.join(model.get('auth_mechanisms', []) or ['none'])} · "
         f"{len(model.get('cookies_set_map', {}))} cookies set")
    return _truncate(s, SUMMARY_CAP)


def likely_identifier_field(keys) -> str:
    """Pick the field most likely to be this entity's primary identifier."""
    names = [k.rsplit('.', 1)[-1] for k in keys]
    for k in names:
        if k.lower() == 'id':
            return 'id'
    for k in names:
        if _IDENTIFIER_KEY_RE.search(k):
            return k
    return ''


def entity_embed_text(entity) -> str:
    parts = [f"entity {entity.get('likely_identifier_field') or 'object'}"]
    if entity.get('keys'):
        parts.append("fields: " + ", ".join(entity['keys'][:20]))
    if entity.get('produced_by'):
        eps = ", ".join(f"{m} {t}" for m, t in entity['produced_by'][:6])
        parts.append("produced by: " + eps)
    if entity.get('consumed_by'):
        eps = ", ".join(f"{m} {t}" for m, t in entity['consumed_by'][:6])
        parts.append("consumed by: " + eps)
    return _truncate(" | ".join(parts), EMBED_TEXT_CAP, 'embed_text')


def entity_summary(entity) -> str:
    n_eps = len(set(entity.get('produced_by', [])) | set(entity.get('consumed_by', [])))
    s = (f"entity ({entity.get('likely_identifier_field') or 'object'}) · "
         f"{len(entity.get('keys', []))} fields · seen at {n_eps} endpoint(s)")
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
    return _truncate(" | ".join(parts), EMBED_TEXT_CAP, 'embed_text')


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
    credential presence and access outcome so security-relevant variations (e.g. a
    data response vs a login-wall response to the same endpoint) never merge.

    It does NOT include the response schema or body: different shapes under one
    key are told apart by behavior_variant_key and emitted as variants."""
    return (a.get('scheme', ''), a['host'], a.get('port', 0), a['method'],
            a['endpoint_template'], a['status_code'],
            a['req_features']['auth_role'], a.get('access_class', ''),
            bool(a['req_features'].get('credential_present')))


def behavior_variant_key(a):
    """Identity for distinct exchanges retained beneath a canonical behavior."""
    reqf, respf = a.get('req_features', {}), a.get('resp_features', {})
    security = (reqf.get('auth_mechanism', ''), tuple(reqf.get('cookie_names', [])),
                tuple(reqf.get('req_features_csv', [])), reqf.get('jwt', ''),
                tuple(respf.get('set_cookies', [])), tuple(respf.get('cookie_issues', [])),
                tuple(respf.get('security_headers_missing', [])), respf.get('cors', ''),
                bool(respf.get('cors_credentials')), respf.get('redirect_location', ''))
    return (tuple(a.get('param_names', [])), a.get('req_content_type', ''),
            a.get('req_schema_sig', ''), a.get('request_variant_sig', ''),
            a.get('graphql_operation', ''),
            a.get('resp_class', ''), a.get('resp_content_type', ''),
            a.get('resp_schema_sig', ''), a.get('response_variant_sig', ''), security)


def behavior_id(a) -> str:
    return md5("|".join(str(x) for x in behavior_collapse_key(a)))
