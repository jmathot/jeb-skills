"""
JavaScript facts: turn a bundle into graph facts instead of text chunks.

Minified code embeds poorly, so a bundle is never cut into text chunks. A small
hand-written lexer finds the string literals across the whole body (up to
JS_SCAN_CHARS), each literal is classified, and what survives is a compact fact
record: library fingerprints, endpoints (with the HTTP method when a call site
shows it), external origins, credential-shaped literals, config keys, the source
map URL and, where module names exist, the facts per module.

No JS parser dependency. Everything is deterministic and bounded; what a cap cuts
is counted in `distill.LEDGER`.
"""
import json
import re
from functools import lru_cache
from urllib.parse import urlparse

JS_SCAN_CHARS = 8_000_000      # bytes of a bundle scanned for literals
JS_LITERAL_CAP = 60_000        # string literals examined per bundle
MAX_ENDPOINTS = 400            # distinct (method, template) kept per bundle
MAX_ORIGINS = 40
MAX_SECRETS = 20
MAX_LIBS = 12
MAX_CONFIG_KEYS = 40
MAX_MODULES_PER_BUNDLE = 20    # modules that become Section nodes
LOOKBEHIND = 80
LOOKAHEAD = 160

# One alternation, tried left to right at each position: comments and regex
# literals first so a quote inside them never opens a string. A regex literal is
# only recognised after a character that cannot end an expression, which keeps
# division (`a / b / c`) from being misread.
_TOKEN = re.compile(r'''
    (?P<lc>//[^\n]*)
  | (?P<bc>/\*.*?\*/)
  | (?P<re>(?<=[=(,:;!&|?{}\[+*%<>~^-])\s*/(?![/*])(?:[^/\\\n\[]|\\.|\[(?:[^\]\\\n]|\\.)*\])+/[dgimsuyv]*)
  | (?P<sq>'(?:[^'\\\n]|\\.)*')
  | (?P<dq>"(?:[^"\\\n]|\\.)*")
  | (?P<tpl>`(?:[^`\\]|\\.)*`)
''', re.S | re.X)

_ESCAPE = re.compile(r'\\(?:u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|(.))', re.S)
_SIMPLE = {'n': '\n', 't': '\t', 'r': '\r', 'b': '\b', 'f': '\f', 'v': '\v', '0': '\0'}
_TEMPLATE_EXPR = re.compile(r'\$\{[^}]*\}')

_ENDPOINT_PATH = re.compile(r'^/[A-Za-z0-9_\-./{}:$@%~]*[A-Za-z][A-Za-z0-9_\-./{}:$@%~]*(?:\?[A-Za-z0-9_\-=&%.{}$@:,]*)?$')
_ABSOLUTE_URL = re.compile(r'^https?://[A-Za-z0-9.\-]+(?::\d+)?(?:/[^\s"\'<>]*)?$')
_ASSET_SUFFIXES = ('.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2',
                   '.ttf', '.eot', '.map', '.webp', '.html', '.htm', '.js', '.mjs', '.json',
                   '.mp3', '.mp4', '.webm', '.wasm', '.txt', '.xml', '.pdf')
_GRAPHQL = re.compile(r'^\s*(?:query|mutation|subscription)\b\s*([A-Za-z_]\w*)?\s*[({]')

_KEY_SHAPES = (
    ('aws-key', re.compile(r'^AKIA[0-9A-Z]{16}$')),
    ('google-api-key', re.compile(r'^AIza[0-9A-Za-z_\-]{35}$')),
    ('stripe-live-key', re.compile(r'^sk_live_[0-9a-zA-Z]{24,}$')),
    ('github-token', re.compile(r'^gh[pousr]_[0-9A-Za-z]{36,}$')),
    ('slack-token', re.compile(r'^xox[abprs]-[0-9A-Za-z\-]{10,}$')),
    ('jwt', re.compile(r'^eyJ[0-9A-Za-z_\-]{8,}\.eyJ[0-9A-Za-z_\-]{8,}\.[0-9A-Za-z_\-]*$')),
)
_ASSIGN = re.compile(
    r'''["']?(api[_-]?key|client[_-]?secret|secret|access[_-]?token|auth[_-]?token|password|passwd|token)["']?\s*[:=]\s*$''',
    re.I)
_METHOD_BEFORE = re.compile(
    r'(?:\.(get|post|put|delete|patch|head|options)|\$\.(get|post)|fetch)\s*\(\s*(?:[A-Za-z_$][\w$.]*\s*\+\s*)?$', re.I)
_METHOD_OPTION = re.compile(r'''method\s*:\s*["'](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)["']''', re.I)
_BANNER = re.compile(
    r'/\*!?\s*(?:@license\s+)?([A-Za-z][\w.\-]{1,40}?)\s+(?:JavaScript\s+Library\s+)?v?(\d+\.\d+(?:\.\d+)?(?:[-+.][\w.\-]*)?)', re.I)
_SOURCEMAP_URL = re.compile(r'//[#@]\s*sourceMappingURL=([^\s]+)')
_WEBPACK_MODULE = re.compile(
    r'''["'](\./[^"'\n]+?\.(?:js|jsx|ts|tsx|vue|mjs))["']\s*:\s*(?:function|\(|async|/\*)''')
_CONFIG_ASSIGN = re.compile(
    r'(?:window|self|globalThis)\.(__[A-Z0-9_]+__|[A-Za-z_]*(?:[Cc]onfig|CONFIG|ENV|[Ee]nv)[A-Za-z_]*)\s*=\s*\{([^}]{0,3000})\}')
_CONFIG_KEY = re.compile(r'''["']?([A-Za-z_][\w]{1,40})["']?\s*:''')
_PROCESS_ENV = re.compile(r'process\.env\.([A-Z][A-Z0-9_]{2,40})')


def _unescape(text):
    def repl(m):
        if m.group(1):
            return chr(int(m.group(1), 16))
        if m.group(2):
            return chr(int(m.group(2), 16))
        return _SIMPLE.get(m.group(3), m.group(3))
    return _ESCAPE.sub(repl, text) if '\\' in text else text


def lex_strings(body, limit=JS_SCAN_CHARS, cap=JS_LITERAL_CAP):
    """-> (literals, stats). literals: [(start, end, text)] with escapes resolved and
    template expressions replaced by `{param}`. Comments and regex literals are
    skipped. stats: {'scanned', 'skipped_chars', 'literals', 'skipped_literals'}."""
    text = body[:limit]
    out, skipped = [], 0
    for m in _TOKEN.finditer(text):
        kind = m.lastgroup
        if kind not in ('sq', 'dq', 'tpl'):
            continue
        if len(out) >= cap:
            skipped += 1
            continue
        raw = m.group()[1:-1]
        if kind == 'tpl':
            raw = _TEMPLATE_EXPR.sub('{param}', raw)
        out.append((m.start(), m.end(), _unescape(raw)))
    return out, {'scanned': len(text), 'skipped_chars': max(0, len(body) - len(text)),
                 'literals': len(out), 'skipped_literals': skipped}


def library_banners(body):
    """`/*! jQuery v3.6.0 */`-style banners -> [(name, version)]."""
    seen = []
    for m in _BANNER.finditer(body[:JS_SCAN_CHARS]):
        entry = (m.group(1).lower().rstrip('.'), m.group(2).rstrip('.-'))
        if entry not in seen:
            seen.append(entry)
        if len(seen) >= MAX_LIBS:
            break
    return seen


def webpack_modules(body):
    """Named modules of a development bundle -> [(start, path)], by position."""
    found = []
    for m in _WEBPACK_MODULE.finditer(body[:JS_SCAN_CHARS]):
        found.append((m.start(), m.group(1)))
    return found


def key_shape(value):
    for name, pattern in _KEY_SHAPES:
        if pattern.match(value):
            return name
    return ''


def classify(literal, lookbehind='', lookahead='', page_origin=''):
    """-> (kind, payload) or None.

    kind: 'endpoint' (method, template-ready path), 'origin' (external origin),
    'graphql' (operation name), 'secret' (name, shape).
    """
    value = literal.strip()
    if len(value) < 3 or len(value) > 2000:
        return None
    shape = key_shape(value)
    if shape:
        return 'secret', (_assign_name(lookbehind) or shape, shape)
    name = _assign_name(lookbehind)
    if name and len(value) >= 8 and not re.search(r'[\s/]', value):
        return 'secret', (name, 'credential-assignment')
    gql = _GRAPHQL.match(value)
    if gql:
        return 'graphql', gql.group(1) or 'anonymous'
    if _ABSOLUTE_URL.match(value):
        parsed = urlparse(value)
        origin = f'{parsed.scheme}://{parsed.netloc}'
        path = parsed.path or '/'
        if page_origin and origin == page_origin and _usable_path(path):
            return 'endpoint', (_method(lookbehind, lookahead), path)
        return 'origin', origin
    if value.startswith('/') and not value.startswith('//') and _ENDPOINT_PATH.match(value) \
            and _usable_path(value.split('?', 1)[0]):
        return 'endpoint', (_method(lookbehind, lookahead), value)
    return None


def _assign_name(lookbehind):
    m = _ASSIGN.search(lookbehind[-LOOKBEHIND:])
    return m.group(1).lower() if m else ''


def _usable_path(path):
    return len(path) >= 3 and not path.lower().endswith(_ASSET_SUFFIXES) and '//' not in path


def _method(lookbehind, lookahead):
    m = _METHOD_BEFORE.search(lookbehind[-LOOKBEHIND:])
    if m:
        verb = (m.group(1) or m.group(2) or '').upper()
        if verb:
            return verb
        option = _METHOD_OPTION.search(lookahead)
        return option.group(1).upper() if option else 'GET'
    option = _METHOD_OPTION.search(lookahead)
    return option.group(1).upper() if option else 'ANY'


def sourcemap_facts(map_json, page_origin=''):
    """Per original source file facts from a captured source map."""
    try:
        data = json.loads(map_json) if isinstance(map_json, (str, bytes)) else map_json
    except (ValueError, TypeError):
        return {}
    sources = data.get('sources') or []
    contents = data.get('sourcesContent') or []
    modules = {}
    for name, content in zip(sources, contents):
        if not content:
            continue
        facts = _extract(content, page_origin)
        if facts['endpoints'] or facts['secrets']:
            modules[name] = facts
    return modules


def _extract(body, page_origin='', modules=None):
    literals, stats = lex_strings(body)
    starts = [pos for pos, _ in modules] if modules else []
    endpoints, origins, secrets, graphql = {}, [], {}, []
    for start, end, text in literals:
        if len(text) < 3:
            continue
        hit = classify(text, body[max(0, start - LOOKBEHIND):start], body[end:end + LOOKAHEAD], page_origin)
        if hit is None:
            continue
        kind, payload = hit
        module = ''
        if modules:
            import bisect
            index = bisect.bisect_right(starts, start) - 1
            module = modules[index][1] if index >= 0 else ''
        if kind == 'endpoint':
            method, path = payload
            endpoints.setdefault((method, path.split('?', 1)[0]), module)
        elif kind == 'origin':
            if payload not in origins:
                origins.append(payload)
        elif kind == 'graphql':
            if payload not in graphql:
                graphql.append(payload)
        elif kind == 'secret':
            name, shape = payload
            secrets.setdefault((name, shape, text), module)
    return {'endpoints': [(m, p, mod) for (m, p), mod in endpoints.items()],
            'origins': origins, 'secrets': [(n, s, v, mod) for (n, s, v), mod in secrets.items()],
            'graphql': graphql, 'stats': stats}


def config_keys(body):
    keys = []
    for m in _CONFIG_ASSIGN.finditer(body[:JS_SCAN_CHARS]):
        for key in _CONFIG_KEY.findall(m.group(2)):
            if key not in keys:
                keys.append(key)
    for name in _PROCESS_ENV.findall(body[:JS_SCAN_CHARS]):
        if name not in keys:
            keys.append(name)
    return keys[:MAX_CONFIG_KEYS]


@lru_cache(maxsize=2)
def js_facts(body, page_origin=''):
    """-> {libs, endpoints[(method, path, module)], origins, secrets[(name, shape, value)],
    graphql, config_keys, sourcemap_url, modules{module: {endpoints, secrets}}, stats}.

    Secret *values* are returned for the identifier index only; callers must not
    put them in node text or persisted feature records (use `compact`)."""
    modules = webpack_modules(body)
    facts = _extract(body, page_origin, modules or None)
    tail = body[-600:]
    sm = _SOURCEMAP_URL.search(tail)
    named = {}
    if modules:
        for method, path, module in facts['endpoints']:
            named.setdefault(module, {'endpoints': 0, 'secrets': 0})['endpoints'] += 1
        for name, shape, value, module in facts['secrets']:
            named.setdefault(module, {'endpoints': 0, 'secrets': 0})['secrets'] += 1
    return {
        'libs': library_banners(body),
        'endpoints': facts['endpoints'][:MAX_ENDPOINTS],
        'endpoints_total': len(facts['endpoints']),
        'origins': facts['origins'][:MAX_ORIGINS],
        'secrets': [(n, s, v) for n, s, v, _ in facts['secrets']][:MAX_SECRETS],
        'graphql': facts['graphql'][:20],
        'config_keys': config_keys(body),
        'sourcemap_url': sm.group(1) if sm else '',
        'modules': {k: v for k, v in named.items() if k},
        'stats': facts['stats'],
    }


def compact(facts):
    """The persistable form: no secret values, bounded."""
    return {
        'libs': facts['libs'],
        'endpoints': [list(e) for e in facts['endpoints']],
        'endpoints_total': facts['endpoints_total'],
        'origins': facts['origins'],
        'secrets': [[n, s] for n, s, _ in facts['secrets']],
        'graphql': facts['graphql'],
        'config_keys': facts['config_keys'],
        'sourcemap_url': facts['sourcemap_url'],
        'modules': dict(list(facts['modules'].items())[:MAX_MODULES_PER_BUNDLE]),
    }


def secret_values(body):
    """Credential-shaped literal values of a bundle, for the identifier index."""
    return sorted({v for _, _, v in js_facts(body)['secrets']})


def summary(facts, label, cap=400):
    """One-line description for node text: counts and top endpoints, never values."""
    bits = [label]
    if facts['libs']:
        bits.append('libraries: ' + ', '.join(f'{n} {v}' for n, v in facts['libs'][:6]))
    if facts['endpoints']:
        shown = ', '.join((f'{m} ' if m != 'ANY' else '') + p for m, p, _ in facts['endpoints'][:12])
        bits.append(f"endpoints ({facts['endpoints_total']}): {shown}")
    if facts['origins']:
        bits.append('external origins: ' + ', '.join(facts['origins'][:4]))
    if facts['secrets']:
        bits.append('credential-like: ' + ', '.join(sorted({f'{n} <{s}>' for n, s, _ in facts['secrets']})[:6]))
    if facts['sourcemap_url']:
        bits.append('source map: ' + facts['sourcemap_url'][:80])
    text = ' | '.join(bits)
    return text if len(text) <= cap else text[:cap - 1] + '…'
