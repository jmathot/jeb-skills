"""Generate the benchmark artifact: one Burp XML export plus its ground-truth labels.

The capture is *authored*, so every expected fact is known without running the
engine under test. Routes, response/request body shapes, and anonymous-access
outcomes are declared below; the manifest is derived from those declarations.

Single origin by design: a J.E.B. project tracks ONE engagement, ONE host.

    python3 tests/make_capture.py [--out-dir tests]

Writes capture.xml and ground_truth.json side by side.
"""
import argparse
import base64
import hashlib
import html
import json
import os

SCHEME, HOST, PORT = 'https', 'app.example', 443
BASE = f'{SCHEME}://{HOST}'
SESSION = 'session=sid-9f8e7d6c5b4a'

# --- authored body shapes -------------------------------------------------
# A schema signature is md5 over the sorted unique JSON key paths, so a shape
# IS its sorted field list. Jaccard overlap between two shapes is therefore
# computable here, which is what makes the `related` labels exact.
SHAPES = {
    'order':          ['customer_id', 'id', 'status', 'total'],
    'order_note':     ['customer_id', 'id', 'note', 'status', 'total'],
    'order_tag':      ['customer_id', 'id', 'status', 'tag', 'total'],
    'customer':       ['email', 'id', 'name'],
    'product':        ['id', 'price', 'sku'],
    'invoice_wide':   ['amount', 'created_at', 'currency', 'customer_id',
                       'due_at', 'id', 'number', 'status', 'total'],
    'address':        ['city', 'country', 'id', 'line1', 'postal_code'],
    'address_region': ['city', 'country', 'id', 'line1', 'postal_code', 'region'],
    'rates':          ['currency', 'rate'],
    'session_info':   ['authenticated', 'expires_at', 'user_id'],
    'quoted_note':    ['author', 'id', 'note'],
}

# The identifier value deliberately shared between an order and a customer, so
# `jeb query command=identifier` has a real cross-endpoint correlation to find.
LINKED_ID = 4711

FIELD_VALUES = {
    'id': lambda i: i,
    'customer_id': lambda i: LINKED_ID,
    'user_id': lambda i: LINKED_ID,
    'status': lambda i: ['open', 'shipped', 'cancelled'][i % 3],
    'total': lambda i: f'{10 + i}.50',
    'amount': lambda i: f'{20 + i}.00',
    'note': lambda i: f'handled by desk {i % 4}',
    'tag': lambda i: ['priority', 'backorder', 'gift'][i % 3],
    'name': lambda i: f'Customer {i}',
    'email': lambda i: f'user{i}@example.com',
    'price': lambda i: f'{5 + i}.99',
    'sku': lambda i: f'SKU-{1000 + i}',
    'currency': lambda i: 'USD',
    'rate': lambda i: 1.0 + i / 100,
    'number': lambda i: f'INV-{2000 + i}',
    'created_at': lambda i: '2026-01-02T10:00:00Z',
    'due_at': lambda i: '2026-02-01T10:00:00Z',
    'expires_at': lambda i: '2026-01-02T12:00:00Z',
    'authenticated': lambda i: True,
    'city': lambda i: 'Springfield',
    'country': lambda i: 'US',
    'line1': lambda i: f'{100 + i} Main Street',
    'postal_code': lambda i: '49007',
    'region': lambda i: 'MI',
    'author': lambda i: 'qa',
}


def body_for(shape, i):
    """Render a shape as a JSON object. Key order is irrelevant to the signature."""
    return json.dumps({f: FIELD_VALUES[f](i) for f in SHAPES[shape]})


# --- HTML -----------------------------------------------------------------
NAV = "".join(f'<li><a href="/s/{i}">Section {i}</a></li>' for i in range(25))
FOOT = ('<footer><nav><a href="/tos">Terms</a><a href="/priv">Privacy</a></nav>'
        '<p>(c) Example Corp</p></footer>')


def page(title, main):
    return (f'<!doctype html><html><head><title>{title}</title>'
            f'<link rel=stylesheet href=/static/app.css></head><body>'
            f'<header><nav><ul>{NAV}</ul></nav></header>'
            f'<main>{main}</main>{FOOT}</body></html>')


def table(n, label):
    rows = "".join(f'<tr><td>{label} {i}</td><td>Customer {i}</td>'
                   f'<td><a href="/orders/{1000 + i}">view</a></td></tr>'
                   for i in range(n))
    return (f'<table><thead><tr><th>Ref</th><th>Who</th><th></th></tr></thead>'
            f'<tbody>{rows}</tbody></table>')


LOGIN_PAGE = page('Sign in', '<h1>Sign in</h1><form action="/login" method="post">'
                  '<label>Email<input type="email" name="email"></label>'
                  '<label>Password<input type="password" name="password"></label>'
                  '<input type="hidden" name="csrf" value="tok-abc123">'
                  '<button>Log in</button></form>')

# (path, title, table rows, table label, anon outcome)
HTML_PAGES = [
    ('/dashboard', 'Dashboard', 120, 'Order', None),
    ('/orders', 'Orders', 300, 'Order', 'data'),
    ('/customers', 'Customers', 200, 'Customer', 'denied'),
    ('/invoices', 'Invoices', 180, 'Invoice', None),
    ('/products', 'Products', 160, 'Product', None),
    ('/addresses', 'Addresses', 90, 'Address', None),
    ('/reports', 'Reports', 150, 'Report', 'wall'),
    ('/audit', 'Audit log', 140, 'Event', 'denied'),
    ('/settings', 'Settings', 0, '', None),
    ('/profile', 'Profile', 0, '', None),
]
PUBLIC_PAGES = ['/tos', '/priv', '/about', '/help', '/faq', '/contact']

# --- API routes -----------------------------------------------------------
# anon: None (never requested anonymously), 'data' (200 + real body -> open-data),
# 'wall' (302 to /login -> soft-auth-wall), 'denied' (403 -> enforced).
API_ROUTES = [
    # method, path template (%d -> a numeric id), response shape, request shape, items, anon
    ('GET',   '/api/orders/%d',                  'order',          None,             6, 'data'),
    ('POST',  '/api/orders',                     'order',          'order',          3, None),
    ('GET',   '/api/orders/%d/detail',           'order_note',     None,             4, 'wall'),
    ('PUT',   '/api/orders/%d',                  'order_note',     'order',          3, None),
    ('GET',   '/api/orders/%d/tags',             'order_tag',      None,             3, None),
    ('PATCH', '/api/orders/%d',                  'order_tag',      'order_tag',      2, None),
    ('GET',   '/api/customers/%d',               'customer',       None,             5, 'denied'),
    ('GET',   '/api/customers/%d/profile',       'customer',       None,             3, None),
    ('GET',   '/api/products/%d',                'product',        None,             5, 'data'),
    ('POST',  '/api/products',                   'product',        'product',        2, None),
    ('GET',   '/api/invoices/%d',                'invoice_wide',   None,             4, 'wall'),
    ('PUT',   '/api/invoices/%d',                'invoice_wide',   'invoice_wide',   2, None),
    ('GET',   '/api/customers/%d/address',       'address',        None,             3, None),
    ('POST',  '/api/customers/%d/address',       'address',        'address',        2, None),
    ('GET',   '/api/addresses/%d',               'address_region', None,             3, 'denied'),
    ('PUT',   '/api/addresses/%d',               'address_region', 'address_region', 2, None),
    ('GET',   '/api/public/rates',               'rates',          None,             2, 'data'),
    ('GET',   '/api/session',                    'session_info',   None,             2, 'wall'),
    ('GET',   '/api/notes/%d',                   'quoted_note',    None,             2, None),
]

# Single-route endpoints whose shapes must NOT be promoted to entities, and
# which give the route map realistic breadth.
MISC_TOPICS = ['shipments', 'refunds', 'payouts', 'carriers', 'warehouses',
               'returns', 'coupons', 'taxes', 'ledgers', 'batches',
               'webhooks', 'exports', 'imports', 'alerts', 'quotas',
               'regions', 'carts', 'wishlists', 'reviews', 'ratings',
               'tickets', 'messages', 'templates', 'schedules', 'jobs',
               'devices', 'tokens', 'scopes', 'policies', 'consents',
               'segments', 'campaigns', 'discounts', 'bundles', 'kits',
               'vendors', 'contracts', 'terms', 'renewals', 'credits']
MISC_ITEMS = 4

NEEDLE_SQL = 'java.sql.SQLSyntaxErrorException: unexpected token near "\'"'
NEEDLE_QUOTED = 'he said "hello" loudly'
# As it appears in the raw HTTP body once json.dumps has escaped it. The
# stored Chroma document escapes it a second time, so this string is present
# in the decoded text and ABSENT from the stored document -- the false
# negative that rules out a where_document prefilter in source_evidence.
NEEDLE_QUOTED_RAW = 'he said \\"hello\\" loudly'


# --- HTTP message construction -------------------------------------------
def request_text(method, path, authed, body='', ctype='application/json'):
    lines = [f'{method} {path} HTTP/1.1', f'Host: {HOST}',
             'User-Agent: Mozilla/5.0', 'Accept: */*', 'Sec-Fetch-Mode: navigate']
    if authed:
        lines.append(f'Cookie: {SESSION}; theme=dark')
    if body:
        lines += [f'Content-Type: {ctype}', f'Content-Length: {len(body)}']
    return '\r\n'.join(lines) + '\r\n\r\n' + body


REASONS = {200: 'OK', 201: 'Created', 302: 'Found', 403: 'Forbidden',
           404: 'Not Found', 500: 'Internal Server Error'}


def response_text(status, ctype, body, extra=()):
    lines = [f'HTTP/1.1 {status} {REASONS[status]}', f'Content-Type: {ctype}',
             f'Content-Length: {len(body)}', 'Server: nginx'] + list(extra)
    return '\r\n'.join(lines) + '\r\n\r\n' + body


class Capture:
    def __init__(self):
        self.items = []

    def add(self, method, path, status, mime, req, resp):
        url = BASE + path
        n = len(self.items)
        stamp = f'Mon Jan 01 {10 + n // 3600:02d}:{n // 60 % 60:02d}:{n % 60:02d} UTC 2026'
        self.items.append(
            f'<item><time>{stamp}</time><url>{html.escape(url)}</url>'
            f'<host>{HOST}</host><port>{PORT}</port><protocol>{SCHEME}</protocol>'
            f'<method>{method}</method><path>{html.escape(path)}</path>'
            f'<status>{status}</status><responselength>{len(resp)}</responselength>'
            f'<mimetype>{mime}</mimetype>'
            f'<request base64="true">{base64.b64encode(req.encode()).decode()}</request>'
            f'<response base64="true">{base64.b64encode(resp.encode()).decode()}</response>'
            f'</item>')

    def xml(self):
        return ('<?xml version="1.0"?><items burpVersion="2024.1">'
                + ''.join(self.items) + '</items>')


def anon_exchange(cap, method, path, body_ctype='application/json', body=''):
    """Emit one anonymous request whose outcome drives access_control."""
    return {
        'data': lambda: cap.add(method, path, 200, 'JSON',
                                request_text(method, path, False),
                                response_text(200, body_ctype, body)),
        'wall': lambda: cap.add(method, path, 302, '',
                                request_text(method, path, False),
                                response_text(302, 'text/html', '',
                                              ['Location: /login?next=' + path])),
        'denied': lambda: cap.add(method, path, 403, 'JSON',
                                  request_text(method, path, False),
                                  response_text(403, 'application/json',
                                                '{"error":"forbidden"}')),
    }


# --- entity expectations derived from the authored shapes -----------------
def expected_entities():
    """Replicate the authored grouping rule over SHAPES/API_ROUTES only.

    This reads the declarations above -- it never parses HTTP or imports the
    engine -- so it is an independent statement of intent, not a copy of
    build_entities.
    """
    produced, consumed = {}, {}
    for method, tpl, resp_shape, req_shape, _, _ in API_ROUTES:
        ref = f"{method} {BASE}:{PORT}{tpl.replace('%d', '{id}')}"
        if resp_shape:
            produced.setdefault(resp_shape, []).append(ref)
        if req_shape:
            consumed.setdefault(req_shape, []).append(ref)

    promoted = {}
    for shape in SHAPES:
        refs = set(produced.get(shape, [])) | set(consumed.get(shape, []))
        if len(refs) >= 2:
            promoted[shape] = {
                'name': shape,
                'fields': SHAPES[shape],
                'produced_by': sorted(set(produced.get(shape, []))),
                'consumed_by': sorted(set(consumed.get(shape, []))),
                'route_count': len(refs),
            }

    threshold = 0.6
    for name, entity in promoted.items():
        left = set(SHAPES[name])
        related = []
        for other in promoted:
            if other == name:
                continue
            right = set(SHAPES[other])
            if min(len(left), len(right)) / max(len(left), len(right)) < threshold:
                continue  # size-ratio prefilter: Jaccard cannot reach the threshold
            score = len(left & right) / len(left | right)
            if score >= threshold:
                related.append({'name': other, 'score': round(score, 2)})
        entity['related'] = sorted(related, key=lambda r: (-r['score'], r['name']))[:5]
    return [promoted[n] for n in sorted(promoted)], \
           sorted(set(SHAPES) - set(promoted))


# --- queries --------------------------------------------------------------
def query_set():
    """Authored semantic queries. Relevance is graded: 2 primary, 1 acceptable.

    Targets are resolved to document ids at test time. Three target forms:
    a route ref ("GET https://host:443/path"), an entity ("entity:<name>"), or
    the synthetic "auth_model" node. Queries use protocol/structural language
    only -- the engine strips vulnerability jargon from structural collections
    by design, which `screened` below covers separately.
    """
    o = f'{BASE}:{PORT}'
    return [
        {'q': 'order record returned by id', 'in': 'structure',
         'relevant': {'entity:order': 2, f'GET {o}/api/orders/{{id}}': 2,
                      f'POST {o}/api/orders': 1,
                      f'GET {o}/api/orders/{{id}}/detail': 1}},
        {'q': 'create a new order with a json request body', 'in': 'structure',
         'relevant': {f'POST {o}/api/orders': 2, f'PUT {o}/api/orders/{{id}}': 1,
                      'entity:order': 1}},
        {'q': 'customer name and email address', 'in': 'structure',
         'relevant': {'entity:customer': 2, f'GET {o}/api/customers/{{id}}': 2,
                      f'GET {o}/api/customers/{{id}}/profile': 2}},
        {'q': 'postal address with city country and line1 fields', 'in': 'structure',
         'relevant': {'entity:address': 2, 'entity:address_region': 2,
                      f'GET {o}/api/addresses/{{id}}': 2,
                      f'GET {o}/api/customers/{{id}}/address': 2,
                      f'POST {o}/api/customers/{{id}}/address': 1}},
        {'q': 'product sku and price', 'in': 'structure',
         'relevant': {'entity:product': 2, f'GET {o}/api/products/{{id}}': 2,
                      f'POST {o}/api/products': 2}},
        {'q': 'invoice with currency amount and due date', 'in': 'structure',
         'relevant': {'entity:invoice_wide': 2, f'GET {o}/api/invoices/{{id}}': 2,
                      f'PUT {o}/api/invoices/{{id}}': 2}},
        {'q': 'session cookie issued when signing in', 'in': 'structure',
         'relevant': {'auth_model': 2, f'POST {o}/login': 2, f'GET {o}/login': 1}},
        {'q': 'reachable with no credential at all', 'in': 'structure',
         'relevant': {f'GET {o}/api/public/rates': 2, f'GET {o}/api/orders/{{id}}': 1,
                      f'GET {o}/api/products/{{id}}': 1, f'GET {o}/orders': 1,
                      f'GET {o}/tos': 1, f'GET {o}/priv': 1}},
        {'q': 'html page listing records in a table', 'in': 'structure',
         'relevant': {f'GET {o}/orders': 2, f'GET {o}/dashboard': 2,
                      f'GET {o}/customers': 1, f'GET {o}/invoices': 1,
                      f'GET {o}/products': 1, f'GET {o}/s/{{id}}': 1}},
        {'q': 'wildcard cross origin resource sharing header', 'in': 'structure',
         'relevant': {f'GET {o}/api/public/rates': 2}},
        {'q': 'updates an existing record in place', 'in': 'structure',
         'relevant': {f'PUT {o}/api/orders/{{id}}': 2,
                      f'PUT {o}/api/invoices/{{id}}': 2,
                      f'PUT {o}/api/addresses/{{id}}': 2,
                      f'PATCH {o}/api/orders/{{id}}': 2}},
        {'q': 'javascript and stylesheet assets', 'in': 'structure',
         'include_static': True,
         'relevant': {f'GET {o}/static/app.js': 2, f'GET {o}/static/app.css': 2,
                      f'GET {o}/static/vendor.js': 2, f'GET {o}/static/print.css': 2}},
        {'q': 'shipment and refund counters', 'in': 'structure',
         'relevant': {f'GET {o}/api/shipments/{{id}}/stats': 2,
                      f'GET {o}/api/refunds/{{id}}/stats': 2,
                      f'GET {o}/api/returns/{{id}}/stats': 1,
                      f'GET {o}/api/payouts/{{id}}/stats': 1}},
        {'q': 'server error exposing a database stack trace', 'in': 'behavior',
         'relevant': {f'GET {o}/api/search': 2}},
        {'q': 'redirected to the sign in page', 'in': 'behavior',
         'relevant': {f'GET {o}/legacy/{{id}}': 2,
                      f'GET {o}/api/invoices/{{id}}': 1, f'GET {o}/api/session': 1,
                      f'GET {o}/api/orders/{{id}}/detail': 1, f'GET {o}/reports': 1}},
        {'q': 'forbidden response to a request with no cookie', 'in': 'behavior',
         'relevant': {f'GET {o}/api/customers/{{id}}': 2,
                      f'GET {o}/api/addresses/{{id}}': 2,
                      f'GET {o}/api/admin/{{id}}': 2,
                      f'GET {o}/customers': 1, f'GET {o}/audit': 1}},
        {'q': 'json object describing one order', 'in': 'behavior',
         'relevant': {f'GET {o}/api/orders/{{id}}': 2, f'POST {o}/api/orders': 1,
                      f'PUT {o}/api/orders/{{id}}': 1}},
        {'q': 'response that set a session cookie', 'in': 'behavior',
         'relevant': {f'POST {o}/login': 2}},
        {'q': 'anonymous request served real page content', 'in': 'behavior',
         'relevant': {f'GET {o}/orders': 2, f'GET {o}/tos': 1, f'GET {o}/priv': 1,
                      f'GET {o}/about': 1, f'GET {o}/api/public/rates': 1}},
        {'q': 'created a new resource and returned it', 'in': 'behavior',
         'relevant': {f'POST {o}/api/orders': 2, f'POST {o}/api/products': 2,
                      f'POST {o}/api/customers/{{id}}/address': 2}},
    ]


SCREENED = [
    {'q': 'sql injection in the orders endpoint',
     'expect_rejected': ['sql injection'], 'expect_action': 'removed-terms'},
    {'q': 'idor on the customer record', 'expect_rejected': ['idor'],
     'expect_action': 'removed-terms'},
    {'q': 'xss', 'expect_rejected': ['xss'], 'expect_action': 'removed-all'},
    {'q': 'broken access control', 'expect_rejected': ['broken access control'],
     'expect_action': 'removed-all'},
]


def build(out_dir):
    cap = Capture()
    routes = {}   # ref -> label dict

    def note_route(method, path_tpl, produces, authed, anon, params=()):
        # The node_kind rule, declared from the authored response content types:
        # a GET that ever produced HTML is a page, a mutating method is an
        # action, anything else an endpoint. Routes with a soft auth wall emit a
        # 302 text/html alongside their JSON, so they are pages too.
        if method == 'GET' and any('html' in c for c in produces):
            kind = 'page'
        elif method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            kind = 'action'
        else:
            kind = 'endpoint'
        ref = f'{method} {BASE}:{PORT}{path_tpl}'
        entry = routes.setdefault(ref, {
            'ref': ref, 'method': method, 'endpoint_template': path_tpl,
            'node_kind': kind, 'authenticated_ever': False, 'anon': None,
            'params': sorted(params),
        })
        entry['authenticated_ever'] = entry['authenticated_ever'] or authed
        if anon:
            entry['anon'] = anon
        return entry

    # 1. login page (anonymous) and the POST that establishes the session
    for _ in range(2):
        cap.add('GET', '/login', 200, 'HTML', request_text('GET', '/login', False),
                response_text(200, 'text/html; charset=utf-8', LOGIN_PAGE))
    note_route('GET', '/login', ['text/html'], False, 'wall')
    form = 'email=a%40example.com&password=hunter2&csrf=tok-abc123'
    cap.add('POST', '/login', 302, '',
            request_text('POST', '/login', False, form,
                         'application/x-www-form-urlencoded'),
            response_text(302, 'text/html', '',
                          ['Location: /dashboard',
                           f'Set-Cookie: {SESSION}; Path=/; HttpOnly']))
    note_route('POST', '/login', ['text/html'], False, None,
               ['csrf', 'email', 'password'])

    # 2. authenticated HTML pages
    for path, title, rows, label, anon in HTML_PAGES:
        body = page(title, f'<h1>{title}</h1>' + (table(rows, label) if rows else
                    '<dl><dt>Email</dt><dd>a@example.com</dd></dl>'))
        for _ in range(2):
            cap.add('GET', path, 200, 'HTML', request_text('GET', path, True),
                    response_text(200, 'text/html; charset=utf-8', body))
        note_route('GET', path, ['text/html'], True, anon)
        if anon == 'data':
            cap.add('GET', path, 200, 'HTML', request_text('GET', path, False),
                    response_text(200, 'text/html; charset=utf-8', body))
        elif anon == 'wall':
            cap.add('GET', path, 302, '', request_text('GET', path, False),
                    response_text(302, 'text/html', '', [f'Location: /login?next={path}']))
        elif anon == 'denied':
            cap.add('GET', path, 403, 'HTML', request_text('GET', path, False),
                    response_text(403, 'text/html', page('Forbidden', '<h1>Forbidden</h1>')))

    # 3. numeric section pages -- 20 distinct paths collapsing to one template
    for i in range(1, 21):
        body = page(f'Section {i}', f'<h1>Section {i}</h1>' + table(20, 'Item'))
        cap.add('GET', f'/s/{i}', 200, 'HTML', request_text('GET', f'/s/{i}', True),
                response_text(200, 'text/html; charset=utf-8', body))
    note_route('GET', '/s/{id}', ['text/html'], True, None)

    # 4. public marketing pages
    for path in PUBLIC_PAGES:
        body = page(path.strip('/').upper(), f'<h1>{path}</h1><p>Static copy.</p>')
        cap.add('GET', path, 200, 'HTML', request_text('GET', path, False),
                response_text(200, 'text/html; charset=utf-8', body))
        note_route('GET', path, ['text/html'], False, 'data')

    # 5. static assets
    for path, ctype, body in [
            ('/static/app.js', 'application/javascript', "console.log('app');\n" * 60),
            ('/static/vendor.js', 'application/javascript', "var v=1;\n" * 80),
            ('/static/app.css', 'text/css', 'body{margin:0}\n' * 40),
            ('/static/print.css', 'text/css', '@media print{a{color:#000}}\n' * 20),
            ('/static/icons.svg', 'image/svg+xml', '<svg xmlns="http://www.w3.org/2000/svg"/>'),
            ('/static/app.map', 'application/json', '{"version":3}')]:
        cap.add('GET', path, 200, 'script', request_text('GET', path, False),
                response_text(200, ctype, body))
        note_route('GET', path, [ctype], False, None)

    # 6. entity-bearing API routes
    for method, tpl, resp_shape, req_shape, count, anon in API_ROUTES:
        template = tpl.replace('%d', '{id}')
        for i in range(count):
            path = tpl % (1040 + i) if '%d' in tpl else tpl
            if resp_shape == 'quoted_note':
                resp_body = json.dumps({'author': 'qa', 'id': 9000 + i,
                                        'note': NEEDLE_QUOTED})
            else:
                resp_body = body_for(resp_shape, i)
            req_body = body_for(req_shape, i) if req_shape else ''
            status = 201 if method == 'POST' else 200
            extra = ['Access-Control-Allow-Origin: *'] if 'public' in tpl else []
            cap.add(method, path, status, 'JSON',
                    request_text(method, path, True, req_body),
                    response_text(status, 'application/json', resp_body, extra))
        params = sorted(SHAPES[req_shape]) if req_shape else []
        produces = ['application/json'] + (['text/html'] if anon == 'wall' else [])
        note_route(method, template, produces, True, anon, params)
        if anon:
            path = tpl % 1040 if '%d' in tpl else tpl
            anon_exchange(cap, method, path, 'application/json',
                          body_for(resp_shape, 0) if resp_shape != 'quoted_note' else '{}')[anon]()

    # 7. the deliberately shared identifier: an order and a customer on 4711
    cap.add('GET', f'/api/customers/{LINKED_ID}', 200, 'JSON',
            request_text('GET', f'/api/customers/{LINKED_ID}', True),
            response_text(200, 'application/json',
                          json.dumps({'id': LINKED_ID, 'name': 'Linked Customer',
                                      'email': 'linked@example.com'})))

    # 8. single-route endpoints (must not become entities)
    for n, topic in enumerate(MISC_TOPICS):
        tpl = f'/api/{topic}/%d/stats'
        for i in range(MISC_ITEMS):
            body = json.dumps({f'{topic}_count': 10 + i, 'id': 500 + n,
                               'window': '7d', f'{topic}_state': 'settled'})
            path = tpl % (500 + n)
            cap.add('GET', path, 200, 'JSON', request_text('GET', path, True),
                    response_text(200, 'application/json', body))
        note_route('GET', f'/api/{topic}/{{id}}/stats', ['application/json'], True, None)

    # 9. keyword needles and error behaviour
    for i in range(2):
        path = "/api/search?q=%27"
        cap.add('GET', path, 500, 'JSON', request_text('GET', path, True),
                response_text(500, 'application/json', NEEDLE_SQL))
    note_route('GET', '/api/search', ['application/json'], True, None, ['q'])

    for i in range(2):
        path = f'/legacy/{200 + i}'
        cap.add('GET', path, 302, '', request_text('GET', path, False),
                response_text(302, 'text/html', '', ['Location: /login']))
    note_route('GET', '/legacy/{id}', ['text/html'], False, 'wall')

    for i in range(2):
        path = f'/api/admin/{300 + i}'
        cap.add('GET', path, 403, 'JSON', request_text('GET', path, False),
                response_text(403, 'application/json', '{"error":"forbidden"}'))
    note_route('GET', '/api/admin/{id}', ['application/json'], False, 'denied')

    # 10. byte-identical repeats -- exercises overlap_key collapsing
    dup_req = request_text('GET', '/api/orders/1040', True)
    dup_resp = response_text(200, 'application/json', body_for('order', 0))
    for _ in range(4):
        cap.add('GET', '/api/orders/1040', 200, 'JSON', dup_req, dup_resp)

    # --- assemble -------------------------------------------------------
    xml = cap.xml()
    entities, non_entities = expected_entities()

    # access_control follows from the authored anonymous outcome
    control = {None: 'unknown', 'data': 'open-data', 'wall': 'soft-auth-wall',
               'denied': 'enforced'}
    for entry in routes.values():
        entry['access_control'] = control[entry['anon']]
        entry['anon_allowed'] = entry['anon'] == 'data'
        del entry['anon']

    manifest = {
        'generated_by': 'tests/make_capture.py',
        'origin': {'scheme': SCHEME, 'host': HOST, 'port': PORT},
        'capture': {'items': len(cap.items), 'bytes': len(xml),
                    'sha256': hashlib.sha256(xml.encode()).hexdigest()},
        'routes': [routes[r] for r in sorted(routes)],
        'entities': entities,
        'non_entities': non_entities,
        'entity_threshold': 0.6,
        # Identifier rows are written for `exchanges` (at ingest) and `attacks`
        # (findings) only, so lookups resolve to observations, never to derived
        # structure/behavior documents.
        'identifiers': [
            {'value': '9000', 'exact_hits': 1, 'fields': ['response.id'],
             'templates': ['/api/notes/{id}']},
            {'value': '300', 'exact_hits': 1, 'fields': ['url.admin'],
             'templates': ['/api/admin/{id}']},
            {'value': str(LINKED_ID), 'min_hits': 20,
             'fields': ['request.customer_id', 'response.customer_id',
                        'response.id', 'response.user_id', 'url.customers'],
             'why': 'one value shared by an order body, an invoice body and a '
                    'customer record -- a cross-endpoint correlation lead'},
        ],
        'needles': [
            {'name': 'sql_error', 'text': 'SQLSyntaxErrorException'},
            {'name': 'embedded_quote', 'text': NEEDLE_QUOTED_RAW,
             'absent_from_stored_document': True,
             'why': 'present in the decoded HTTP text but escaped again inside '
                    'the stored document, so where_document cannot prefilter it'},
            {'name': 'session_cookie', 'text': 'sid-9f8e7d6c5b4a'},
        ],
        'queries': query_set(),
        'screened': SCREENED,
        'auth_model': {'cookies_set': ['session'], 'cookies_sent': ['session', 'theme'],
                       'mechanisms': ['cookie']},
    }

    xml_path = os.path.join(out_dir, 'capture.xml')
    man_path = os.path.join(out_dir, 'ground_truth.json')
    with open(xml_path, 'w') as handle:
        handle.write(xml)
    with open(man_path, 'w') as handle:
        json.dump(manifest, handle, indent=2, sort_keys=False)
        handle.write('\n')
    print(f'{xml_path}: {len(cap.items)} items, {len(xml) / 1024:.1f} KB')
    print(f'{man_path}: {len(manifest["routes"])} routes, '
          f'{len(entities)} entities, {len(non_entities)} non-entity shapes, '
          f'{len(manifest["queries"])} queries')
    for entity in entities:
        rel = ', '.join(f'{r["name"]}@{r["score"]}' for r in entity['related']) or '-'
        print(f'  entity {entity["name"]:<15} routes={entity["route_count"]} related={rel}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out-dir', default=os.path.dirname(os.path.abspath(__file__)))
    build(parser.parse_args().out_dir)


if __name__ == '__main__':
    main()
