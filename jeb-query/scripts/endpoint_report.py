"""
J.E.B. -- the `endpoint` command: everything known about one route, in one call.

This is the answer to "investigate /api/orders". It is a deterministic index
scan, not a vector search: `JebAgent.parent_index()` returns every canonical
`structure` node in a single `collection.get`, and the route is located by
comparing path templates. No embedding, no Ollama round-trip, and no relevance
cutoff that a badly-worded query could fall foul of.

The report assembles, for the matched route(s): parameters, auth posture,
cookies sent and set, missing security headers and CORS; the origin's auth-model
node; sub-paths and sibling routes; the entity nodes that link this route to
others handling the same data shape; the behavior documents it was observed in;
and the raw request/response of one representative behavior, truncated
structurally so headers always survive.
"""
import re
from urllib.parse import urlparse

import distill as d

SYNTHETIC_TEMPLATES = {'{auth-model}', '{entity}', '{spa-shell}'}
PLACEHOLDER_RE = re.compile(r'^\{[^}]*\}$')

# How much of each section survives at each depth.
BUDGET = {
    'quick':  dict(matches=4,  sub_paths=5,  siblings=0,  examples=0,  page_content=False),
    'normal': dict(matches=6,  sub_paths=10, siblings=8,  examples=5,  page_content=False),
    'deep':   dict(matches=12, sub_paths=25, siblings=20, examples=12, page_content=True),
}
MAX_HEADER_LINES = 40
REQUEST_BODY_CAP = 1500


def _csv_list(value):
    return [t.strip() for t in str(value or '').split(',') if t.strip()]


def _segments(template):
    return [s for s in str(template or '').split('/') if s]


def normalize_target(raw):
    """Accepts a path, a host-qualified path, or a full URL.

    `/api/orders/42` and `https://app/api/orders/42?limit=10` both normalise to
    the template `/api/orders/{id}`, which is what `structure` actually stores --
    so the agent may paste whatever the user said.
    """
    raw = (raw or '').strip()
    host = None
    path = raw
    if '://' in raw:
        parsed = urlparse(raw)
        host = parsed.hostname
        path = parsed.path or '/'
    elif raw and not raw.startswith('/') and '/' in raw and '.' in raw.split('/')[0]:
        # bare 'app.example.com/api/orders'
        head, _, rest = raw.partition('/')
        host, path = head, '/' + rest
    if '?' in path:
        path = path.split('?', 1)[0]
    if not path.startswith('/'):
        path = '/' + path
    if len(path) > 1:
        path = path.rstrip('/')
    template = d.templatize_path(path)
    return {'input': raw, 'host': host, 'path': path, 'template': template,
            'segments': _segments(template), 'words': d.path_words(template)}


def segment_match(a_template, b_template):
    """Segment-wise equality where any `{...}` segment is a wildcard.

    `distill._templatize_segment` picks a placeholder from the observed value, so
    the same real segment can be stored as `{id}` in one capture and `{token}` in
    another. Plain string equality would miss that; this does not.
    """
    a, b = _segments(a_template), _segments(b_template)
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if x == y:
            continue
        if PLACEHOLDER_RE.match(x) or PLACEHOLDER_RE.match(y):
            continue
        return False
    return True


def classify_match(target, meta):
    """-> 'exact' | 'template' | 'descendant' | 'sibling' | 'fuzzy' | None"""
    template = str(meta.get('endpoint_template', '') or '')
    if not template or template in SYNTHETIC_TEMPLATES:
        return None
    if template in (target['path'], target['template']):
        return 'exact'
    if segment_match(template, target['template']):
        return 'template'
    node_segments = _segments(template)
    if len(node_segments) > len(target['segments']) and segment_match(
            '/'.join(node_segments[:len(target['segments'])]), target['template']):
        return 'descendant'
    parent = target['template'].rsplit('/', 1)[0] or '/'
    if parent != '/' and template.rsplit('/', 1)[0] == parent:
        return 'sibling'
    tail = next((s for s in reversed(target['segments'])
                 if not PLACEHOLDER_RE.match(s)), None)
    if tail and tail in _segments(template):
        return 'fuzzy'
    return None


def pick_representative(behaviors):
    """Which observed request/response best represents this route.

    Prefers one that actually delivered application data over a login wall or a
    redirect, since that is the response an agent needs to read.
    """
    def rank(item):
        doc_id, meta = item
        return (
            0 if meta.get('access_class') == 'data' else 1,
            0 if meta.get('authenticated') else 1,
            0 if 200 <= int(meta.get('status_code', 0) or 0) < 300 else 1,
            -int(meta.get('instance_count', 0) or 0),
            doc_id,
        )
    rows = sorted(behaviors.items(), key=rank)
    return rows[0][0] if rows else None


def _split_sections(document):
    """Split a reconstructed exchange into (request, response), dropping the
    `--- COLLAPSED:` example-URL tail, which is duplicate information."""
    text = document or ''
    collapsed = text.find('\n\n--- COLLAPSED:')
    if collapsed != -1:
        text = text[:collapsed]
    marker = '\n--- RESPONSE ---\n'
    head = text.split('--- REQUEST ---\n', 1)[-1]
    if marker in head:
        request, response = head.split(marker, 1)
    else:
        request, response = head, ''
    return request.rstrip('\n'), response.rstrip('\n')


def _trim_half(section, body_cap, drop_body=False):
    """Keep the start line and every header; budget only the body."""
    if not section:
        return '', 0
    parts = section.split('\n\n', 1)
    head, body = parts[0], (parts[1] if len(parts) > 1 else '')
    lines = head.split('\n')
    if len(lines) > MAX_HEADER_LINES:
        head = '\n'.join(lines[:MAX_HEADER_LINES]) + \
            f"\n[... {len(lines) - MAX_HEADER_LINES} more header lines]"
    dropped = 0
    if drop_body and body:
        dropped = len(body)
        body = '[static asset body omitted]'
    elif len(body) > body_cap:
        dropped = len(body) - body_cap
        body = body[:body_cap]
    return (head + ('\n\n' + body if body else '')), dropped


def truncate_raw(document, budget, meta):
    """Structure-aware truncation: headers carry the cookies, auth and CORS that
    matter and are small, so they are never budgeted -- only bodies are."""
    request, response = _split_sections(document)
    # Measure against the exchange itself, not the stored blob: the COLLAPSED
    # example-URL tail is dropped as duplicate information, not truncated away.
    total = len(f"--- REQUEST ---\n{request}\n\n--- RESPONSE ---\n{response}")
    resp_ct = str(meta.get('resp_content_type', '') or '')
    drop_body = bool(meta.get('is_static')) or \
        resp_ct.startswith(('image/', 'font/', 'video/', 'audio/'))
    req_text, req_dropped = _trim_half(request, REQUEST_BODY_CAP)
    resp_text, resp_dropped = _trim_half(response, max(0, int(budget)), drop_body)
    text = f"--- REQUEST ---\n{req_text}\n\n--- RESPONSE ---\n{resp_text}"
    dropped = req_dropped + resp_dropped
    if dropped:
        text += (f"\n\n... [truncated {dropped} of {total} chars "
                 f"-- full document: jeb-query.sh get {meta.get('_id', '<id>')}]")
    return {'text': text, 'truncated': bool(dropped),
            'bytes_shown': len(text), 'bytes_total': total}


def _node_view(doc_id, meta, tier):
    return {
        'id': doc_id,
        'match': tier,
        'origin': f"{meta.get('scheme', '')}://{meta.get('host', '')}:{meta.get('port', '')}",
        'method': meta.get('method', ''),
        'endpoint_template': meta.get('endpoint_template', ''),
        'node_kind': meta.get('node_kind', ''),
        'params': _csv_list(meta.get('param_names')),
        'produces': _csv_list(meta.get('produces')),
        'status_codes': _csv_list(meta.get('status_codes')),
        'instance_count': meta.get('instance_count', 0),
        'auth': {
            'authenticated_ever': meta.get('authenticated_ever'),
            'anon_allowed': meta.get('anon_allowed'),
            'anon_soft_denied': meta.get('anon_soft_denied'),
            'access_control': meta.get('access_control', ''),
            'mechanisms': _csv_list(meta.get('auth_mechanisms')),
            'cookies_sent': _csv_list(meta.get('cookies_sent')),
            'cookies_set': _csv_list(meta.get('cookies_set')),
        },
        'security': {
            'headers_missing': _csv_list(meta.get('security_headers_missing')),
            'cors': meta.get('cors', ''),
        },
        'example_ids': _csv_list(meta.get('example_ids')),
        'entity_ids': _csv_list(meta.get('entity_ids')),
    }


def _brief(doc_id, meta):
    return {'id': doc_id, 'method': meta.get('method', ''),
            'endpoint_template': meta.get('endpoint_template', ''),
            'access_control': meta.get('access_control', ''),
            'instance_count': meta.get('instance_count', 0),
            'summary': meta.get('summary', '')}


def build_report(agent, raw_target, host=None, method=None, depth='normal',
                 raw_chars=None):
    target = normalize_target(raw_target)
    host = host or target['host']
    budget = BUDGET.get(depth, BUDGET['normal'])
    raw_budget = max(0, int(raw_chars or 0))

    tiers = {'exact': [], 'template': [], 'descendant': [], 'sibling': [], 'fuzzy': []}
    for doc_id, meta in agent.parent_index():
        if meta.get('node_kind') in ('auth_model', 'entity'):
            continue
        if host and meta.get('host') != host:
            continue
        if method and str(meta.get('method', '')).upper() != method.upper():
            continue
        tier = classify_match(target, meta)
        if tier:
            tiers[tier].append((doc_id, meta))

    notes = []
    matched = tiers['exact'] + tiers['template'] + tiers['descendant']
    if not matched and tiers['fuzzy']:
        matched = tiers['fuzzy']
        notes.append(f"No route matches {target['template']} exactly; showing routes "
                     f"whose path shares a segment with it.")
    if not matched:
        return _empty_report(agent, target, host, notes)

    matched.sort(key=lambda item: (0 if classify_match(target, item[1]) == 'exact' else 1,
                                   item[1].get('endpoint_template', ''),
                                   item[1].get('method', '')))
    primary = matched[:budget['matches']]
    matches = [_node_view(doc_id, meta, classify_match(target, meta))
               for doc_id, meta in primary]

    hosts = sorted({m['origin'] for m in matches})
    if len(hosts) > 1:
        notes.append(f"{len(hosts)} origins serve this path: {', '.join(hosts)}. "
                     f"Pass --host to narrow.")

    if budget['page_content']:
        docs = agent.get_many([m['id'] for m in matches], include=('documents',))
        for m in matches:
            if m['id'] in docs:
                m['report'] = docs[m['id']].get('document', '')

    report = {
        'command': 'endpoint',
        'query': {'input': target['input'], 'path': target['path'],
                  'template': target['template'], 'host': host},
        'count': len(matches),
        'matches': matches,
    }

    sub_paths = [_brief(i, m) for i, m in tiers['descendant']
                 if i not in {x['id'] for x in matches}][:budget['sub_paths']]
    if sub_paths:
        report['sub_paths'] = sub_paths
    siblings = [_brief(i, m) for i, m in tiers['sibling']][:budget['siblings']]
    if siblings:
        report['siblings'] = siblings

    auth_model = _auth_model(agent, matches, budget['page_content'])
    if auth_model:
        report['auth_model'] = auth_model

    related = _entities(agent, matches)
    if related:
        report['related_by_entity'] = related

    if budget['examples']:
        example_ids, seen = [], set()
        for m in matches:
            for eid in m['example_ids']:
                if eid not in seen:
                    seen.add(eid)
                    example_ids.append(eid)
        behaviors = agent.get_many(example_ids[:budget['examples'] * 2],
                                   collection_name='behavior')
        metas = {i: e['metadata'] for i, e in behaviors.items()}
        if metas:
            report['examples'] = [
                _example_view(i, metas[i])
                for i in example_ids if i in metas][:budget['examples']]
            variant_ids = list(dict.fromkeys(
                variant_id for example in report['examples']
                for variant_id in example.get('variant_ids', [])))
            if variant_ids:
                variant_docs = agent.get_many(
                    variant_ids[:budget['examples']], collection_name='behavior')
                report['variants'] = [
                    _example_view(i, variant_docs[i]['metadata'])
                    for i in variant_ids if i in variant_docs][:budget['examples']]
            if raw_budget:
                report['raw_example'] = _raw_example(agent, metas, raw_budget)
        elif example_ids:
            notes.append("This route's example behavior ids are not present in the "
                         "behavior collection; re-run jeb-import.")

    report['notes'] = notes
    report['next'] = _next_steps(report, target)
    return report


def _example_view(doc_id, meta):
    return {
        'id': doc_id,
        'method': meta.get('method', ''),
        'status_code': meta.get('status_code'),
        'auth_role': meta.get('auth_role', ''),
        'authenticated': meta.get('authenticated'),
        'access_class': meta.get('access_class', ''),
        'anon_matches_auth': meta.get('anon_matches_auth'),
        'req_features': meta.get('req_features', ''),
        'param_names': _csv_list(meta.get('param_names')),
        'req_content_type': meta.get('req_content_type', ''),
        'req_schema_keys': _csv_list(meta.get('req_schema_keys')),
        'graphql_operation': meta.get('graphql_operation', ''),
        'resp_class': meta.get('resp_class', ''),
        'resp_content_type': meta.get('resp_content_type', ''),
        'resp_body_sha256': meta.get('resp_body_sha256', ''),
        'cookie_issues': _csv_list(meta.get('cookie_issues')),
        'set_cookies': _csv_list(meta.get('set_cookies')),
        'jwt': meta.get('jwt', ''),
        'summary': meta.get('summary', ''),
        'variant_ids': _csv_list(meta.get('variant_ids')),
    }


def _raw_example(agent, metas, budget):
    chosen = pick_representative(metas)
    if not chosen:
        return None
    full = agent.get_many([chosen], collection_name='behavior',
                          include=('metadatas', 'documents'))
    if chosen not in full:
        return None
    meta = dict(full[chosen]['metadata'] or {})
    meta['_id'] = chosen
    out = truncate_raw(full[chosen].get('document', ''), budget, meta)
    reasons = []
    if meta.get('access_class') == 'data':
        reasons.append('served application data')
    if meta.get('authenticated'):
        reasons.append('authenticated')
    reasons.append(f"status {meta.get('status_code')}")
    reasons.append(f"{meta.get('instance_count', 1)} instance(s)")
    out.update({'id': chosen, 'selected_because': ', '.join(reasons),
                'instance_count': meta.get('instance_count', 1)})
    return out


def _auth_model(agent, matches, want_report):
    hosts = [m['origin'].split('://', 1)[-1].rsplit(':', 1)[0] for m in matches]
    for host in dict.fromkeys(h for h in hosts if h):
        found = agent.filter(where={"$and": [{'node_kind': 'auth_model'},
                                             {'host': host}]},
                             n_results=1, snippet_len=0)
        if not found['results']:
            continue
        node = found['results'][0]
        view = {'id': node['id'], 'host': host,
                'mechanisms': _csv_list(node.get('auth_mechanisms')),
                'cookies_set': _csv_list(node.get('cookies_set')),
                'cookies_sent': _csv_list(node.get('cookies_sent')),
                'headers_missing': _csv_list(node.get('security_headers_missing')),
                'cors': node.get('cors', '')}
        if want_report:
            docs = agent.get_many([node['id']], include=('documents',))
            view['report'] = docs.get(node['id'], {}).get('document', '')
        return view
    return None


def _entities(agent, matches):
    ids, seen = [], set()
    for m in matches:
        for eid in m['entity_ids']:
            if eid not in seen:
                seen.add(eid)
                ids.append(eid)
    out = []
    for doc_id, entry in agent.get_many(ids).items():
        meta = entry['metadata']
        out.append({'entity_id': doc_id,
                    'identifier_field': meta.get('identifier_field', ''),
                    'produced_by': _csv_list(meta.get('produced_by')),
                    'consumed_by': _csv_list(meta.get('consumed_by'))})
    return out


def _next_steps(report, target):
    steps = []
    raw = report.get('raw_example')
    if raw:
        steps.append(f"jeb-query.sh get {raw['id']}  -- full request/response")
    elif report.get('examples'):
        steps.append(f"jeb-query.sh get {report['examples'][0]['id']}")
    if report.get('related_by_entity'):
        steps.append("jeb-query.sh identifier <id value>  -- prove two routes touched "
                     "the same record")
    steps.append(f"jeb-query.sh search --in behavior --path {target['path']}")
    steps.append(f"jeb-query.sh attacks --path {target['path']}  -- findings recorded here")
    return steps


def _empty_report(agent, target, host, notes):
    """Never answer an unmatched endpoint with nothing: fall back to a conjunctive
    lexical lookup on the path tokens, then to the nearest routes by name."""
    suggestions = []
    parent_ids = agent._lexical_candidates(target['words'], 'structure', 20, op='AND')
    for doc_id, entry in agent.get_many(parent_ids[:10]).items():
        meta = entry['metadata']
        if meta.get('endpoint_template') not in SYNTHETIC_TEMPLATES:
            suggestions.append(_brief(doc_id, meta))
    if not suggestions:
        wanted = set(target['words'].split())
        scored = []
        for doc_id, meta in agent.parent_index():
            template = str(meta.get('endpoint_template', '') or '')
            if template in SYNTHETIC_TEMPLATES:
                continue
            overlap = len(wanted & set(d.path_words(template).split()))
            if overlap:
                scored.append((-overlap, doc_id, meta))
        scored.sort(key=lambda x: (x[0], x[1]))
        suggestions = [_brief(i, m) for _, i, m in scored[:10]]
    headline = (f"No route in this capture matches {target['path']}"
                + (f" on host {host}." if host else "."))
    notes = notes + [
        headline + (" `did_you_mean` lists the closest routes that were actually "
                    "observed." if suggestions else
                    " Nothing in the capture resembles it either -- the path may "
                    "never have been requested, or belong to another project's "
                    "database. `map` lists every route that was observed.")]
    return {'command': 'endpoint',
            'query': {'input': target['input'], 'path': target['path'],
                      'template': target['template'], 'host': host},
            'count': 0, 'matches': [], 'did_you_mean': suggestions,
            'notes': notes,
            'next': (["jeb-query.sh endpoint <one of did_you_mean>"] if suggestions
                     else []) + ["jeb-query.sh map  -- list every observed route"]}
