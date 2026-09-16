"""J.E.B. Chroma-only query interface: semantic discovery and exact evidence lookup."""
import argparse
import datetime
import json
import os
import re
import sys
import uuid

import chromadb

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, '../../jeb-import/scripts')))
from embedding import EMBEDDING_PROFILE_METADATA, embed_documents, make_ollama_ef, embedding_profile
import distill as d
from storage import (LOOKUP_COLLECTIONS, scan, sync_identifiers,
                     writer_lock, digest)
from findings import finding_document, parse_finding, pairs_for_finding
import retrieval

# Preserve the structural-query guidance without adding another retrieval engine.
VULN_ALIASES = ('sql injection', 'sql-injection', 'sqli', 'nosql injection',
                'cross site scripting', 'cross-site scripting', 'xss', 'ssrf',
                'server side request forgery', 'idor', 'bola', 'csrf', 'xsrf',
                'xxe', 'rce', 'remote code execution', 'command injection',
                'path traversal', 'directory traversal', 'lfi', 'rfi', 'ssti',
                'template injection', 'deserialization', 'open redirect',
                'broken access control', 'privilege escalation', 'auth bypass',
                'vulnerability', 'vulnerabilities', 'exploitable', 'pentest')
VULN_RE = re.compile(r'(?<![\w-])(' + '|'.join(re.escape(a) for a in
                     sorted(VULN_ALIASES, key=len, reverse=True)) + r')(?![\w-])', re.I)


def screen_query(text, collection):
    if collection == 'attacks':
        return text, []
    rejected = [m.group() for m in VULN_RE.finditer(text)]
    return re.sub(r'\s+', ' ', VULN_RE.sub(' ', text)).strip(' ,;-'), rejected

COLLECTIONS = ('structure', 'behavior', 'attacks')
ADDRESSABLE = COLLECTIONS + ('exchanges',)
DEPTH = {
    'quick': dict(candidate_k=20, n_results=5, max_per_endpoint=1, snippet_len=120, raw_chars=0),
    'normal': dict(candidate_k=40, n_results=8, max_per_endpoint=2, snippet_len=200, raw_chars=2000),
    'deep': dict(candidate_k=120, n_results=25, max_per_endpoint=4, snippet_len=400, raw_chars=8000),
}


class MissingCollection(ValueError):
    pass


class JebAgent:
    def __init__(self, db_path='./chroma_db', collection_name='behavior', create_if_missing=False):
        self.db_path = os.path.abspath(db_path)
        self.collection_name = collection_name
        if not create_if_missing and not os.path.isdir(self.db_path):
            raise MissingCollection('Project database does not exist; import a capture first.')
        self.client = chromadb.PersistentClient(path=self.db_path)
        self.ollama_ef = make_ollama_ef()
        self._siblings = {}
        self._parent_index_cache = None
        have = {c.name for c in self.client.list_collections()}
        if collection_name not in have:
            if not create_if_missing:
                raise MissingCollection(f"Project has no '{collection_name}' collection.")
            if 'attacks_rebuild_backup' in have:
                raise ValueError('Finding migration pending; finish project rebuild before writing findings.')
            self.collection = self.client.create_collection(
                collection_name, embedding_function=self.ollama_ef,
                metadata=embedding_profile(self.ollama_ef))
        else:
            self.collection = self.client.get_collection(
                collection_name, embedding_function=None if collection_name in LOOKUP_COLLECTIONS
                else self.ollama_ef)
        if collection_name in COLLECTIONS:
            self._validate(self.collection)
        self.has_segments = collection_name in ('structure', 'behavior')

    def _validate(self, collection):
        if any((collection.metadata or {}).get(k) != v
               for k, v in EMBEDDING_PROFILE_METADATA.items()):
            raise ValueError(f"Collection '{collection.name}' needs a rebuild. "
                             'Run process_burp.sh rebuild [project_dir]; '
                             'retain all original captures and the database.')
        self.ollama_ef.expected_digest = (collection.metadata or {}).get('embedding_model_digest', '')

    def sibling(self, name):
        if name == self.collection_name:
            return self.collection
        if name not in self._siblings:
            have = {c.name for c in self.client.list_collections()}
            col = self.client.get_collection(
                name, embedding_function=None if name in LOOKUP_COLLECTIONS else self.ollama_ef
            ) if name in have else None
            if col is not None and name in COLLECTIONS:
                self._validate(col)
            self._siblings[name] = col
        return self._siblings[name]

    def parent_index(self, refresh=False):
        if self._parent_index_cache is None or refresh:
            kwargs = {'where': {'granularity': 'parent'}} if self.has_segments else {}
            self._parent_index_cache = [(r['id'], r['metadatas'] or {})
                                        for r in scan(self.collection, **kwargs)]
        return self._parent_index_cache

    def get_many(self, ids, collection_name=None, include=('metadatas',)):
        col = self.collection if collection_name is None else self.sibling(collection_name)
        ids = [i for i in dict.fromkeys(ids) if i]
        out = {}
        if col is None:
            return out
        for start in range(0, len(ids), 500):
            got = col.get(ids=ids[start:start + 500], include=list(include))
            for index, record_id in enumerate(got['ids']):
                out[record_id] = {}
                if 'metadatas' in include:
                    out[record_id]['metadata'] = got['metadatas'][index] or {}
                if 'documents' in include:
                    out[record_id]['document'] = got['documents'][index] or ''
        return out

    def _summarize(self, doc_id, meta, distance=None, snippet_len=200):
        out = {'id': doc_id, **{k: v for k, v in meta.items()
                              if not k.startswith('_') and k not in ('payload', 'summary', 'evidence_ids')
                              and v != ''}}
        if distance is not None:
            out['distance'] = round(float(distance), 4)
        if snippet_len:
            out['summary'] = str(meta.get('summary', ''))[:snippet_len]
        if meta.get('evidence_ids'):
            evidence = meta['evidence_ids'].split(',')
            out['evidence_ids'] = evidence[:5]
            out['evidence_count'] = len(evidence)
        return out

    @staticmethod
    def _and_where(where, extra):
        return {'$and': [where, extra]} if where else extra

    def filter(self, where=None, where_document=None, n_results=8, snippet_len=200,
               post=None, sort_key=None, reverse=False, offset=0):
        effective = self._and_where(where, {'granularity': 'parent'}) if self.has_segments else where
        kwargs = {}
        if effective:
            kwargs['where'] = effective
        if where_document:
            kwargs['where_document'] = where_document
        rows = {r['id']: r['metadatas'] or {} for r in scan(self.collection, **kwargs)
                if all(p(r['metadatas'] or {}) for p in (post or []))}
        matched = {}
        if self.collection_name == 'behavior' and (where or where_document or post):
            kwargs['where'] = self._and_where(where, {'granularity': 'variant'})
            for row in scan(self.collection, **kwargs):
                meta = row['metadatas'] or {}
                if all(p(meta) for p in (post or [])):
                    matched.setdefault(meta['parent_id'], []).append(row['id'])
            rows.update({i: r['metadata'] for i, r in self.get_many(matched).items()})
        key = sort_key or (lambda row: (-int(row[1].get('instance_count', 0)), row[0]))
        ordered = sorted(rows.items(), key=key, reverse=reverse)
        results = [self._summarize(i, m, snippet_len=snippet_len)
                   for i, m in ordered[offset:offset + max(1, n_results)]]
        for result in results:
            if result['id'] in matched:
                result['matched_variants'] = matched[result['id']]
        return {'results': results, 'total': len(rows), 'complete': True,
                'offset': offset, 'has_more': len(rows) > offset + len(results)}

    def search(self, query, **kwargs):
        return retrieval.search(self, query, **kwargs)

    def get_full(self, doc_id, original=False):
        row = self.get_many([doc_id], include=('metadatas', 'documents')).get(doc_id)
        if not row:
            return None
        if self.collection_name == 'exchanges':
            item = json.loads(row['document'])
            row['metadata'] = {k: v for k, v in row['metadata'].items() if not k.startswith('_')}
            from normalize import reconstruct_raw
            row['document'] = reconstruct_raw(item, full=True)
            row['capture'] = item.get('_capture_id')
            row['source_item'] = item.get('_source_item')
            if original:
                row['original_http_base64'] = {k: item.get(k, {}).get('raw_base64', '')
                                               for k in ('request', 'response')}
        elif self.collection_name == 'attacks':
            row['document'] = parse_finding(row['document']) or row['document']
        return {'id': doc_id, **row}

    def find_similar(self, doc_id, n_results=8, where=None, snippet_len=200, post=None):
        seed = self.collection.get(ids=[doc_id], include=['embeddings'])
        if not seed['ids']:
            return {'results': []}
        effective = self._and_where(where, {'granularity': 'parent'}) if self.has_segments else where
        kwargs = {'where': effective} if effective else {}
        found = self.collection.query(query_embeddings=[seed['embeddings'][0]],
                                      n_results=max(n_results * 4, 40),
                                      include=['metadatas', 'distances'], **kwargs)
        results = []
        for i, m, distance in zip(found['ids'][0], found['metadatas'][0], found['distances'][0]):
            if i != doc_id and all(p(m) for p in (post or [])):
                results.append(self._summarize(i, m, distance, snippet_len))
        return {'results': results[:n_results]}

    def find_by_identifier(self, value):
        col = self.sibling('identifiers')
        if col is None:
            raise ValueError('Identifier collection missing; reimport original captures to populate it.')
        captures = self.sibling('captures')
        allowed = {r['id'] for r in scan(captures) if r['metadatas'].get('state') in
                   ('ready', 'complete', 'indexing')} if captures is not None else set()
        return [{'id': r['metadatas']['doc_id'],
                 'collection': r['metadatas']['source_collection'],
                 'field': r['metadatas']['field']}
                for r in scan(col, where={'value': str(value)})
                if r['metadatas'].get('source_collection') != 'exchanges'
                or r['metadatas'].get('capture_id') in allowed]

    def source_evidence(self, where=None, post=None, contains=None, offset=0, limit=50):
        """Scan source text without searching JSON escaping or base64 artifacts."""
        from normalize import reconstruct_raw
        captures = self.sibling('captures')
        allowed = {r['id'] for r in scan(captures) if r['metadatas'].get('state') in
                   ('ready', 'complete', 'indexing')} if captures is not None else set()
        col = self.sibling('exchanges')
        rows = []
        include = ('metadatas', 'documents') if contains else ('metadatas',)
        kwargs = {'where': where} if where else {}
        if col is not None:
            for row in scan(col, include=include, page_size=20, **kwargs):
                meta = row['metadatas']
                if meta.get('capture_id') not in allowed or not all(p(meta) for p in (post or [])):
                    continue
                if contains and contains not in reconstruct_raw(json.loads(row['documents']), full=True):
                    continue
                rows.append((row['id'], meta))
        rows.sort(key=lambda r: (r[1].get('capture_id', ''), r[1].get('source_item', 0), r[0]))
        results = [self._summarize(i, m) for i, m in rows[offset:offset + limit]]
        return {'results': results, 'total': len(rows), 'offset': offset,
                'has_more': offset + len(results) < len(rows), 'complete': True}

    def record_attack(self, m, request_text, response_text):
        if 'attacks_rebuild_backup' in {c.name for c in self.client.list_collections()}:
            raise ValueError('Finding migration pending; finish project rebuild before writing findings.')
        parsed = d.urlparse(m['endpoint'])
        if not parsed.scheme or not parsed.hostname:
            raise ValueError('--endpoint must be an absolute URL, including scheme and host.')
        m = dict(m, method=m.get('method', '').upper())
        template = d.templatize_path(parsed.path or '/')
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        record = dict(m, endpoint_template=template, status_code=d._to_int(m.get('status', '')))
        text = d.attack_embed_text(record)
        meta = {k: str(m.get(k, '')) for k in ('vuln_class', 'method', 'param', 'payload',
                                              'severity', 'verdict', 'tool')}
        meta.update(doc_kind='attack', scheme=parsed.scheme, host=parsed.hostname or '',
                    port=parsed.port or (443 if parsed.scheme == 'https' else 80),
                    endpoint_template=template, time=now, granularity='parent',
                    source_behavior_id=m.get('source_id', ''),
                    status_code=record['status_code'], summary=d.attack_summary(record),
                    _embed_text=text)
        doc_id = 'attack-' + digest(m['event_id']) if m.get('event_id') else uuid.uuid4().hex
        data = {k: m.get(k, '') for k in ('endpoint', 'method', 'param', 'payload', 'status',
                'severity', 'verdict', 'vuln_class', 'source_id', 'evidence', 'tool')}
        data.update(request=request_text, response=response_text)
        document = finding_document(data)
        old = self.collection.get(ids=[doc_id], include=['documents', 'metadatas'])
        if old['ids'] and old['documents'][0] != document:
            raise ValueError('Event ID already belongs to different finding inputs.')
        if not old['ids']:
            meta.update(identifier_state='pending', event_id=m.get('event_id', ''))
            self.collection.upsert(ids=[doc_id], documents=[document], metadatas=[meta],
                                   embeddings=embed_documents(self.ollama_ef, [text]))
        try:
            sync_identifiers(self.client, 'attacks', [{'id': doc_id,
                              'identifier_pairs': pairs_for_finding(data)}], replace=True)
            self.collection.update(ids=[doc_id], metadatas=[{'identifier_state': 'complete'}])
            return {'recorded': doc_id, 'summary': meta['summary'], 'identifier_state': 'complete'}
        except Exception as exc:
            return {'recorded': doc_id, 'summary': meta['summary'], 'identifier_state': 'pending',
                    'notes': [f'Finding saved; identifier repair pending: {exc}. Run project rebuild.']}


def _status_clause(spec):
    match = re.fullmatch(r'([<>]=?)?(\d{3})', spec)
    if match:
        op, value = match.groups()
        return {'status_code': { {'>': '$gt', '>=': '$gte', '<': '$lt', '<=': '$lte'}[op]: int(value)}} if op else {'status_code': int(value)}
    if re.fullmatch(r'\dxx', spec, re.I):
        low, high = int(spec[0]) * 100, int(spec[0]) * 100 + 99
    elif re.fullmatch(r'\d{3}-\d{3}', spec):
        low, high = map(int, spec.split('-'))
    else:
        raise ValueError('Status must be 500, >=500, 500-599, or 5xx.')
    return {'$and': [{'status_code': {'$gte': low}}, {'status_code': {'$lte': high}}]}


def build_where(args, collection):
    if collection == 'attacks':
        unsupported = ('kind', 'access_control', 'access_class', 'anon', 'auth', 'cors_open',
                       'anon_matches_auth', 'cookie_issues', 'jwt', 'cookie', 'missing_header', 'param')
    elif collection == 'exchanges':
        unsupported = ('kind', 'access_control', 'access_class', 'anon', 'auth', 'cors_open',
                       'cookie_issues', 'jwt', 'cookie', 'missing_header', 'param', 'status',
                       'severity', 'verdict', 'vuln_class')
    else:
        unsupported = ('vuln_class', 'verdict', 'severity')
        if collection == 'structure':
            unsupported += ('access_class', 'anon_matches_auth', 'cookie_issues', 'jwt')
        else:
            unsupported += ('kind', 'access_control')
    for flag in unsupported:
        if getattr(args, flag, None):
            raise ValueError(f'--{flag.replace("_", "-")} is not supported for {collection}.')
    clauses = []
    for name, field in [('host', 'host'), ('kind', 'node_kind'), ('access_control', 'access_control'),
                        ('access_class', 'access_class'), ('vuln_class', 'vuln_class'),
                        ('verdict', 'verdict'), ('severity', 'severity')]:
        if getattr(args, name, None):
            clauses.append({field: getattr(args, name)})
    if getattr(args, 'method', None):
        methods = args.method if isinstance(args.method, list) else [args.method]
        clauses.append({'method': {'$in': [m.upper() for m in methods]}})
    if getattr(args, 'status', None):
        if collection == 'structure':
            raise ValueError('--status applies to behavior or attacks.')
        clauses.append(_status_clause(args.status))
    if getattr(args, 'anon', False):
        clauses.append({'anon_allowed': True} if collection == 'structure' else {'credential_present': False})
    if getattr(args, 'auth', False):
        clauses.append({'authenticated_ever': True} if collection == 'structure' else {'credential_present': True})
    if getattr(args, 'anon_matches_auth', False):
        clauses.append({'anon_matches_auth': True})
    if getattr(args, 'cors_open', False):
        clauses.append({'cors': {'$in': ['*', 'null', '* creds', 'null creds']}})
    if collection in ('structure', 'behavior') and not getattr(args, 'include_static', False):
        clauses.append({'is_static': False})
    if getattr(args, 'where', None):
        clauses.append(json.loads(args.where))
    return {'$and': clauses} if len(clauses) > 1 else clauses[0] if clauses else None


def post_filters(args, collection):
    predicates = []
    for attr, field in [('param', 'param_names'), ('missing_header', 'security_headers_missing')]:
        for value in getattr(args, attr, None) or []:
            predicates.append(lambda m, v=value.lower(), f=field:
                              v in str(m.get(f, '')).lower().split(','))
    for value in getattr(args, 'cookie', None) or []:
        def cookie_names(meta):
            names = set()
            for field in ('cookie_names', 'cookies_sent', 'cookies_set'):
                names.update(str(meta.get(field, '')).split(','))
            names.update(re.findall(r'(?:^|,)([^,()]+)\(', str(meta.get('set_cookies', ''))))
            return names
        predicates.append(lambda m, v=value: v in cookie_names(m))
    for field in ('jwt', 'cookie_issues'):
        if getattr(args, field, False):
            predicates.append(lambda m, f=field: bool(m.get(f)))
    if getattr(args, 'path', None):
        import endpoint_report as er
        target = er.normalize_target(args.path)
        predicates.append(lambda m: er.origin_matches(target, m) and er.classify_match(target, m)
                          in ('exact', 'template', 'descendant'))
    return predicates


def envelope(command, **fields):
    return {'command': command, 'count': len(fields.get('results', [])), 'next': [], **fields}


def resolve_collection(db_path, doc_id):
    if not os.path.isdir(db_path):
        return None
    client = chromadb.PersistentClient(path=os.path.abspath(db_path))
    have = {c.name for c in client.list_collections()}
    for name in ADDRESSABLE:
        if name in have and client.get_collection(name, embedding_function=None).get(ids=[doc_id], include=[])['ids']:
            return name
    return None


def execute(args):
    command = args.command
    settings = dict(DEPTH[getattr(args, 'depth', 'normal')])
    if getattr(args, 'limit', None) is not None:
        if args.limit < 1:
            raise ValueError('--limit must be positive.')
        settings['n_results'] = args.limit
    if getattr(args, 'offset', 0) < 0:
        raise ValueError('--offset must be nonnegative.')
    collection = getattr(args, 'collection', None) or (
        'structure' if command in ('map', 'endpoint') else 'attacks' if command in ('attacks', 'record-attack') else 'behavior')
    if command in ('get', 'similar'):
        collection = getattr(args, 'collection', None) or resolve_collection(args.db_path, args.target)
        if collection is None:
            return envelope(command, results=[], notes=['ID not found.'], next=['jeb-query.sh map'])
    if command == 'identifier':
        collection = 'identifiers'
    if command == 'evidence':
        collection = 'exchanges'
    agent = JebAgent(args.db_path, collection, create_if_missing=command == 'record-attack')
    if command == 'endpoint':
        import endpoint_report as er
        return er.build_report(agent, args.target, host=args.host, method=args.method,
                               depth=args.depth, limit=args.limit, raw_chars=0 if args.no_raw else (
                                   args.raw_chars if args.raw_chars is not None else settings['raw_chars']))
    if command == 'get':
        doc = agent.get_full(args.target, original=args.original)
        return envelope(command, collection=collection, count=int(doc is not None), document=doc,
                        next=([f'jeb-query.sh evidence {args.target}', f'jeb-query.sh similar {args.target}']
                              if collection == 'behavior' else
                              [f'jeb-query.sh similar {args.target}'] if collection in COLLECTIONS else []))
    if command == 'identifier':
        hits = agent.find_by_identifier(args.target)
        offset, limit = args.offset, args.limit or 50
        return envelope(command, value=args.target, results=hits[offset:offset + limit], complete=True,
                        total=len(hits), has_more=len(hits) > offset + limit, offset=offset,
                         notes=['Equal identifier values are correlation leads, not proof of the same record.'])
    if command == 'evidence':
        where = {'behavior_id': args.target}
        if args.signal:
            field = 'anon_matches_auth' if args.signal == 'content' else 'anon_schema_matches_credentialed'
            where = {'$and': [where, {field: True}]}
        found = agent.source_evidence(where=where, offset=args.offset, limit=args.limit)
        return envelope(command, **found, next=[f"jeb-query.sh get {r['id']}" for r in found['results'][:3]])
    if command == 'record-attack':
        def read_text(value, path):
            if path:
                with open(path) as handle:
                    return handle.read()
            return value or ''
        recorded = agent.record_attack(vars(args), read_text(args.request, args.request_file),
                                        read_text(args.response, args.response_file))
        return envelope(command, count=1, **recorded, next=[f"jeb-query.sh get {recorded['recorded']}"])
    where, post = build_where(args, collection), post_filters(args, collection)
    if collection == 'exchanges' and command == 'search':
        if args.text:
            raise ValueError('Source exchanges support exact filters/--contains; use behavior for semantic text.')
        found = agent.source_evidence(where, post, args.contains, args.offset, settings['n_results'])
    elif command == 'similar':
        if collection not in COLLECTIONS:
            raise ValueError('Use semantic search to discover behavior; observations use exact lookup.')
        found = agent.find_similar(args.target, n_results=settings['n_results'], where=where,
                                  post=post, snippet_len=settings['snippet_len'])
    elif command == 'search' and args.text:
        if args.offset:
            raise ValueError('--offset applies only to metadata listings without query text.')
        text = ' '.join(args.text)
        residue, rejected = screen_query(text, collection)
        if not residue:
            return envelope(command, results=[], query='', query_original=text,
                            rejected_terms=rejected, screening_action='removed-all',
                            notes=['Search protocol signals or query recorded attacks by vulnerability class.'],
                            next=['jeb-query.sh map', 'jeb-query.sh attacks'])
        found = agent.search(residue, where=where, post=post,
                             where_document={'$contains': args.contains} if args.contains else None,
                             max_distance=None if args.loose else 'default',
                             **{k: v for k, v in settings.items() if k != 'raw_chars'})
        found.update(query=residue, query_original=text, rejected_terms=rejected)
        if rejected:
            found['screening_action'] = 'removed-terms'
        if not found['results']:
            found['notes'] = ['No eligible candidate passed the cutoff.' if found['fallback'] else
                              'No matching evidence in the candidate set; try exact filters or a broader query.']
    else:
        key = (lambda r: (r[1].get('time', ''), r[0])) if command == 'attacks' else None
        found = agent.filter(where=where, post=post, n_results=settings['n_results'],
                             snippet_len=settings['snippet_len'], sort_key=key, reverse=command == 'attacks',
                             offset=getattr(args, 'offset', 0),
                             where_document={'$contains': args.contains} if getattr(args, 'contains', None) else None)
    return envelope(command, collection=collection, **found,
                    next=[f"jeb-query.sh get {r['id']}" for r in found['results'][:3]])


def build_parser():
    parser = argparse.ArgumentParser(description='J.E.B. Chroma-only capture investigation')
    sub = parser.add_subparsers(dest='command', required=True)
    for command in ('endpoint', 'map', 'search', 'get', 'similar', 'identifier', 'evidence', 'attacks', 'record-attack'):
        p = sub.add_parser(command)
        p.add_argument('--db-path', default='./chroma_db')
        if command in ('endpoint', 'get', 'similar', 'identifier', 'evidence'):
            p.add_argument('target')
        if command in ('identifier', 'evidence'):
            p.add_argument('--offset', type=int, default=0)
            p.add_argument('--limit', type=int, default=50)
        if command == 'evidence':
            p.add_argument('--signal', choices=('content', 'schema'))
        if command == 'get':
            p.add_argument('--original', action='store_true', help='include original HTTP base64')
        if command in ('search', 'get', 'similar'):
            p.add_argument('--in', dest='collection', choices=ADDRESSABLE if command in ('get', 'search') else COLLECTIONS)
        if command in ('endpoint', 'map', 'search', 'similar', 'attacks'):
            p.add_argument('--depth', choices=DEPTH, default='normal')
            p.add_argument('--limit', type=int)
            p.add_argument('--host')
            p.add_argument('--path')
        if command in ('map', 'search', 'attacks'):
            p.add_argument('--offset', type=int, default=0, help='metadata listing offset (no query text)')
            p.add_argument('--method', action='append')
            for field in ('status', 'kind', 'access-control', 'access-class', 'contains', 'where',
                          'vuln-class', 'verdict', 'severity'):
                p.add_argument('--' + field)
            for field in ('anon', 'auth', 'cors-open', 'include-static', 'anon-matches-auth', 'cookie-issues', 'jwt'):
                p.add_argument('--' + field, action='store_true')
            for field in ('param', 'cookie', 'missing-header'):
                p.add_argument('--' + field, action='append')
        if command == 'endpoint':
            p.add_argument('--method')
            p.add_argument('--no-raw', action='store_true')
            p.add_argument('--raw-chars', type=int)
        if command == 'search':
            p.add_argument('text', nargs='*')
            p.add_argument('--loose', action='store_true')
        if command == 'record-attack':
            p.add_argument('--event-id', help='idempotent caller event key; reuse only for identical inputs')
            for field in ('vuln-class', 'endpoint'):
                p.add_argument('--' + field, required=True)
            for field in ('method', 'param', 'payload', 'status', 'severity', 'source-id', 'evidence', 'tool',
                          'request', 'request-file', 'response', 'response-file'):
                p.add_argument('--' + field, default='')
            p.add_argument('--verdict', choices=('vulnerable', 'not_vulnerable', 'inconclusive'), default='inconclusive')
    return parser


def main():
    args = build_parser().parse_args()
    try:
        if args.command == 'record-attack':
            with writer_lock(args.db_path):
                result = execute(args)
        else:
            result = execute(args)
        if os.path.isdir(args.db_path):
            client = chromadb.PersistentClient(path=os.path.abspath(args.db_path))
            names = {c.name for c in client.list_collections()}
            if 'attacks_rebuild_backup' in names:
                result.setdefault('notes', []).append('Finding migration pending; resume import with --rebuild.')
                result['finding_migration_pending'] = True
            if 'captures' in names:
                captures = client.get_collection('captures', embedding_function=None)
                pending = [r['id'] for r in scan(captures)
                           if r['metadatas'].get('state') not in ('ready', 'complete', 'indexing', 'abandoned')]
                state = (captures.metadata or {}).get('index_state', 'unknown')
                if state != 'complete':
                    result.setdefault('notes', []).append(f'Derived index state: {state}; run project rebuild.')
                    result['index_state'] = state
                if pending:
                    result.setdefault('notes', []).append('Import incomplete; derived results may be partial. Resume the import.')
                    result['incomplete_captures'] = pending
        print(json.dumps(result, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps(envelope(args.command, results=[], error=str(exc))))
        return 2


if __name__ == '__main__':
    sys.exit(main())
