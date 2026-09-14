"""
J.E.B. v4 -- query / hunting interface.

Reads a per-project ChromaDB built by the jeb-import pipeline. Three collections:
  structure  the site map (endpoint templates, pages, actions, per-host auth model)
  behavior   distinct request/response behaviors (default)
  attacks    results of active testing (written here by `record-attack`)

The interface is subcommand-based: every invocation is
`jeb-query.sh <command> [target] [flags]`. Collections are inferred from the
command, retrieval tuning is collapsed into `--depth`, and metadata filtering is
expressed with named flags rather than raw Chroma JSON.

Searches embed the query with the same retrieval prompt the corpus was built
with. Because the vector is the distilled `embed_text` while the stored document
is the raw HTTP, `--contains "SameSite=None"` filters on the real header/cookie
text without bloating metadata.

The `structure` and `behavior` vectors describe protocol structure only. They
contain no vulnerability-class vocabulary, so such terms are screened out of a
query before it reaches either retriever (see `screen_query`). Vulnerability
classes live in `attacks` as the `vuln_class` metadata field.
"""
import argparse
import datetime
import json
import math
import os
import re
import sqlite3
import sys

import chromadb

_here = os.path.dirname(os.path.abspath(__file__))
for _candidate in (
    os.path.normpath(os.path.join(_here, "..", "..", "jeb-import", "scripts")),
    os.path.expanduser("~/.config/opencode/skill/jeb-import/scripts"),
):
    if os.path.isdir(_candidate):
        if _candidate not in sys.path:
            sys.path.insert(0, _candidate)
        break
if _here not in sys.path:
    sys.path.insert(0, _here)
from embedding import (EMBEDDING_PROFILE_METADATA, embed_documents, embed_query,
                       make_ollama_ef)  # noqa: E402
import distill as d  # noqa: E402

DEFAULT_DB_PATH = "./chroma_db"
SNIPPET_LEN_DEFAULT = 200
CANDIDATE_K_DEFAULT = 40
TOP_K_DEFAULT = 8
TOP_P_DEFAULT = 0.90
RRF_K = 60
PARENT_SCAN_CAP = 20000
SCAN_CAP_DEFAULT = 2000
COLLECTIONS = ('structure', 'behavior', 'attacks')
DEFAULT_MAX_DISTANCE = {'structure': 0.65, 'behavior': 0.70, 'attacks': 0.70}

# One knob replaces the eight retrieval-tuning flags. 'normal' reproduces the
# historical defaults exactly.
DEPTH = {
    'quick':  dict(candidate_k=20,  n_results=5,  top_p=0.80, min_results=2,
                   max_per_endpoint=1, snippet_len=120, raw_chars=0),
    'normal': dict(candidate_k=40,  n_results=8,  top_p=0.90, min_results=3,
                   max_per_endpoint=2, snippet_len=200, raw_chars=2000),
    'deep':   dict(candidate_k=120, n_results=25, top_p=None, min_results=5,
                   max_per_endpoint=4, snippet_len=400, raw_chars=8000),
}

# Facets surfaced in a result summary, per collection.
FACETS = {
    'structure': ['node_kind', 'scheme', 'host', 'port', 'endpoint_template',
                  'method', 'param_names', 'produces', 'status_codes',
                  'authenticated_ever', 'anon_allowed', 'anon_soft_denied',
                  'access_control', 'auth_mechanisms',
                  'cookies_sent', 'cookies_set', 'security_headers_missing', 'cors',
                  'instance_count', 'example_ids', 'entity_ids',
                  'schema_sig', 'identifier_field', 'produced_by', 'consumed_by'],
    'behavior': ['method', 'scheme', 'host', 'port', 'endpoint_template',
                  'status_code', 'resp_len', 'resp_content_type',
                  'resp_class', 'req_schema_sig', 'req_schema_keys',
                  'graphql_operation', 'variant_count', 'variant_ids',
                  'authenticated', 'auth_role', 'auth_mechanism', 'access_class',
                 'anon_matches_auth', 'param_names', 'req_features',
                 'cors', 'cookie_issues', 'set_cookies', 'jwt',
                 'security_headers_missing', 'redirect_location', 'instance_count'],
    'attacks': ['vuln_class', 'verdict', 'severity', 'host', 'endpoint_template',
                'method', 'param', 'status_code', 'source_behavior_id', 'time'],
}

# ---------------------------------------------------------------------------
# Vulnerability-class screening
# ---------------------------------------------------------------------------
# `structure` and `behavior` embed distilled protocol structure -- method,
# templated path, parameter names, status, content types, auth role/mechanism,
# cookie names and flags, missing security headers, CORS posture, JWT alg and
# claims. Vulnerability-class words appear nowhere in that vocabulary, so a
# query containing them lands past the collection's distance cutoff (returning
# nothing) while the lexical retriever OR-fires on whatever generic tokens are
# left (returning noise). They are stripped before either retriever sees them.
#
# `attacks` is deliberately exempt: `attack_embed_text` embeds `vuln_class` and
# `record_attack` writes it to metadata, so vulnerability vocabulary is real
# there and nowhere else.
VULN_TERMS = {
    'SQLi': ('sql injection', 'sql-injection', 'sqli', 'blind sql', 'nosql injection'),
    'XSS': ('cross site scripting', 'cross-site scripting', 'stored xss',
            'reflected xss', 'dom xss', 'xss'),
    'SSRF': ('server side request forgery', 'server-side request forgery', 'ssrf'),
    'IDOR': ('insecure direct object reference', 'broken object level authorization',
             'idor', 'bola'),
    'CSRF': ('cross site request forgery', 'cross-site request forgery', 'csrf', 'xsrf'),
    'XXE': ('xml external entity', 'xxe'),
    'RCE': ('remote code execution', 'command injection', 'code injection', 'rce'),
    'LFI': ('path traversal', 'directory traversal', 'local file inclusion',
            'remote file inclusion', 'lfi', 'rfi'),
    'SSTI': ('server side template injection', 'server-side template injection',
             'template injection', 'ssti'),
    'Deserialization': ('insecure deserialization', 'deserialization', 'deserialisation'),
    'OpenRedirect': ('open redirect', 'unvalidated redirect'),
    'BrokenAccessControl': ('broken access control', 'privilege escalation', 'privesc',
                            'authorization bypass', 'authorisation bypass', 'auth bypass'),
    '': ('vulnerabilities', 'vulnerability', 'vulnerable', 'exploitable', 'exploit',
         'attack vector', 'security flaw', 'pentest', 'payload'),
}
_ALIAS_TO_CLASS = {alias: cls for cls, aliases in VULN_TERMS.items() for alias in aliases}
# Longest alias first so "sql injection" is consumed before "sqli" can match a
# substring of it, and word-boundary guards so a legitimate "redirect" survives
# while "open redirect" does not.
_VULN_RE = re.compile(
    r'(?<![\w-])(' + '|'.join(
        re.escape(a) for a in sorted(_ALIAS_TO_CLASS, key=len, reverse=True)
    ) + r')(?![\w-])', re.IGNORECASE)

INDEX_CONTENT_NOTE = (
    "The structure and behavior collections index protocol structure only: methods, "
    "path templates, parameter names, status codes, content types, auth roles and "
    "mechanisms, cookie names and flags, missing security headers, CORS posture, and "
    "JWT alg/claims. Vulnerability-class words are not in that index and were removed "
    "before searching.")


def screen_query(query, collection_name):
    """Strip vulnerability-class jargon before it reaches either retriever.

    Returns (residue, rejected_terms, guidance):
      residue         the query with all matched spans removed, whitespace
                      collapsed; '' when nothing structural remains
      rejected_terms  the literal spans removed, in input order
      guidance        ready-to-run command suggestions
    No-op for the `attacks` collection, where vuln_class is a real field.
    """
    if not query or collection_name == 'attacks':
        return query or '', [], []
    rejected = [m.group(0) for m in _VULN_RE.finditer(query)]
    if not rejected:
        return query, [], []
    residue = re.sub(r'\s+', ' ', _VULN_RE.sub(' ', query)).strip(' ,;-')
    classes, seen = [], set()
    for term in rejected:
        cls = _ALIAS_TO_CLASS.get(term.lower(), '')
        if cls and cls not in seen:
            seen.add(cls)
            classes.append(cls)
    guidance = ["jeb-query.sh endpoint <path>  -- inspect a specific endpoint"]
    for cls in classes[:3]:
        guidance.append(f"jeb-query.sh attacks --vuln-class {cls}"
                        f"  -- findings already recorded for {cls}")
    guidance.append("jeb-query.sh search --in structure --anon"
                    "  -- endpoints that served data anonymously")
    return residue, rejected, guidance


class MissingCollection(Exception):
    def __init__(self, wanted, have):
        self.wanted = wanted
        self.have = have
        super().__init__(f"collection '{wanted}' not found")


class JebAgent:
    def __init__(self, db_path=DEFAULT_DB_PATH, collection_name="behavior",
                 create_if_missing=False):
        self.db_path = os.path.abspath(db_path)
        self.collection_name = collection_name
        self.ollama_ef = make_ollama_ef()
        self.client = chromadb.PersistentClient(path=self.db_path)
        self._parent_index_cache = None
        self._siblings = {}
        have = {c.name for c in self.client.list_collections()}
        if collection_name in have:
            self.collection = self.client.get_collection(
                collection_name, embedding_function=self.ollama_ef)
        elif create_if_missing:
            self.collection = self.client.create_collection(
                name=collection_name, embedding_function=self.ollama_ef,
                metadata=dict(EMBEDDING_PROFILE_METADATA))
        else:
            raise MissingCollection(collection_name, sorted(have))
        meta = self.collection.metadata or {}
        if any(meta.get(key) != value
               for key, value in EMBEDDING_PROFILE_METADATA.items()):
            raise ValueError(
                f"Collection '{collection_name}' does not match the current "
                "EmbeddingGemma profile. Delete chroma_db and re-run jeb-import.")

        # structure/behavior carry both 'parent' (canonical) and 'segment'
        # (semantic child) documents in one collection, distinguished by the
        # `granularity` metadata field; attacks has no segments.
        self.has_segments = collection_name in ('structure', 'behavior')

    # -- infrastructure ----------------------------------------------------

    def sibling(self, collection_name):
        """Lazily open another collection on the same client; None if absent."""
        if collection_name == self.collection_name:
            return self.collection
        if collection_name not in self._siblings:
            have = {c.name for c in self.client.list_collections()}
            self._siblings[collection_name] = (
                self.client.get_collection(collection_name,
                                           embedding_function=self.ollama_ef)
                if collection_name in have else None)
        return self._siblings[collection_name]

    def parent_index(self, refresh=False):
        """[(doc_id, metadata)] for every canonical doc in this collection.

        One `collection.get` with no embedding and no Ollama round-trip, memoised
        per process. This is what makes `endpoint` and every metadata-only
        listing a deterministic index scan rather than a vector search.
        """
        if self._parent_index_cache is not None and not refresh:
            return self._parent_index_cache
        kwargs = {'include': ['metadatas'], 'limit': PARENT_SCAN_CAP}
        if self.has_segments:
            kwargs['where'] = {'granularity': 'parent'}
        got = self.collection.get(**kwargs)
        rows = list(zip(got['ids'], [m or {} for m in got['metadatas']]))
        if len(rows) >= PARENT_SCAN_CAP:
            print(f"[jeb-query] Warning: capture has at least {PARENT_SCAN_CAP} "
                  f"canonical documents; scan truncated.", file=sys.stderr)
        self._parent_index_cache = rows
        return rows

    def get_many(self, ids, collection_name=None, include=('metadatas',)):
        """Batch .get by id. Missing ids are omitted rather than raising."""
        ids = [i for i in dict.fromkeys(ids) if i]
        if not ids:
            return {}
        collection = (self.collection if collection_name is None
                      else self.sibling(collection_name))
        if collection is None:
            return {}
        try:
            got = collection.get(ids=ids, include=list(include))
        except Exception as e:
            print(f"[jeb-query] Lookup failed: {e}", file=sys.stderr)
            return {}
        out = {}
        for idx, doc_id in enumerate(got['ids']):
            entry = {}
            if 'metadatas' in include:
                entry['metadata'] = (got['metadatas'] or [{}] * len(got['ids']))[idx] or {}
            if 'documents' in include:
                entry['document'] = (got['documents'] or [''] * len(got['ids']))[idx] or ''
            out[doc_id] = entry
        return out

    def _summarize(self, doc_id, meta, distance=None, snippet_len=SNIPPET_LEN_DEFAULT):
        kind = meta.get('doc_kind', self.collection_name)
        out = {'id': doc_id, 'doc_kind': kind}
        if distance is not None:
            out['distance'] = round(float(distance), 4)
        for f in FACETS.get(kind, FACETS.get(self.collection_name, [])):
            if meta.get(f, '') != '':
                out[f] = meta.get(f)
        if snippet_len:
            out['summary'] = (meta.get('summary', '') or '')[:snippet_len]
        return out

    @staticmethod
    def _and_where(where, extra):
        return {"$and": [where, extra]} if where else extra

    @staticmethod
    def _fts_query(query, op='OR'):
        terms = re.findall(r"[A-Za-z0-9_{}.-]+", query)
        joiner = f" {op} "
        return joiner.join('"' + term.replace('"', '""') + '"'
                           for term in terms[:20])

    def _lexical_candidates(self, query, collection_name, limit, op='OR'):
        path = os.path.join(self.db_path, 'jeb_lexical.sqlite')
        fts_query = self._fts_query(query, op)
        if not os.path.exists(path) or not fts_query:
            return []
        try:
            with sqlite3.connect(path) as conn:
                rows = conn.execute(
                    "SELECT parent_id, bm25(retrieval_fts) AS rank_score "
                    "FROM retrieval_fts WHERE retrieval_fts MATCH ? "
                    "AND collection_name = ? ORDER BY rank_score LIMIT ?",
                    (fts_query, collection_name, limit),
                ).fetchall()
        except (sqlite3.Error, OSError) as e:
            print(f"[jeb-query] Lexical retrieval unavailable: {e}", file=sys.stderr)
            return []
        seen, out = set(), []
        for parent_id, _ in rows:
            if parent_id not in seen:
                seen.add(parent_id)
                out.append(parent_id)
        return out

    def _upsert_lexical(self, doc_id, collection_name, text, parent_id=None):
        path = os.path.join(self.db_path, 'jeb_lexical.sqlite')
        try:
            with sqlite3.connect(path) as conn:
                conn.execute(
                    "CREATE VIRTUAL TABLE IF NOT EXISTS retrieval_fts USING fts5("
                    "doc_id UNINDEXED, collection_name UNINDEXED, "
                    "parent_id UNINDEXED, text)"
                )
                conn.execute(
                    "DELETE FROM retrieval_fts WHERE doc_id = ? AND collection_name = ?",
                    (doc_id, collection_name),
                )
                conn.execute(
                    "INSERT INTO retrieval_fts(doc_id, collection_name, parent_id, text) "
                    "VALUES (?, ?, ?, ?)",
                    (doc_id, collection_name, parent_id or doc_id, text),
                )
        except (sqlite3.Error, OSError) as e:
            print(f"[jeb-query] Could not update lexical index: {e}", file=sys.stderr)

    def _upsert_identifiers(self, doc_id, collection_name, pairs):
        """Mirror `vector_store.update_identifier_index` for docs written at query
        time, so an attack recorded against /users/42 is findable by
        `identifier 42` alongside the behavior docs that touched the same record."""
        path = os.path.join(self.db_path, 'jeb_lexical.sqlite')
        try:
            with sqlite3.connect(path) as conn:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS identifier_index ("
                    "value TEXT, field TEXT, doc_id TEXT, collection_name TEXT)"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_identifier_value "
                    "ON identifier_index(value)"
                )
                conn.execute(
                    "DELETE FROM identifier_index WHERE doc_id = ? AND collection_name = ?",
                    (doc_id, collection_name),
                )
                conn.executemany(
                    "INSERT INTO identifier_index(value, field, doc_id, collection_name) "
                    "VALUES (?, ?, ?, ?)",
                    [(value, field, doc_id, collection_name) for field, value in pairs],
                )
        except (sqlite3.Error, OSError) as e:
            print(f"[jeb-query] Could not update identifier index: {e}", file=sys.stderr)

    def _eligible_parents(self, parent_ids, where, where_document):
        if not parent_ids:
            return {}
        kwargs = {'ids': parent_ids, 'include': ['metadatas']}
        if where:
            kwargs['where'] = where
        if where_document:
            kwargs['where_document'] = where_document
        got = self.collection.get(**kwargs)
        return {doc_id: meta or {}
                for doc_id, meta in zip(got['ids'], got['metadatas'])}

    # -- metadata-only listing --------------------------------------------

    def filter(self, where=None, where_document=None, n_results=TOP_K_DEFAULT,
               snippet_len=SNIPPET_LEN_DEFAULT, scan_cap=SCAN_CAP_DEFAULT,
               post=None, sort_key=None):
        """Metadata-only listing: no embedding, no query text, no Ollama call.

        Always constrains to canonical docs. Without that clause a filter such as
        `{"anon_allowed": true}` would return the parent *and* both of its
        semantic segments, since segments inherit the parent's metadata.
        """
        kwargs = {'include': ['metadatas'], 'limit': max(1, int(scan_cap))}
        effective = (self._and_where(where, {'granularity': 'parent'})
                     if self.has_segments else where)
        if effective:
            kwargs['where'] = effective
        if where_document:
            kwargs['where_document'] = where_document
        got = self.collection.get(**kwargs)
        rows = [(doc_id, meta or {})
                for doc_id, meta in zip(got['ids'], got['metadatas'])]
        for predicate in (post or []):
            rows = [r for r in rows if predicate(r[1])]

        matched_variants = {}
        if self.collection_name == 'behavior' and (where or where_document or post):
            variant_where = self._and_where(where, {'granularity': 'variant'})
            variant_kwargs = {'include': ['metadatas'], 'limit': max(1, int(scan_cap)),
                              'where': variant_where}
            if where_document:
                variant_kwargs['where_document'] = where_document
            variants = self.collection.get(**variant_kwargs)
            variant_parent_ids = []
            for variant_id, meta in zip(variants['ids'], variants['metadatas']):
                meta = meta or {}
                if all(predicate(meta) for predicate in (post or [])):
                    parent_id = meta.get('parent_id', '')
                    variant_parent_ids.append(parent_id)
                    matched_variants.setdefault(parent_id, []).append(variant_id)
            existing_ids = {doc_id for doc_id, _meta in rows}
            variant_parents = self.get_many(variant_parent_ids)
            rows.extend((doc_id, entry['metadata'])
                        for doc_id, entry in variant_parents.items()
                        if doc_id not in existing_ids)
        total = len(rows)
        key = sort_key or (lambda item: (-int(item[1].get('instance_count', 0) or 0),
                                         item[0]))
        rows.sort(key=key)
        results = [self._summarize(doc_id, meta, None, snippet_len)
                   for doc_id, meta in rows[:max(1, int(n_results))]]
        for result in results:
            if result['id'] in matched_variants:
                result['matched_variants'] = matched_variants[result['id']]
        return {'results': results, 'total': total}

    # -- hybrid search -----------------------------------------------------

    def search(self, query, n_results=TOP_K_DEFAULT, where=None, where_document=None,
               snippet_len=SNIPPET_LEN_DEFAULT, candidate_k=CANDIDATE_K_DEFAULT,
               max_distance=None, min_score=0.0, top_p=TOP_P_DEFAULT,
               min_results=3, max_per_endpoint=2, post=None):
        top_k = max(1, min(int(n_results), 100))
        candidate_k = max(top_k, min(int(candidate_k), 200))
        min_score = max(0.0, min(float(min_score), 1.0))
        if top_p is not None:
            top_p = max(0.0, min(float(top_p), 1.0))
        min_results = max(1, min(int(min_results), top_k))
        lexical_collection = self.collection_name

        kwargs = {'n_results': candidate_k,
                  'include': ['metadatas', 'distances']}
        if self.has_segments:
            # Entity nodes have no semantic children, so a segment-only filter
            # would make them dense-unreachable. Existing v4 databases predate
            # the ingest-side fix, so admit them by node_kind as well.
            granularity = ({'$or': [{'granularity': 'segment'},
                                    {'node_kind': 'entity'}]}
                           if self.collection_name == 'structure'
                           else {'$or': [{'granularity': 'segment'},
                                        {'granularity': 'variant'}]})
            kwargs['where'] = self._and_where(where, granularity)
        elif where:
            kwargs['where'] = where
        if where_document and not self.has_segments:
            kwargs['where_document'] = where_document
        kwargs['query_embeddings'] = [embed_query(
            self.ollama_ef, self.collection_name, query)]
        dense = self.collection.query(**kwargs)

        if max_distance is None:
            max_distance = DEFAULT_MAX_DISTANCE.get(self.collection_name)

        diag = {'dense_candidates': 0, 'dropped_by_distance': 0,
                'lexical_candidates': 0, 'eligible_after_filter': 0,
                'dropped_by_diversity': 0}

        def merge_dense(results, source, into, maxd, count=False):
            if not results['ids']:
                return
            for rank, (doc_id, meta, distance) in enumerate(zip(
                    results['ids'][0], results['metadatas'][0],
                    results['distances'][0]), 1):
                distance = float(distance)
                if count:
                    diag['dense_candidates'] += 1
                if maxd is not None and distance > maxd:
                    if count:
                        diag['dropped_by_distance'] += 1
                    continue
                parent_id = (meta or {}).get('parent_id', doc_id)
                entry = into.setdefault(parent_id, {
                    'rrf': 0.0, 'distance': distance, 'sources': set(),
                    'representations': set(), 'matched_ids': set(),
                })
                if source not in entry['sources']:
                    entry['rrf'] += 1.0 / (RRF_K + rank)
                entry['distance'] = min(entry['distance'], distance)
                entry['sources'].add(source)
                entry['matched_ids'].add(doc_id)
                representation = (meta or {}).get('representation')
                if representation:
                    entry['representations'].add(representation)

        candidates = {}
        merge_dense(dense, 'dense', candidates, max_distance, count=True)
        raw_filter = None
        if where_document and self.has_segments:
            raw_kwargs = {'n_results': candidate_k,
                          'include': ['metadatas', 'distances'],
                          'where_document': where_document,
                          'where': self._and_where(
                              where, {'$or': [{'granularity': 'parent'},
                                             {'granularity': 'variant'}]})}
            raw_kwargs['query_embeddings'] = [embed_query(
                self.ollama_ef, self.collection_name, query)]
            raw_filter = self.collection.query(**raw_kwargs)
            merge_dense(raw_filter, 'dense_raw_filter', candidates, max_distance,
                        count=True)

        lexical = self._lexical_candidates(
            query, lexical_collection, min(candidate_k * 5, 500))
        lexical = lexical[:candidate_k]
        diag['lexical_candidates'] = len(lexical)
        for rank, parent_id in enumerate(lexical, 1):
            entry = candidates.setdefault(parent_id, {
                'rrf': 0.0, 'distance': None, 'sources': set(),
                'representations': set(), 'matched_ids': set(),
            })
            entry['rrf'] += 1.0 / (RRF_K + rank)
            entry['sources'].add('lexical')

        ranked = self._rank(candidates, query, where, where_document, post)
        diag['eligible_after_filter'] = len(ranked)

        fallback = []
        if not ranked and diag['dropped_by_distance']:
            # The candidates are already in memory; only the merge is re-run, so
            # this costs no extra embedding call.
            loose = {}
            merge_dense(dense, 'dense', loose, None)
            if raw_filter is not None:
                merge_dense(raw_filter, 'dense_raw_filter', loose, None)
            loose_ranked = self._rank(loose, query, where, where_document, post)
            fallback = [self._as_result(e, snippet_len) for e in loose_ranked[:3]]

        if not ranked:
            return {'results': [], 'diagnostics': diag, 'fallback': fallback}

        best = ranked[0]['raw_score'] or 1.0
        ranked = [r for r in ranked if (r.setdefault('score', r['raw_score'] / best)
                                        >= min_score)]

        diverse, endpoint_counts = [], {}
        for entry in ranked:
            meta = entry['metadata']
            key = (meta.get('host', ''), meta.get('endpoint_template', ''))
            if max_per_endpoint > 0 and endpoint_counts.get(key, 0) >= max_per_endpoint:
                diag['dropped_by_diversity'] += 1
                continue
            endpoint_counts[key] = endpoint_counts.get(key, 0) + 1
            diverse.append(entry)

        total_mass = sum(r['score'] for r in diverse[:top_k]) or 1.0
        selected, cumulative = [], 0.0
        for entry in diverse[:top_k]:
            selected.append(entry)
            cumulative += entry['score'] / total_mass
            if len(selected) >= min_results and (top_p is None or cumulative >= top_p):
                break

        return {'results': [self._as_result(e, snippet_len) for e in selected],
                'diagnostics': diag, 'fallback': []}

    def _rank(self, candidates, query, where, where_document, post=None):
        eligible = self._eligible_parents(list(candidates), None, None)
        matching_children = {}
        for parent_id, candidate in candidates.items():
            child_ids = [doc_id for doc_id in candidate.get('matched_ids', set())
                         if doc_id != parent_id]
            if not child_ids:
                continue
            kwargs = {'ids': child_ids, 'include': ['metadatas']}
            if where:
                kwargs['where'] = where
            if where_document:
                kwargs['where_document'] = where_document
            got = self.collection.get(**kwargs)
            matched = [doc_id for doc_id, meta in zip(got['ids'], got['metadatas'])
                       if (meta or {}).get('granularity') == 'variant'
                       and all(predicate(meta or {}) for predicate in (post or []))]
            if matched:
                matching_children[parent_id] = matched
        query_terms = {t.lower() for t in re.findall(r"[A-Za-z0-9_{}.-]+", query)}
        ranked = []
        for parent_id, meta in eligible.items():
            parent_matches = True
            if where or where_document:
                parent_matches = parent_id in self._eligible_parents(
                    [parent_id], where, where_document)
            child_matches = matching_children.get(parent_id, [])
            if not parent_matches and not child_matches:
                continue
            if any(not predicate(meta) for predicate in (post or [])) and not child_matches:
                continue
            entry = candidates[parent_id]
            facet_text = " ".join(str(meta.get(field, '')) for field in (
                'host', 'endpoint_template', 'method', 'param_names', 'summary'))
            facet_terms = {t.lower() for t in re.findall(
                r"[A-Za-z0-9_{}.-]+", facet_text)}
            overlap = len(query_terms & facet_terms) / max(len(query_terms), 1)
            entry['raw_score'] = entry['rrf'] + 0.01 * overlap
            entry['id'] = parent_id
            entry['metadata'] = meta
            if child_matches:
                entry['matched_variants'] = child_matches
            ranked.append(entry)
        ranked.sort(key=lambda x: (-x['raw_score'],
                                   x['distance'] if x['distance'] is not None else math.inf,
                                   x['id']))
        return ranked

    def _as_result(self, entry, snippet_len):
        item = self._summarize(entry['id'], entry['metadata'],
                               entry['distance'], snippet_len)
        item['score'] = round(entry.get('score', entry['raw_score']), 4)
        item['sources'] = sorted(entry['sources'])
        if entry['representations']:
            item['representations'] = sorted(entry['representations'])
        if entry.get('matched_variants'):
            item['matched_variants'] = entry['matched_variants']
        return item

    # -- pivots ------------------------------------------------------------

    def find_similar(self, doc_id, n_results=5, where=None, where_document=None,
                     snippet_len=SNIPPET_LEN_DEFAULT, post=None):
        seed = self.collection.get(ids=[doc_id],
                                   include=['embeddings', 'metadatas'])
        if not seed['ids']:
            return {'error': f"Seed id {doc_id} not found in '{self.collection_name}'."}
        seed_meta = (seed['metadatas'] or [{}])[0] or {}
        kwargs = {'query_embeddings': [seed['embeddings'][0]],
                  'n_results': max(n_results * 3, n_results + 1),
                  'include': ['metadatas', 'distances']}
        # Without this the nearest neighbours of a canonical doc are its own
        # semantic children, whose ids are not addressable by `get`.
        effective = where
        if self.has_segments and seed_meta.get('granularity', 'parent') == 'parent':
            effective = self._and_where(where, {'granularity': 'parent'})
        if effective:
            kwargs['where'] = effective
        if where_document:
            kwargs['where_document'] = where_document
        res = self.collection.query(**kwargs)
        out, seen = [], {doc_id}
        if res['ids']:
            for i in range(len(res['ids'][0])):
                rid = res['ids'][0][i]
                meta = res['metadatas'][0][i] or {}
                parent_id = meta.get('parent_id', rid)
                if parent_id in seen:
                    continue
                if any(not predicate(meta) for predicate in (post or [])):
                    continue
                seen.add(parent_id)
                out.append(self._summarize(parent_id, meta,
                                           res['distances'][0][i], snippet_len))
                if len(out) >= n_results:
                    break
        return {'results': out}

    def find_by_identifier(self, value, limit=50):
        """Exact-match lookup across every collection for a concrete id/uuid/hash
        value (e.g. a user id) seen in a URL path or a JSON field named like an
        identifier. This is the instance-level counterpart to schema-based
        `entity` correlation in `structure`: two different endpoints sharing
        the same identifier value are very likely operating on the same
        underlying record."""
        path = os.path.join(self.db_path, 'jeb_lexical.sqlite')
        if not os.path.exists(path):
            return []
        try:
            with sqlite3.connect(path) as conn:
                rows = conn.execute(
                    "SELECT DISTINCT doc_id, collection_name, field "
                    "FROM identifier_index WHERE value = ? LIMIT ?",
                    (value, limit),
                ).fetchall()
        except sqlite3.Error as e:
            print(f"[jeb-query] Identifier lookup unavailable: {e}", file=sys.stderr)
            return []
        return [{'id': doc_id, 'collection': coll, 'field': field}
                for doc_id, coll, field in rows]

    def get_full(self, doc_id):
        res = self.collection.get(ids=[doc_id], include=['documents', 'metadatas'])
        if not res['ids']:
            return {'error': f"id {doc_id} not found in '{self.collection_name}'."}
        return {'id': doc_id, 'metadata': res['metadatas'][0],
                'document': res['documents'][0]}

    def record_attack(self, m, request_text, response_text):
        endpoint = m.get('endpoint', '')
        parsed = d.urlparse(endpoint)
        host = (parsed.hostname or '') if parsed.scheme else ''
        path = parsed.path if parsed.scheme else endpoint
        template = d.templatize_path(path)
        now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
        record = {
            'vuln_class': m.get('vuln_class', ''),
            'method': m.get('method', ''),
            'endpoint_template': template,
            'param': m.get('param', ''),
            'payload': m.get('payload', ''),
            'status_code': d._to_int(m.get('status', '')),
            'evidence': m.get('evidence', ''),
            'verdict': m.get('verdict', 'inconclusive'),
        }
        embed_text = d.attack_embed_text(record)
        summary = d.attack_summary(record)
        page_content = (f"ATTACK {record['vuln_class']} | {record['method']} {endpoint} "
                        f"| param={record['param']} | verdict={record['verdict']} "
                        f"| severity={m.get('severity','')}\npayload: {record['payload']}\n"
                        f"evidence: {record['evidence']}\n\n--- REQUEST ---\n{request_text}"
                        f"\n\n--- RESPONSE ---\n{response_text}")
        metadata = {
            'doc_kind': 'attack', 'host': host, 'endpoint_template': template,
            'method': record['method'], 'param': record['param'],
            'vuln_class': record['vuln_class'], 'verdict': record['verdict'],
            'severity': m.get('severity', ''), 'status_code': record['status_code'],
            'source_behavior_id': m.get('source_id', ''),
            'payload': record['payload'], 'tool': m.get('tool', ''),
            'time': now, 'granularity': 'parent', 'summary': summary,
        }
        doc_id = d.md5(f"{now}|{template}|{record['param']}|{record['payload']}")
        embedding = embed_documents(self.ollama_ef, [embed_text])[0]
        self.collection.upsert(ids=[doc_id], documents=[page_content],
                               metadatas=[metadata], embeddings=[embedding])
        self._upsert_lexical(doc_id, 'attacks', embed_text)
        self._upsert_identifiers(doc_id, 'attacks',
                                 d.extract_identifier_values(
                                     path, [request_text, response_text]))
        return {'recorded': doc_id, 'summary': summary}


# ---------------------------------------------------------------------------
# Filter compilation
# ---------------------------------------------------------------------------
# `--cors` values are stored differently per collection: build_behavior appends
# " creds" when Access-Control-Allow-Credentials is set, build_structure stores
# the bare posture. An equality filter therefore silently misses the credentialed
# case -- the interesting one -- so `--cors-open` enumerates both spellings.
CORS_OPEN = {
    'behavior': ["*", "* creds", "reflected", "reflected creds", "null", "null creds"],
    'structure': ["*", "reflected", "null"],
}


def _csv_tokens(value):
    return {t.strip().lower() for t in str(value or '').split(',') if t.strip()}


def _status_clause(spec):
    """Accepts 500, '>=500', '<400', '500-599' and '5xx'."""
    spec = str(spec).strip()
    m = re.fullmatch(r'([<>]=?)\s*(\d{3})', spec)
    if m:
        op = {'>': '$gt', '>=': '$gte', '<': '$lt', '<=': '$lte'}[m.group(1)]
        return {'status_code': {op: int(m.group(2))}}
    m = re.fullmatch(r'(\d{3})\s*-\s*(\d{3})', spec)
    if m:
        return {"$and": [{'status_code': {'$gte': int(m.group(1))}},
                         {'status_code': {'$lte': int(m.group(2))}}]}
    m = re.fullmatch(r'(\d)xx', spec, re.IGNORECASE)
    if m:
        low = int(m.group(1)) * 100
        return {"$and": [{'status_code': {'$gte': low}},
                         {'status_code': {'$lte': low + 99}}]}
    if re.fullmatch(r'\d{3}', spec):
        return {'status_code': int(spec)}
    raise ValueError(f"--status: expected 500, '>=500', '500-599' or '5xx', got {spec!r}")


def build_where(args, collection_name):
    """AND-compose the named facet flags into a Chroma `where`.

    Returns None when there are no clauses and the bare clause (never a
    single-element `$and`) when there is exactly one -- Chroma rejects both an
    empty dict and, in some versions, a one-element `$and`.
    """
    clauses = []
    get = lambda name: getattr(args, name, None)  # noqa: E731

    if get('host'):
        clauses.append({'host': args.host})
    if get('method'):
        methods = [m.upper() for m in args.method]
        clauses.append({'method': methods[0]} if len(methods) == 1
                       else {'method': {'$in': methods}})
    if get('status'):
        if collection_name == 'structure':
            raise ValueError("--status applies to behavior/attacks; structure nodes "
                             "carry status_codes as a csv string")
        clauses.append(_status_clause(args.status))
    if get('kind'):
        clauses.append({'node_kind': args.kind})
    if get('access_control'):
        clauses.append({'access_control': args.access_control})
    if get('access_class'):
        clauses.append({'access_class': args.access_class})
    if get('anon_matches_auth'):
        clauses.append({'anon_matches_auth': True})
    if get('anon'):
        clauses.append({'anon_allowed': True} if collection_name == 'structure'
                       else {'authenticated': False})
    if get('auth'):
        clauses.append({'authenticated_ever': True} if collection_name == 'structure'
                       else {'authenticated': True})
    if get('cors_open') and collection_name in CORS_OPEN:
        clauses.append({'cors': {'$in': CORS_OPEN[collection_name]}})
    if get('raw_where'):
        clauses.append(args.raw_where)
    if get('vuln_class'):
        clauses.append({'vuln_class': args.vuln_class})
    if get('verdict'):
        clauses.append({'verdict': args.verdict})
    if get('severity'):
        clauses.append({'severity': args.severity})
    # Static assets are js/css/image noise for every question this tool answers,
    # so they are excluded unless explicitly asked for.
    if collection_name in ('structure', 'behavior') and not get('include_static'):
        clauses.append({'is_static': False})

    if not clauses:
        return None
    return clauses[0] if len(clauses) == 1 else {"$and": clauses}


def post_filters(args, collection_name):
    """Client-side predicates over metadata, for csv-valued fields Chroma cannot
    substring-match and for `--path` scoping."""
    preds = []
    get = lambda name: getattr(args, name, None)  # noqa: E731

    for name in (get('param') or []):
        wanted = name.strip().lower()
        preds.append(lambda meta, w=wanted: w in _csv_tokens(meta.get('param_names')))
    for name in (get('cookie') or []):
        wanted = name.strip().lower()

        def cookie_pred(meta, w=wanted):
            blob = ",".join(str(meta.get(f, '')) for f in
                            ('cookie_names', 'cookies_sent', 'set_cookies', 'cookies_set'))
            return w in blob.lower()
        preds.append(cookie_pred)
    for name in (get('missing_header') or []):
        wanted = name.strip().lower()
        preds.append(lambda meta, w=wanted:
                     w in _csv_tokens(meta.get('security_headers_missing')))
    if get('cookie_issues'):
        preds.append(lambda meta: bool(str(meta.get('cookie_issues', '') or '').strip()))
    if get('jwt'):
        preds.append(lambda meta: bool(str(meta.get('jwt', '') or '').strip()))
    if get('path'):
        # Scoping to a path means that route and its subtree -- not its siblings,
        # which classify_match also reports for the `endpoint` report's benefit.
        import endpoint_report as er
        target = er.normalize_target(args.path)
        preds.append(lambda meta, t=target: er.classify_match(t, meta) in
                     ('exact', 'template', 'descendant'))
    return preds


def resolve_depth(args):
    """DEPTH preset with any explicit override applied on top."""
    settings = dict(DEPTH[getattr(args, 'depth', 'normal') or 'normal'])
    for name in ('candidate_k', 'n_results', 'top_p', 'min_results',
                 'max_per_endpoint', 'snippet_len', 'raw_chars'):
        value = getattr(args, name, None)
        if value is not None:
            settings[name] = value
    if getattr(args, 'limit', None) is not None:
        settings['n_results'] = args.limit
    if getattr(args, 'no_raw', False):
        settings['raw_chars'] = 0
    return settings


# ---------------------------------------------------------------------------
# Output envelope
# ---------------------------------------------------------------------------
def envelope(command, **fields):
    """Every subcommand answers with an object carrying at least `command`,
    `count` and `next`, so an agent can tell 'no results' apart from 'wrong
    command' without guessing."""
    out = {'command': command}
    out.update({k: v for k, v in fields.items() if v not in (None, [], {})})
    out.setdefault('count', len(fields.get('results') or []))
    # `results` and `next` are always present, even when empty, so a caller can
    # index them without a membership test.
    if 'results' in fields and 'results' not in out:
        out['results'] = []
    out.setdefault('next', [])
    return out


def emit(payload):
    print(json.dumps(payload, indent=2, default=str))
    return 0


def resolve_collection(db_path, doc_id, preferred=None):
    """Find which collection holds `doc_id`, so the agent never has to say."""
    client = chromadb.PersistentClient(path=os.path.abspath(db_path))
    have = [c.name for c in client.list_collections()]
    order = ([preferred] if preferred in have else []) + \
            [n for n in COLLECTIONS if n in have and n != preferred]
    ef = make_ollama_ef()
    for name in order:
        try:
            got = client.get_collection(name, embedding_function=ef).get(
                ids=[doc_id], include=[])
        except Exception:
            continue
        if got['ids']:
            return name
    return None


def open_agent(args, collection_name, create=False):
    return JebAgent(db_path=args.db_path, collection_name=collection_name,
                    create_if_missing=create)


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------
def cmd_endpoint(args):
    import endpoint_report as er
    agent = open_agent(args, 'structure')
    settings = resolve_depth(args)
    report = er.build_report(agent, args.target, host=args.host, method=args.method,
                             depth=args.depth or 'normal',
                             raw_chars=settings['raw_chars'])
    return emit(report)


def cmd_map(args):
    agent = open_agent(args, 'structure')
    settings = resolve_depth(args)
    where = build_where(args, 'structure')
    result = agent.filter(where=where, n_results=settings['n_results'],
                          snippet_len=settings['snippet_len'],
                          post=post_filters(args, 'structure'),
                          sort_key=lambda item: (item[1].get('host', ''),
                                                 item[1].get('endpoint_template', ''),
                                                 item[1].get('method', '')))
    return emit(envelope('map', collection='structure',
                         filter={'where': where},
                         count=len(result['results']), total=result['total'],
                         results=result['results'],
                         next=["jeb-query.sh endpoint <path>",
                               "jeb-query.sh map --kind auth_model",
                               "jeb-query.sh search --in structure --anon"]))


def cmd_search(args):
    collection = args.collection
    agent = open_agent(args, collection)
    settings = resolve_depth(args)
    where = build_where(args, collection)
    where_document = {"$contains": args.contains} if args.contains else None
    post = post_filters(args, collection)
    text = " ".join(args.text or []).strip()

    if not text:
        # A metadata-only listing is a first-class query, not a degenerate search.
        result = agent.filter(where=where, where_document=where_document,
                              n_results=settings['n_results'],
                              snippet_len=settings['snippet_len'], post=post)
        return emit(envelope('search', collection=collection,
                             filter={'where': where, 'where_document': where_document},
                             count=len(result['results']), total=result['total'],
                             results=result['results'],
                             next=["jeb-query.sh endpoint <path>",
                                   "jeb-query.sh get <id>"]))

    residue, rejected, guidance = screen_query(text, collection)
    notes = []
    if rejected:
        notes.append(INDEX_CONTENT_NOTE)
        notes.append("Recorded findings, which do carry a vuln_class, live in the "
                     "attacks collection.")
    if not residue:
        return emit(envelope(
            'search', collection=collection, query='', query_original=text,
            rejected_terms=rejected, count=0, results=[],
            notes=notes + ["Nothing structural remained after removing "
                           "vulnerability-class terms."],
            next=guidance))

    found = agent.search(residue, n_results=settings['n_results'], where=where,
                         where_document=where_document,
                         snippet_len=settings['snippet_len'],
                         candidate_k=settings['candidate_k'],
                         max_distance=None if args.loose else args.max_distance,
                         min_score=args.min_score or 0.0,
                         top_p=settings['top_p'],
                         min_results=settings['min_results'],
                         max_per_endpoint=settings['max_per_endpoint'],
                         post=post)
    nxt = list(guidance) if rejected else []
    if not found['results']:
        notes.append("No result cleared the relevance threshold for this collection. "
                     "`fallback` shows the closest matches with the cutoff disabled.")
        nxt = nxt or ["jeb-query.sh search <text> --loose",
                      "jeb-query.sh endpoint <path>",
                      "jeb-query.sh map"]
    else:
        nxt = nxt or ["jeb-query.sh get <id>", "jeb-query.sh similar <id>"]
    return emit(envelope('search', collection=collection,
                         query=residue, query_original=text,
                         rejected_terms=rejected,
                         filter={'where': where, 'where_document': where_document},
                         count=len(found['results']), results=found['results'],
                         diagnostics=found['diagnostics'],
                         fallback=found['fallback'], notes=notes, next=nxt))


def cmd_attacks(args):
    agent = open_agent(args, 'attacks')
    settings = resolve_depth(args)
    where = build_where(args, 'attacks')
    result = agent.filter(where=where, n_results=settings['n_results'],
                          snippet_len=settings['snippet_len'],
                          post=post_filters(args, 'attacks'),
                          sort_key=lambda item: (str(item[1].get('time', '')),
                                                 item[0]))
    result['results'].reverse()  # newest first
    return emit(envelope('attacks', collection='attacks',
                         filter={'where': where},
                         count=len(result['results']), total=result['total'],
                         results=result['results'],
                         next=["jeb-query.sh get <id>",
                               "jeb-query.sh endpoint <endpoint_template>"]))


def cmd_get(args):
    collection = args.collection or resolve_collection(args.db_path, args.target)
    if collection is None:
        return emit(envelope('get', count=0, results=[],
                             notes=[f"id {args.target} is not in any collection of "
                                    f"{os.path.abspath(args.db_path)}."],
                             next=["jeb-query.sh map", "jeb-query.sh endpoint <path>"]))
    agent = open_agent(args, collection)
    doc = agent.get_full(args.target)
    return emit(envelope('get', collection=collection, count=1, document=doc,
                         next=["jeb-query.sh similar <id>",
                               "jeb-query.sh identifier <value>"]))


def cmd_similar(args):
    collection = args.collection or resolve_collection(args.db_path, args.target)
    if collection is None:
        return emit(envelope('similar', count=0, results=[],
                             notes=[f"id {args.target} is not in any collection of "
                                    f"{os.path.abspath(args.db_path)}."],
                             next=["jeb-query.sh map"]))
    agent = open_agent(args, collection)
    settings = resolve_depth(args)
    where = build_where(args, collection)
    found = agent.find_similar(args.target, n_results=settings['n_results'],
                               where=where,
                               snippet_len=settings['snippet_len'],
                               post=post_filters(args, collection))
    if 'error' in found:
        return emit(envelope('similar', collection=collection, count=0, results=[],
                             notes=[found['error']], next=["jeb-query.sh map"]))
    return emit(envelope('similar', collection=collection,
                         count=len(found['results']), results=found['results'],
                         next=["jeb-query.sh get <id>"]))


def cmd_identifier(args):
    for name in COLLECTIONS:
        try:
            agent = open_agent(args, name)
            break
        except MissingCollection:
            continue
    else:
        raise MissingCollection('structure', [])
    hits = agent.find_by_identifier(args.target)
    return emit(envelope('identifier', value=args.target,
                         count=len(hits), results=hits,
                         notes=[] if hits else
                         [f"No document referenced the value {args.target!r}. "
                          f"Identifiers are harvested from URL path segments and "
                          f"JSON fields named id/*_id/uuid/guid."],
                         next=["jeb-query.sh get <id>  -- read each hit in full"]))


def _read(val, path):
    if path:
        with open(path) as f:
            return f.read()
    return val or ''


def cmd_record_attack(args):
    agent = open_agent(args, 'attacks', create=True)
    m = {'vuln_class': args.vuln_class, 'endpoint': args.endpoint,
         'method': args.method, 'param': args.param, 'payload': args.payload,
         'status': args.status, 'verdict': args.verdict, 'severity': args.severity,
         'source_id': args.source_id, 'evidence': args.evidence, 'tool': args.tool}
    req = _read(args.request, args.request_file)
    resp = _read(args.response, args.response_file)
    recorded = agent.record_attack(m, req, resp)
    return emit(envelope('record-attack', collection='attacks', count=1,
                         recorded=recorded['recorded'], summary=recorded['summary'],
                         next=[f"jeb-query.sh attacks --vuln-class {args.vuln_class}",
                               "jeb-query.sh get <id>"]))


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
def _add_common(p):
    p.add_argument('--db-path', default=DEFAULT_DB_PATH,
                   help="project ChromaDB (default: ./chroma_db)")


def _add_depth(p):
    p.add_argument('--depth', choices=list(DEPTH), default='normal',
                   help="how much to return: quick | normal | deep")
    p.add_argument('--limit', type=int, default=None,
                   help="maximum results (overrides --depth)")
    # Retrieval internals. Functional, but deliberately undocumented: --depth
    # covers every case an agent should be reasoning about.
    for flag, kind in (('--candidate-k', int), ('--n-results', int),
                       ('--top-p', float), ('--min-results', int),
                       ('--max-per-endpoint', int), ('--snippet-len', int),
                       ('--max-distance', float), ('--min-score', float)):
        p.add_argument(flag, type=kind, default=None, help=argparse.SUPPRESS)


def _add_facets(p, *, structure=False, behavior=False, attacks=False):
    p.add_argument('--host', help="restrict to one host")
    p.add_argument('--method', action='append',
                   help="HTTP method; repeat for several")
    p.add_argument('--path', help="restrict to an endpoint path or subtree")
    if behavior or attacks:
        p.add_argument('--status', help="500 | '>=500' | 500-599 | 5xx")
    if structure or behavior:
        p.add_argument('--anon', action='store_true',
                       help="anonymous access (structure: served real data)")
        p.add_argument('--auth', action='store_true',
                       help="authenticated requests only")
        p.add_argument('--cors-open', dest='cors_open', action='store_true',
                       help="permissive CORS (wildcard, reflected or null)")
        p.add_argument('--include-static', dest='include_static',
                       action='store_true',
                       help="keep js/css/image noise (excluded by default)")
        p.add_argument('--param', action='append', help="has this parameter name")
        p.add_argument('--cookie', action='append', help="mentions this cookie name")
        p.add_argument('--missing-header', dest='missing_header', action='append',
                       help="missing this security header, e.g. csp")
    if structure:
        p.add_argument('--kind', help="page | endpoint | action | auth_model | entity")
        p.add_argument('--access-control', dest='access_control',
                       help="open-data | soft-auth-wall | enforced | unknown")
    if behavior:
        p.add_argument('--access-class', dest='access_class',
                       help="data | auth_wall | shell | denied | redirect | empty "
                            "| static | other")
        p.add_argument('--anon-matches-auth', dest='anon_matches_auth',
                       action='store_true',
                       help="anon response matched the authenticated one")
        p.add_argument('--cookie-issues', dest='cookie_issues', action='store_true',
                       help="response set a cookie missing HttpOnly/Secure/SameSite")
        p.add_argument('--jwt', action='store_true', help="request carried a JWT")
    if attacks:
        p.add_argument('--vuln-class', dest='vuln_class',
                       help="SQLi | XSS | SSRF | IDOR | ...")
        p.add_argument('--verdict', help="vulnerable | not_vulnerable | inconclusive")
        p.add_argument('--severity')
    p.add_argument('--contains', help="substring of the raw HTTP text")
    p.add_argument('--where', help=argparse.SUPPRESS)


def build_parser():
    ap = argparse.ArgumentParser(
        prog='jeb-query.sh',
        description="J.E.B. v4 -- query a Burp capture mapped into ChromaDB.")
    sub = ap.add_subparsers(dest='command', required=True)

    p = sub.add_parser('endpoint', help="everything known about one endpoint")
    p.add_argument('target', help="path or URL, e.g. /api/orders")
    p.add_argument('--host')
    p.add_argument('--method')
    p.add_argument('--no-raw', dest='no_raw', action='store_true',
                   help="omit the inlined raw request/response")
    p.add_argument('--raw-chars', dest='raw_chars', type=int, default=None,
                   help="response-body budget for the raw example")
    _add_depth(p)
    _add_common(p)
    p.set_defaults(func=cmd_endpoint)

    p = sub.add_parser('map', help="list the site map")
    _add_facets(p, structure=True)
    _add_depth(p)
    _add_common(p)
    p.set_defaults(func=cmd_map)

    p = sub.add_parser('search', help="hybrid search; omit text for a pure filter")
    p.add_argument('text', nargs='*', help="structural words, not vulnerability names")
    p.add_argument('--in', dest='collection', choices=COLLECTIONS, default='behavior',
                   help="collection to search (default: behavior)")
    p.add_argument('--loose', action='store_true',
                   help="disable the relevance cutoff")
    _add_facets(p, structure=True, behavior=True, attacks=True)
    _add_depth(p)
    _add_common(p)
    p.set_defaults(func=cmd_search)

    p = sub.add_parser('attacks', help="findings you recorded, by class or verdict")
    _add_facets(p, attacks=True)
    _add_depth(p)
    _add_common(p)
    p.set_defaults(func=cmd_attacks)

    p = sub.add_parser('get', help="one document in full, collection auto-detected")
    p.add_argument('target', help="document id")
    p.add_argument('--in', dest='collection', choices=COLLECTIONS, default=None)
    _add_common(p)
    p.set_defaults(func=cmd_get)

    p = sub.add_parser('similar', help="nearest neighbours of a document")
    p.add_argument('target', help="document id")
    p.add_argument('--in', dest='collection', choices=COLLECTIONS, default=None)
    # Deliberately narrow: "more like this" needs scoping at most, not the whole
    # facet vocabulary.
    p.add_argument('--host', help="restrict to one host")
    p.add_argument('--path', help="restrict to an endpoint path or subtree")
    _add_depth(p)
    _add_common(p)
    p.set_defaults(func=cmd_similar)

    p = sub.add_parser('identifier',
                       help="every document that referenced an id/uuid value")
    p.add_argument('target', help="the concrete value, e.g. 42")
    _add_common(p)
    p.set_defaults(func=cmd_identifier)

    p = sub.add_parser('record-attack', help="persist an active-testing result")
    p.add_argument('--vuln-class', dest='vuln_class', required=True)
    p.add_argument('--endpoint', required=True)
    p.add_argument('--method', default='')
    p.add_argument('--param', default='')
    p.add_argument('--payload', default='')
    p.add_argument('--status', default='')
    p.add_argument('--verdict', default='inconclusive',
                   choices=['vulnerable', 'not_vulnerable', 'inconclusive'])
    p.add_argument('--severity', default='')
    p.add_argument('--source-id', dest='source_id', default='')
    p.add_argument('--evidence', default='')
    p.add_argument('--tool', default='')
    p.add_argument('--request', default='')
    p.add_argument('--request-file', dest='request_file')
    p.add_argument('--response', default='')
    p.add_argument('--response-file', dest='response_file')
    _add_common(p)
    p.set_defaults(func=cmd_record_attack)

    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    if getattr(args, 'where', None):
        try:
            args.raw_where = json.loads(args.where)
        except ValueError as e:
            print(json.dumps({'command': args.command,
                              'error': f"--where is not valid JSON: {e}"}, indent=2))
            return 2
    try:
        return args.func(args)
    except MissingCollection as e:
        return emit(envelope(
            args.command, count=0, results=[],
            notes=[f"This project has no '{e.wanted}' collection at "
                   f"{os.path.abspath(args.db_path)}."
                   + (f" Present: {', '.join(e.have)}." if e.have else
                      " The database is empty -- run the jeb-import skill first.")],
            next=["Run the jeb-import skill on the Burp XML export for this project."]))
    except ValueError as e:
        return emit(envelope(args.command, count=0, results=[], notes=[str(e)]))


if __name__ == '__main__':
    sys.exit(main() or 0)
