"""
J.E.B. v2 — query / hunting interface.

Reads a per-project ChromaDB built by the jeb-import pipeline. Three collections:
  structure  the site map (endpoint templates, pages, actions, per-host auth model)
  behavior   distinct request/response behaviors (default)
  attacks    results of active testing (written here by --record-attack)

Searches embed the query with the same retrieval prompt the corpus was built
with. Because the vector is the distilled `embed_text` while the stored document
is the raw HTTP, `--where-document '{"$contains": "SameSite=None"}'` filters on
the real header/cookie text without bloating metadata.
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
from embedding import (COLLECTION_SCHEMA, DISTANCE_METRIC, EMBEDDING_SCHEME,
                       make_ollama_ef, embed_query, embed_documents)  # noqa: E402
import distill as d  # noqa: E402

DEFAULT_DB_PATH = "./chroma_db"
SNIPPET_LEN_DEFAULT = 200
CANDIDATE_K_DEFAULT = 40
TOP_K_DEFAULT = 8
TOP_P_DEFAULT = 0.90
RRF_K = 60
DEFAULT_MAX_DISTANCE = {'structure': 0.65, 'behavior': 0.70, 'attacks': 0.70}

# Facets surfaced in a result summary, per collection.
FACETS = {
    'structure': ['node_kind', 'scheme', 'host', 'port', 'endpoint_template',
                  'method', 'param_names',
                  'produces', 'authenticated_ever', 'anon_allowed', 'anon_soft_denied',
                  'access_control', 'auth_mechanisms',
                  'cookies_sent', 'cookies_set', 'security_headers_missing', 'cors',
                  'instance_count', 'example_ids'],
    'behavior': ['method', 'scheme', 'host', 'port', 'endpoint_template',
                 'status_code', 'auth_role',
                 'auth_mechanism', 'access_class', 'anon_matches_auth', 'param_names',
                 'cors', 'cookie_issues', 'security_headers_missing', 'redirect_location',
                 'instance_count'],
    'attacks': ['vuln_class', 'verdict', 'severity', 'host', 'endpoint_template',
                'method', 'param', 'status_code', 'source_behavior_id'],
}


class JebAgent:
    def __init__(self, db_path=DEFAULT_DB_PATH, collection_name="behavior"):
        self.db_path = os.path.abspath(db_path)
        self.collection_name = collection_name
        self.ollama_ef = make_ollama_ef()
        self.client = chromadb.PersistentClient(path=self.db_path)
        have = {c.name for c in self.client.list_collections()}
        if collection_name in have:
            self.collection = self.client.get_collection(
                collection_name, embedding_function=self.ollama_ef)
        else:
            self.collection = self.client.create_collection(
                name=collection_name, embedding_function=self.ollama_ef,
                metadata={"embedding_scheme": EMBEDDING_SCHEME,
                          "collection_schema": COLLECTION_SCHEMA,
                          "hnsw:space": DISTANCE_METRIC})
        meta = self.collection.metadata or {}
        self.prefixed = meta.get("embedding_scheme") == EMBEDDING_SCHEME
        if not self.prefixed:
            print("[jeb-query] Note: DB uses an older embedding scheme; "
                  "using raw query text. Re-run jeb-import into a fresh chroma_db.",
                  file=sys.stderr)

        segment_name = f"{collection_name}_segments"
        have = {c.name for c in self.client.list_collections()}
        self.segment_collection = None
        if segment_name in have:
            candidate = self.client.get_collection(segment_name,
                                                   embedding_function=self.ollama_ef)
            segment_meta = candidate.metadata or {}
            if segment_meta.get('collection_schema') == COLLECTION_SCHEMA:
                self.segment_collection = candidate

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
    def _fts_query(query):
        terms = re.findall(r"[A-Za-z0-9_{}.-]+", query)
        return " OR ".join('"' + term.replace('"', '""') + '"'
                           for term in terms[:20])

    def _lexical_candidates(self, query, collection_name, limit):
        path = os.path.join(self.db_path, 'jeb_lexical.sqlite')
        fts_query = self._fts_query(query)
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

    def search(self, query, n_results=TOP_K_DEFAULT, where=None, where_document=None,
               snippet_len=SNIPPET_LEN_DEFAULT, candidate_k=CANDIDATE_K_DEFAULT,
               max_distance=None, min_score=0.0, top_p=TOP_P_DEFAULT,
               min_results=3, max_per_endpoint=2):
        top_k = max(1, min(int(n_results), 100))
        candidate_k = max(top_k, min(int(candidate_k), 200))
        min_score = max(0.0, min(float(min_score), 1.0))
        if top_p is not None:
            top_p = max(0.0, min(float(top_p), 1.0))
        min_results = max(1, min(int(min_results), top_k))
        dense_collection = self.segment_collection or self.collection
        lexical_collection = (f"{self.collection_name}_segments"
                              if self.segment_collection else self.collection_name)

        kwargs = {'n_results': candidate_k,
                  'include': ['metadatas', 'distances']}
        if where and self.segment_collection:
            kwargs['where'] = where
        elif where:
            kwargs['where'] = where
        if where_document and not self.segment_collection:
            kwargs['where_document'] = where_document
        if self.prefixed:
            kwargs['query_embeddings'] = [embed_query(
                self.ollama_ef, self.collection_name, query)]
        else:
            kwargs['query_texts'] = [query]
        dense = dense_collection.query(**kwargs)

        if max_distance is None:
            max_distance = DEFAULT_MAX_DISTANCE.get(self.collection_name)
        candidates = {}

        def merge_dense(results, source):
            if not results['ids']:
                return
            for rank, (doc_id, meta, distance) in enumerate(zip(
                    results['ids'][0], results['metadatas'][0],
                    results['distances'][0]), 1):
                distance = float(distance)
                if max_distance is not None and distance > max_distance:
                    continue
                parent_id = (meta or {}).get('parent_id', doc_id)
                entry = candidates.setdefault(parent_id, {
                    'rrf': 0.0, 'distance': distance, 'sources': set(),
                    'representations': set(),
                })
                if source not in entry['sources']:
                    entry['rrf'] += 1.0 / (RRF_K + rank)
                entry['distance'] = min(entry['distance'], distance)
                entry['sources'].add(source)
                representation = (meta or {}).get('representation')
                if representation:
                    entry['representations'].add(representation)

        merge_dense(dense, 'dense')
        if where_document and self.segment_collection:
            raw_kwargs = {'n_results': candidate_k,
                          'include': ['metadatas', 'distances'],
                          'where_document': where_document}
            if where:
                raw_kwargs['where'] = where
            if self.prefixed:
                raw_kwargs['query_embeddings'] = [embed_query(
                    self.ollama_ef, self.collection_name, query)]
            else:
                raw_kwargs['query_texts'] = [query]
            merge_dense(self.collection.query(**raw_kwargs), 'dense_raw_filter')

        lexical = self._lexical_candidates(
            query, lexical_collection, min(candidate_k * 5, 500))
        lexical = lexical[:candidate_k]
        for rank, parent_id in enumerate(lexical, 1):
            entry = candidates.setdefault(parent_id, {
                'rrf': 0.0, 'distance': None, 'sources': set(),
                'representations': set(),
            })
            entry['rrf'] += 1.0 / (RRF_K + rank)
            entry['sources'].add('lexical')

        eligible = self._eligible_parents(list(candidates), where, where_document)
        query_terms = {t.lower() for t in re.findall(r"[A-Za-z0-9_{}.-]+", query)}
        ranked = []
        for parent_id, meta in eligible.items():
            entry = candidates[parent_id]
            facet_text = " ".join(str(meta.get(field, '')) for field in (
                'host', 'endpoint_template', 'method', 'param_names', 'summary'))
            facet_terms = {t.lower() for t in re.findall(
                r"[A-Za-z0-9_{}.-]+", facet_text)}
            overlap = len(query_terms & facet_terms) / max(len(query_terms), 1)
            entry['raw_score'] = entry['rrf'] + 0.01 * overlap
            entry['id'] = parent_id
            entry['metadata'] = meta
            ranked.append(entry)
        ranked.sort(key=lambda x: (-x['raw_score'],
                                  x['distance'] if x['distance'] is not None else math.inf,
                                  x['id']))

        if not ranked:
            return []
        best = ranked[0]['raw_score'] or 1.0
        ranked = [r for r in ranked if (r.setdefault('score', r['raw_score'] / best)
                                        >= min_score)]

        diverse, endpoint_counts = [], {}
        for entry in ranked:
            meta = entry['metadata']
            key = (meta.get('host', ''), meta.get('endpoint_template', ''))
            if max_per_endpoint > 0 and endpoint_counts.get(key, 0) >= max_per_endpoint:
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

        out = []
        for entry in selected:
            item = self._summarize(entry['id'], entry['metadata'],
                                   entry['distance'], snippet_len)
            item['score'] = round(entry['score'], 4)
            item['sources'] = sorted(entry['sources'])
            if entry['representations']:
                item['representations'] = sorted(entry['representations'])
            out.append(item)
        return out

    def find_similar(self, doc_id, n_results=5, where=None, where_document=None,
                     snippet_len=SNIPPET_LEN_DEFAULT):
        seed = self.collection.get(ids=[doc_id], include=['embeddings'])
        if not seed['ids']:
            return f"Seed id {doc_id} not found in '{self.collection_name}'."
        kwargs = {'query_embeddings': [seed['embeddings'][0]],
                  'n_results': n_results + 1,
                  'include': ['metadatas', 'distances']}
        if where:
            kwargs['where'] = where
        if where_document:
            kwargs['where_document'] = where_document
        res = self.collection.query(**kwargs)
        out = []
        if res['ids']:
            for i in range(len(res['ids'][0])):
                rid = res['ids'][0][i]
                if rid == doc_id:
                    continue
                out.append(self._summarize(rid, res['metadatas'][0][i],
                                           res['distances'][0][i], snippet_len))
                if len(out) >= n_results:
                    break
        return out

    def get_full(self, doc_id):
        res = self.collection.get(ids=[doc_id], include=['documents', 'metadatas'])
        if not res['ids']:
            return f"id {doc_id} not found in '{self.collection_name}'."
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
            'time': now, 'summary': summary,
        }
        doc_id = d.md5(f"{now}|{template}|{record['param']}|{record['payload']}")
        embedding = embed_documents(self.ollama_ef, [embed_text])[0] if self.prefixed else None
        if embedding is not None:
            self.collection.upsert(ids=[doc_id], documents=[page_content],
                                   metadatas=[metadata], embeddings=[embedding])
        else:
            self.collection.upsert(ids=[doc_id], documents=[page_content],
                                   metadatas=[metadata])
        self._upsert_lexical(doc_id, 'attacks', embed_text)
        return {'recorded': doc_id, 'summary': summary}


def _read(val, path):
    if path:
        with open(path) as f:
            return f.read()
    return val or ''


def main():
    ap = argparse.ArgumentParser(description="J.E.B. v3 query / hunting interface")
    ap.add_argument('--db-path', default=DEFAULT_DB_PATH)
    ap.add_argument('--collection', default='behavior',
                    help="structure | behavior | attacks (default: behavior)")
    ap.add_argument('--query')
    ap.add_argument('--similar-to', dest='similar_to')
    ap.add_argument('--id')
    ap.add_argument('--where')
    ap.add_argument('--where-document', dest='where_document',
                    help='JSON, e.g. \'{"$contains": "SameSite=None"}\' (substring over raw HTTP)')
    ap.add_argument('--n-results', '--top-k', dest='n_results', type=int,
                    default=TOP_K_DEFAULT,
                    help='Maximum final results (default: 8)')
    ap.add_argument('--candidate-k', type=int, default=CANDIDATE_K_DEFAULT,
                    help='Candidates requested from each retriever (default: 40)')
    ap.add_argument('--max-distance', type=float, default=None,
                    help='Maximum dense cosine distance; defaults by collection')
    ap.add_argument('--min-score', type=float, default=0.0,
                    help='Minimum normalized fused score from 0 to 1')
    ap.add_argument('--top-p', type=float, default=TOP_P_DEFAULT,
                    help='Cumulative retrieval relevance mass (default: 0.90)')
    ap.add_argument('--min-results', type=int, default=3)
    ap.add_argument('--max-per-endpoint', type=int, default=2)
    ap.add_argument('--snippet-len', type=int, default=SNIPPET_LEN_DEFAULT)
    # record-attack
    ap.add_argument('--record-attack', action='store_true')
    ap.add_argument('--vuln-class')
    ap.add_argument('--endpoint')
    ap.add_argument('--method', default='')
    ap.add_argument('--param', default='')
    ap.add_argument('--payload', default='')
    ap.add_argument('--request', default='')
    ap.add_argument('--request-file')
    ap.add_argument('--response', default='')
    ap.add_argument('--response-file')
    ap.add_argument('--status', default='')
    ap.add_argument('--verdict', default='inconclusive')
    ap.add_argument('--severity', default='')
    ap.add_argument('--source-id', dest='source_id', default='')
    ap.add_argument('--evidence', default='')
    ap.add_argument('--tool', default='')
    args = ap.parse_args()

    def _json(s, label):
        if not s:
            return None
        try:
            return json.loads(s)
        except Exception as e:
            print(f"Error parsing {label} JSON: {e}")
            sys.exit(1)

    collection = 'attacks' if args.record_attack else args.collection
    agent = JebAgent(db_path=args.db_path, collection_name=collection)
    where = _json(args.where, '--where')
    where_document = _json(args.where_document, '--where-document')

    if args.record_attack:
        if not args.vuln_class or not args.endpoint:
            print("record-attack requires --vuln-class and --endpoint")
            sys.exit(1)
        m = {'vuln_class': args.vuln_class, 'endpoint': args.endpoint,
             'method': args.method, 'param': args.param, 'payload': args.payload,
             'status': args.status, 'verdict': args.verdict, 'severity': args.severity,
             'source_id': args.source_id, 'evidence': args.evidence, 'tool': args.tool}
        req = _read(args.request, args.request_file)
        resp = _read(args.response, args.response_file)
        print(json.dumps(agent.record_attack(m, req, resp), indent=2))
    elif args.query:
        print(json.dumps(agent.search(
            args.query, args.n_results, where, where_document, args.snippet_len,
            args.candidate_k, args.max_distance, args.min_score, args.top_p,
            args.min_results, args.max_per_endpoint), indent=2))
    elif args.similar_to:
        print(json.dumps(agent.find_similar(args.similar_to, args.n_results, where,
                                            where_document, args.snippet_len), indent=2))
    elif args.id:
        print(json.dumps(agent.get_full(args.id), indent=2))
    else:
        print("Provide --query, --similar-to, --id, or --record-attack")


if __name__ == '__main__':
    main()
