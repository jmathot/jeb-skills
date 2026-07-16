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
import os
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
from embedding import EMBEDDING_SCHEME, make_ollama_ef, embed_query, embed_documents  # noqa: E402
import distill as d  # noqa: E402

DEFAULT_DB_PATH = "./chroma_db"
SNIPPET_LEN_DEFAULT = 200

# Facets surfaced in a result summary, per collection.
FACETS = {
    'structure': ['node_kind', 'host', 'endpoint_template', 'method', 'param_names',
                  'produces', 'authenticated_ever', 'anon_allowed', 'anon_soft_denied',
                  'access_control', 'auth_mechanisms',
                  'cookies_sent', 'cookies_set', 'security_headers_missing', 'cors',
                  'instance_count', 'example_ids'],
    'behavior': ['method', 'host', 'endpoint_template', 'status_code', 'auth_role',
                 'auth_mechanism', 'access_class', 'anon_matches_auth', 'param_names',
                 'cors', 'cookie_issues', 'security_headers_missing', 'redirect_location',
                 'instance_count'],
    'attacks': ['vuln_class', 'verdict', 'severity', 'host', 'endpoint_template',
                'method', 'param', 'status_code', 'source_behavior_id'],
}


class JebAgent:
    def __init__(self, db_path=DEFAULT_DB_PATH, collection_name="behavior"):
        self.collection_name = collection_name
        self.ollama_ef = make_ollama_ef()
        self.client = chromadb.PersistentClient(path=os.path.abspath(db_path))
        self.collection = self.client.get_or_create_collection(
            name=collection_name, embedding_function=self.ollama_ef,
            metadata={"embedding_scheme": EMBEDDING_SCHEME})
        meta = self.collection.metadata or {}
        self.prefixed = meta.get("embedding_scheme") == EMBEDDING_SCHEME
        if not self.prefixed:
            print("[jeb-query] Note: DB built without the v2 embedding scheme; "
                  "using raw query text. Re-run jeb-import into a fresh chroma_db.",
                  file=sys.stderr)

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

    def search(self, query, n_results=5, where=None, where_document=None,
               snippet_len=SNIPPET_LEN_DEFAULT):
        kwargs = {'n_results': n_results, 'include': ['metadatas', 'distances']}
        if where:
            kwargs['where'] = where
        if where_document:
            kwargs['where_document'] = where_document
        if self.prefixed:
            kwargs['query_embeddings'] = [embed_query(self.ollama_ef, self.collection_name, query)]
        else:
            kwargs['query_texts'] = [query]
        res = self.collection.query(**kwargs)
        out = []
        if res['ids']:
            for i in range(len(res['ids'][0])):
                out.append(self._summarize(
                    res['ids'][0][i], res['metadatas'][0][i],
                    res['distances'][0][i], snippet_len))
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
        return {'recorded': doc_id, 'summary': summary}


def _read(val, path):
    if path:
        with open(path) as f:
            return f.read()
    return val or ''


def main():
    ap = argparse.ArgumentParser(description="J.E.B. v2 query / hunting interface")
    ap.add_argument('--db-path', default=DEFAULT_DB_PATH)
    ap.add_argument('--collection', default='behavior',
                    help="structure | behavior | attacks (default: behavior)")
    ap.add_argument('--query')
    ap.add_argument('--similar-to', dest='similar_to')
    ap.add_argument('--id')
    ap.add_argument('--where')
    ap.add_argument('--where-document', dest='where_document',
                    help='JSON, e.g. \'{"$contains": "SameSite=None"}\' (substring over raw HTTP)')
    ap.add_argument('--n-results', type=int, default=5)
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
        print(json.dumps(agent.search(args.query, args.n_results, where,
                                      where_document, args.snippet_len), indent=2))
    elif args.similar_to:
        print(json.dumps(agent.find_similar(args.similar_to, args.n_results, where,
                                            where_document, args.snippet_len), indent=2))
    elif args.id:
        print(json.dumps(agent.get_full(args.id), indent=2))
    else:
        print("Provide --query, --similar-to, --id, or --record-attack")


if __name__ == '__main__':
    main()
