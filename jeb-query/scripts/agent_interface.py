import os
import sys
import chromadb

# Reuse the shared embedding helpers from the jeb-import skill so the query
# prompt exactly matches how the corpus was embedded. The jeb-import scripts dir
# is a sibling skill: <skill root>/jeb-query/scripts -> <skill root>/jeb-import/scripts.
# This relative resolution works for both the dev tree and the installed layout;
# the fixed install path is kept as a fallback.
_here = os.path.dirname(os.path.abspath(__file__))
for _candidate in (
    os.path.normpath(os.path.join(_here, "..", "..", "jeb-import", "scripts")),
    os.path.expanduser("~/.config/opencode/skill/jeb-import/scripts"),
):
    if os.path.isdir(_candidate) and _candidate not in sys.path:
        sys.path.insert(0, _candidate)
from embedding import EMBEDDING_SCHEME, make_ollama_ef, embed_query

# Each project has its OWN database in its project folder. Default to ./chroma_db
# in the current (project) directory. There is deliberately no global/env-var
# default so project databases can never be mixed.
DEFAULT_DB_PATH = "./chroma_db"

SNIPPET_LEN_DEFAULT = 200


class BurpTrafficAgent:
    def __init__(self, db_path=DEFAULT_DB_PATH, collection_name="burp_traffic"):
        db_path = os.path.abspath(db_path)
        self.collection_name = collection_name
        self.ollama_ef = make_ollama_ef()
        self.client = chromadb.PersistentClient(path=db_path)
        self.collection = self.client.get_collection(
            name=collection_name,
            embedding_function=self.ollama_ef
        )
        # A database built by the current import pipeline stamps its collections
        # with the prefixed embedding scheme. Only then can we safely embed the
        # query with the asymmetric prompt; otherwise (legacy DB embedded from
        # raw text) prefixing the query would mismatch the document vectors, so
        # we fall back to the raw query text to avoid regressing retrieval.
        meta = self.collection.metadata or {}
        self.prefixed_scheme = meta.get("embedding_scheme") == EMBEDDING_SCHEME
        if not self.prefixed_scheme:
            print(
                "[jeb-query] Note: this database was built without the prefixed "
                "embedding scheme; using raw query text. Re-run jeb-import (into a "
                "fresh chroma_db) to enable improved retrieval.",
                file=sys.stderr,
            )

    def _snippet(self, document, snippet_len):
        """Short, single-line-ish preview of the matched document text.
        For web_code the first line is a generated header, so prefer the body."""
        if not document:
            return ""
        text = document
        if document.startswith("// web_code"):
            parts = document.split("\n", 1)
            if len(parts) == 2:
                text = parts[1]
        text = " ".join(text.split())
        if len(text) > snippet_len:
            text = text[:snippet_len] + "…"
        return text

    def _summarize(self, doc_id, meta, document=None, distance=None, snippet_len=SNIPPET_LEN_DEFAULT):
        if meta.get('content_kind') == 'web_code':
            summary = {
                "id": doc_id,
                "content_kind": "web_code",
                "code_type": meta.get('code_type', ''),
                "host": meta.get('host', ''),
                "source_url": meta.get('source_url', ''),
                "url_count": meta.get('url_count', ''),
                "chunk_index": meta.get('chunk_index', ''),
                "total_chunks": meta.get('total_chunks', ''),
                "has_secrets": meta.get('has_secrets', ''),
                "dom_sinks": meta.get('dom_sinks', ''),
                "endpoints": meta.get('endpoints', ''),
                "endpoint_count": meta.get('endpoint_count', ''),
                "embed": meta.get('embed', ''),
            }
        else:
            summary = {
                "id": doc_id,
                "method": meta.get('method', ''),
                "host": meta.get('host', ''),
                "endpoint": meta.get('endpoint', ''),
                "status": meta.get('status', ''),
                "status_code": meta.get('status_code', ''),
                "status_class": meta.get('status_class', ''),
                "url_params": meta.get('url_params', ''),
                "cookies": meta.get('cookies', ''),
                "body_params": meta.get('body_params', ''),
                "param_count": meta.get('param_count', ''),
                "req_content_type": meta.get('req_content_type', ''),
                "is_static": meta.get('is_static', ''),
                "file_ext": meta.get('file_ext', ''),
                "referer": meta.get('referer', ''),
                "cors_wildcard": meta.get('cors_wildcard', ''),
                "auth_role": meta.get('auth_role', ''),
                "authenticated": meta.get('authenticated', ''),
                "time": meta.get('time', ''),
                "resp_len": meta.get('resp_len', meta.get('responselength', ''))
            }
        if distance is not None:
            summary["distance"] = round(float(distance), 4)
        if snippet_len > 0:
            summary["snippet"] = self._snippet(document, snippet_len)
        return summary

    def search_traffic_summary(self, query: str, n_results: int = 5, where: dict = None,
                               snippet_len: int = SNIPPET_LEN_DEFAULT):
        """
        Search for traffic based on a semantic query and return a summary.
        This prevents context window overflow by only returning metadata and a
        short matched snippet plus a similarity distance for triage.
        Handles both the `burp_traffic` and `web_code` collections.
        """
        query_kwargs = {
            "n_results": n_results,
            "include": ["metadatas", "documents", "distances"],
        }
        if where:
            query_kwargs["where"] = where

        # Embed the query with the collection-appropriate prompt when the DB was
        # built with the prefixed scheme; otherwise use raw text (legacy match).
        if self.prefixed_scheme:
            query_kwargs["query_embeddings"] = [
                embed_query(self.ollama_ef, self.collection_name, query)
            ]
        else:
            query_kwargs["query_texts"] = [query]

        results = self.collection.query(**query_kwargs)

        summaries = []
        if results['ids']:
            for i in range(len(results['ids'][0])):
                doc_id = results['ids'][0][i]
                meta = results['metadatas'][0][i]
                document = results['documents'][0][i] if results.get('documents') else None
                distance = results['distances'][0][i] if results.get('distances') else None
                summaries.append(self._summarize(doc_id, meta, document, distance, snippet_len))
        return summaries

    def find_similar(self, doc_id: str, n_results: int = 5, where: dict = None,
                     snippet_len: int = SNIPPET_LEN_DEFAULT):
        """
        Retrieve the nearest neighbours of an existing document by its stored
        vector — an embedding-native pivot: "show me everything like this one".
        """
        seed = self.collection.get(ids=[doc_id], include=["embeddings", "metadatas"])
        if not seed['ids']:
            return f"Seed document id {doc_id} not found in collection '{self.collection_name}'."

        seed_meta = seed['metadatas'][0] if seed.get('metadatas') else {}
        # Store-only chunks (vendor/minified/CSS) share a fixed placeholder vector,
        # so their nearest neighbours are meaningless.
        if seed_meta.get('embed') is False:
            print(
                f"[jeb-query] Warning: seed {doc_id} is a store-only chunk "
                "(placeholder vector); similarity results are not meaningful.",
                file=sys.stderr,
            )

        seed_vec = seed['embeddings'][0]

        query_kwargs = {
            "query_embeddings": [seed_vec],
            "n_results": n_results + 1,  # +1 because the seed itself will match
            "include": ["metadatas", "documents", "distances"],
        }
        if where:
            query_kwargs["where"] = where

        results = self.collection.query(**query_kwargs)

        summaries = []
        if results['ids']:
            for i in range(len(results['ids'][0])):
                rid = results['ids'][0][i]
                if rid == doc_id:  # drop the seed itself
                    continue
                meta = results['metadatas'][0][i]
                document = results['documents'][0][i] if results.get('documents') else None
                distance = results['distances'][0][i] if results.get('distances') else None
                summaries.append(self._summarize(rid, meta, document, distance, snippet_len))
                if len(summaries) >= n_results:
                    break
        return summaries

    def get_full_traffic(self, doc_id: str):
        """
        Retrieve the full request/response content for a specific ID.
        Allows deep dives into specific requests.
        """
        result = self.collection.get(
            ids=[doc_id]
        )
        if result['documents'] and len(result['documents']) > 0:
            return result['documents'][0]
        return "Not found."

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="J.E.B. query / hunting interface")
    parser.add_argument("--query", type=str, help="Semantic search query")
    parser.add_argument("--similar-to", type=str, dest="similar_to",
                        help="Document ID to find semantically similar documents to")
    parser.add_argument("--where", type=str, help="JSON string for metadata filtering")
    parser.add_argument("--id", type=str, help="Document ID to fetch (full deep dive)")
    parser.add_argument("--db-path", type=str, default=DEFAULT_DB_PATH,
                        help="Path to the project's ChromaDB directory (default: ./chroma_db)")
    parser.add_argument("--collection", type=str, default="burp_traffic",
                        help="Collection to query: 'burp_traffic' (HTTP traffic) or "
                             "'web_code' (client-side HTML/JS). Default: burp_traffic")
    parser.add_argument("--n-results", type=int, default=5,
                        help="Number of search results to return (default: 5)")
    parser.add_argument("--snippet-len", type=int, default=SNIPPET_LEN_DEFAULT,
                        help="Max chars of matched-document snippet per result "
                             "(0 disables snippets; default: %(default)s)")
    args = parser.parse_args()

    agent = BurpTrafficAgent(db_path=args.db_path, collection_name=args.collection)

    where_dict = None
    if args.where:
        import json
        try:
            where_dict = json.loads(args.where)
        except Exception as e:
            print(f"Error parsing --where JSON: {e}")
            exit(1)

    if args.query:
        print(f"Search results for '{args.query}':")
        print(agent.search_traffic_summary(
            args.query, n_results=args.n_results, where=where_dict,
            snippet_len=args.snippet_len))
    elif args.similar_to:
        print(f"Documents similar to '{args.similar_to}':")
        print(agent.find_similar(
            args.similar_to, n_results=args.n_results, where=where_dict,
            snippet_len=args.snippet_len))
    elif args.id:
        print(f"Full traffic for ID {args.id}:")
        print(agent.get_full_traffic(args.id))
    else:
        print("Please provide --query, --similar-to, or --id")
