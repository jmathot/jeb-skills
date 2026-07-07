import os
import chromadb

# Each project has its OWN database in its project folder. Default to ./chroma_db
# in the current (project) directory. There is deliberately no global/env-var
# default so project databases can never be mixed.
DEFAULT_DB_PATH = "./chroma_db"


class BurpTrafficAgent:
    def __init__(self, db_path=DEFAULT_DB_PATH, collection_name="burp_traffic"):
        db_path = os.path.abspath(db_path)
        from chromadb.utils import embedding_functions
        self.ollama_ef = embedding_functions.OllamaEmbeddingFunction(
            url="http://localhost:11434/api/embeddings",
            model_name="embeddinggemma:latest",
        )
        self.client = chromadb.PersistentClient(path=db_path)
        self.collection = self.client.get_collection(
            name=collection_name,
            embedding_function=self.ollama_ef
        )
        
    def search_traffic_summary(self, query: str, n_results: int = 5, where: dict = None):
        """
        Search for traffic based on a semantic query and return a summary.
        This prevents context window overflow by only returning metadata and snippets.
        Handles both the `burp_traffic` and `web_code` collections.
        """
        # If where is provided, pass it to chroma query
        query_kwargs = {
            "query_texts": [query],
            "n_results": n_results
        }
        if where:
            query_kwargs["where"] = where
            
        results = self.collection.query(**query_kwargs)
        
        summaries = []
        if results['ids']:
            for i in range(len(results['ids'][0])):
                doc_id = results['ids'][0][i]
                meta = results['metadatas'][0][i]

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
                summaries.append(summary)
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
    parser = argparse.ArgumentParser(description="Test Agent Interface")
    parser.add_argument("--query", type=str, help="Search query")
    parser.add_argument("--where", type=str, help="JSON string for metadata filtering")
    parser.add_argument("--id", type=str, help="Document ID to fetch")
    parser.add_argument("--db-path", type=str, default=DEFAULT_DB_PATH,
                        help="Path to the project's ChromaDB directory (default: ./chroma_db)")
    parser.add_argument("--collection", type=str, default="burp_traffic",
                        help="Collection to query: 'burp_traffic' (HTTP traffic) or "
                             "'web_code' (client-side HTML/JS). Default: burp_traffic")
    parser.add_argument("--n-results", type=int, default=5,
                        help="Number of search results to return (default: 5)")
    args = parser.parse_args()
    
    agent = BurpTrafficAgent(db_path=args.db_path, collection_name=args.collection)
    
    if args.query:
        where_dict = None
        if args.where:
            import json
            try:
                where_dict = json.loads(args.where)
            except Exception as e:
                print(f"Error parsing --where JSON: {e}")
                exit(1)
        print(f"Search results for '{args.query}':")
        print(agent.search_traffic_summary(args.query, n_results=args.n_results, where=where_dict))
    elif args.id:
        print(f"Full traffic for ID {args.id}:")
        print(agent.get_full_traffic(args.id))
    else:
        print("Please provide --query or --id")
