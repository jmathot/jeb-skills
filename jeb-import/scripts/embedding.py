"""
Shared embedding helpers for the J.E.B. import + query steps.

Single source of truth for:
  * the Ollama embedding model / endpoint,
  * the embeddinggemma asymmetric prompt prefixes, and
  * a schema stamp so a database advertises which embedding scheme built it.

embeddinggemma is trained with *paired* task prompts: documents and queries
must both be prefixed for the vectors to land in a shared space. The document
prompt is identical for general and code retrieval; only the query prompt
differs (general "search result" vs "code retrieval"). We therefore embed the
whole corpus with the document prompt and choose the query prompt per
collection at search time.

To avoid ever relying on ChromaDB's implicit `query_texts` / document
embedding (which would skip the prefixes), callers compute explicit prefixed
embeddings with the helpers below and pass them as `embeddings=` /
`query_embeddings=`. A plain OllamaEmbeddingFunction is still attached to the
collection purely for persisted-config compatibility.
"""

from chromadb.utils import embedding_functions

# Bump this string whenever the prompt scheme changes so stale databases embedded
# under an older scheme can be detected (and either handled or rebuilt).
EMBEDDING_SCHEME = "embeddinggemma-v1-prefixed"

OLLAMA_URL = "http://localhost:11434/api/embeddings"
OLLAMA_MODEL = "embeddinggemma:latest"


def make_ollama_ef():
    """Plain Ollama embedding function (no prefixing). Attached to collections
    for config compatibility; prefixing is applied by the helpers below."""
    return embedding_functions.OllamaEmbeddingFunction(
        url=OLLAMA_URL,
        model_name=OLLAMA_MODEL,
    )


def doc_prefix(text: str) -> str:
    """Document/corpus prompt (same for general and code retrieval)."""
    return f"title: none | text: {text}"


def query_prefix_search(text: str) -> str:
    """Query prompt for general semantic retrieval (burp_traffic)."""
    return f"task: search result | query: {text}"


def query_prefix_code(text: str) -> str:
    """Query prompt for code retrieval (web_code)."""
    return f"task: code retrieval | query: {text}"


def query_prefix_for_collection(collection_name: str, text: str) -> str:
    """Pick the correct query prompt based on the collection being searched."""
    if collection_name == "web_code":
        return query_prefix_code(text)
    return query_prefix_search(text)


def embed_documents(ollama_ef, texts):
    """Embed a batch of corpus documents with the document prompt."""
    return ollama_ef([doc_prefix(t) for t in texts])


def embed_query(ollama_ef, collection_name: str, text: str):
    """Embed a single query string with the collection-appropriate prompt."""
    prefixed = query_prefix_for_collection(collection_name, text)
    return ollama_ef([prefixed])[0]
