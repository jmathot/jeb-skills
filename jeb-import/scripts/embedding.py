"""
Shared embedding helpers for the J.E.B. import + query steps.

Single source of truth for:
  * the Ollama embedding model / endpoint,
  * the embeddinggemma asymmetric prompt prefixes, and
  * a schema stamp so a database advertises which embedding scheme built it.

embeddinggemma is trained with *paired* task prompts: documents and queries
must both be prefixed for the vectors to land in a shared space. v3 embeds the
distilled `embed_text` of every doc with the document prompt and embeds queries
with a single retrieval prompt (the three collections — structure, behavior,
attacks — are all distilled security text, so one prompt fits all).

Callers compute explicit prefixed embeddings with the helpers below and pass
them as `embeddings=` / `query_embeddings=` (never relying on ChromaDB's
implicit embedding, which would skip the prefixes). A plain
OllamaEmbeddingFunction is still attached to collections for config
compatibility.
"""

from chromadb.utils import embedding_functions

# Bump this string whenever the prompt scheme changes so stale databases embedded
# under an older scheme can be detected (and either handled or rebuilt).
# v4: structure_segments/behavior_segments folded into structure/behavior via a
# `granularity` metadata field (parent|segment); entity nodes + identifier index
# added. A v3 chroma_db has no `granularity` field on its docs, so v4's dense
# query (which filters on it) would silently return nothing -- rebuild it.
EMBEDDING_SCHEME = "embeddinggemma-v4-unified-collections"
COLLECTION_SCHEMA = "jeb-v4"
DISTANCE_METRIC = "cosine"

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
    """Document/corpus prompt."""
    return f"title: none | text: {text}"


def query_prefix_search(text: str) -> str:
    """Query prompt. v2 embeds three homogeneous collections (structure /
    behavior / attacks) of distilled security text, so a single retrieval
   prompt is used for all of them."""
    return f"task: search result | query: {text}"


def query_prefix_for_collection(collection_name: str, text: str) -> str:
    """Kept for call-site compatibility; all v2 collections share one prompt."""
    return query_prefix_search(text)


def embed_documents(ollama_ef, texts):
    """Embed a batch of corpus documents with the document prompt."""
    return ollama_ef([doc_prefix(t) for t in texts])


def embed_query(ollama_ef, collection_name: str, text: str):
    """Embed a single query string with the retrieval prompt."""
    return ollama_ef([query_prefix_search(text)])[0]
