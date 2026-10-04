"""
Shared embedding helpers for the J.E.B. import + query steps.

Single source of truth for:
  * the Ollama embedding model / endpoint,
  * the embeddinggemma asymmetric prompt prefixes, and
  * a schema stamp so a database advertises which embedding scheme built it.

embeddinggemma is trained with *paired* task prompts: documents and queries
must both be prefixed for the vectors to land in a shared space. J.E.B. embeds the
distilled `embed_text` of every doc with the document prompt and embeds queries
with a single retrieval prompt (the three collections — structure, behavior,
attacks — are all distilled security text, so one prompt fits all).

Callers compute explicit prefixed embeddings with the helpers below and pass
them as `embeddings=` / `query_embeddings=` (never relying on ChromaDB's
implicit embedding, which would skip the prefixes). The custom embedding
function remains Chroma-compatible while fixing the model profile explicitly.
"""

import os

import numpy as np
from chromadb.utils import embedding_functions

# Bump this string whenever the prompt scheme changes so stale databases embedded
# under an older scheme can be detected (and either handled or rebuilt).
# This profile uses EmbeddingGemma's optional title slot when a real HTML title
# is available. Rebuild derived indexes after changes; preserve source observations.
# Index-defining knobs. The plugin passes these as JEB_* env vars from opencode.json
# plugin options; changing any of them changes the recorded embedding profile and
# requires a project rebuild (the digest/profile check refuses mismatched queries).
EMBEDDING_SCHEME = os.environ.get("JEB_EMBEDDING_SCHEME") or "embeddinggemma-v5-titled-768d"
COLLECTION_SCHEMA = "jeb-v6-streaming"
DISTANCE_METRIC = os.environ.get("JEB_DISTANCE_METRIC") or "cosine"

OLLAMA_URL = os.environ.get("JEB_OLLAMA_URL") or "http://localhost:11434/api/embeddings"
OLLAMA_MODEL = os.environ.get("JEB_EMBEDDING_MODEL") or "embeddinggemma:latest"
OLLAMA_TIMEOUT_SECONDS = int(os.environ.get("JEB_OLLAMA_TIMEOUT", "3600"))
OLLAMA_KEEP_ALIVE = os.environ.get("JEB_OLLAMA_KEEP_ALIVE", "30m")
EMBEDDING_DIMENSIONS = int(os.environ.get("JEB_EMBEDDING_DIMENSIONS") or 768)
EMBEDDING_CONTEXT_TOKENS = 2048
EMBEDDING_PROFILE_METADATA = {
    "embedding_scheme": EMBEDDING_SCHEME,
    "collection_schema": COLLECTION_SCHEMA,
    "embedding_model": OLLAMA_MODEL,
    "embedding_dimensions": EMBEDDING_DIMENSIONS,
    "embedding_context_tokens": EMBEDDING_CONTEXT_TOKENS,
    "embedding_truncate": False,
    "hnsw:space": DISTANCE_METRIC,
}


class EmbeddingGemmaFunction(embedding_functions.OllamaEmbeddingFunction):
    """Chroma-compatible Ollama adapter with an explicit J.E.B. profile."""

    def __call__(self, input):
        actual = self.model_digest()
        if getattr(self, 'expected_digest', actual) != actual:
            raise ValueError('Installed embedding model differs from the collection; rebuild the project.')
        try:
            response = self._client.embed(
                model=self.model_name,
                input=input,
                truncate=False,
                dimensions=EMBEDDING_DIMENSIONS,
                keep_alive=OLLAMA_KEEP_ALIVE,
            )
        except Exception as exc:
            if getattr(exc, 'status_code', None) in (400, 413, 422):
                raise ValueError(f'Embedding input/profile rejected (context limit '
                                 f'{EMBEDDING_CONTEXT_TOKENS} tokens; no silent truncation): {exc}') from exc
            raise
        vectors = response["embeddings"]
        if len(vectors) != len(input):
            raise ValueError(
                f"Ollama returned {len(vectors)} embeddings for {len(input)} inputs")
        out = []
        for vector in vectors:
            array = np.asarray(vector, dtype=np.float32)
            if array.shape != (EMBEDDING_DIMENSIONS,):
                raise ValueError(
                    f"{OLLAMA_MODEL} returned {array.size} dimensions; "
                    f"expected {EMBEDDING_DIMENSIONS}")
            if not np.isfinite(array).all():
                raise ValueError(f"{OLLAMA_MODEL} returned a non-finite embedding")
            out.append(array)
        return out

    def model_digest(self):
        """Resolve the local tag once per process; never download a model here."""
        if not getattr(self, '_resolved_digest', None):
            for model in self._client.list()['models']:
                name = (model.get('model') or model.get('name')) if isinstance(model, dict) else model.model
                if name == self.model_name:
                    self._resolved_digest = model['digest']
                    break
            else:
                raise ValueError(f'Local embedding model {self.model_name} is not installed.')
        return self._resolved_digest


def embedding_profile(ef):
    return {**EMBEDDING_PROFILE_METADATA, 'embedding_model_digest': ef.model_digest()}


def make_ollama_ef():
    """EmbeddingGemma adapter; prompt prefixing is applied by callers."""
    return EmbeddingGemmaFunction(
        url=OLLAMA_URL,
        model_name=OLLAMA_MODEL,
        timeout=OLLAMA_TIMEOUT_SECONDS,
    )


def doc_prefix(text: str, title: str = "") -> str:
    """Document/corpus prompt."""
    title = " ".join((title or "").replace("|", " ").split())[:200]
    return f"title: {title or 'none'} | text: {text}"


def query_prefix_search(text: str) -> str:
    """Query prompt shared by all distilled security-text collections."""
    return f"task: search result | query: {text}"


def embed_documents(ollama_ef, texts, titles=None):
    """Embed a batch of corpus documents with the document prompt."""
    titles = titles or [""] * len(texts)
    if len(titles) != len(texts):
        raise ValueError("document title count must match document text count")
    return ollama_ef([doc_prefix(text, title) for text, title in zip(texts, titles)])


def embed_query(ollama_ef, collection_name: str, text: str):
    """Embed a single query string with the retrieval prompt."""
    return ollama_ef([query_prefix_search(text)])[0]
