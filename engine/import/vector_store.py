"""Stream derived documents into Chroma, retaining unchanged distilled vectors."""
import argparse
import json
import os
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
import chromadb
from embedding import EMBEDDING_SCHEME, embed_documents, make_ollama_ef, embedding_profile
from storage import digest, scan, delete_ids, writer_lock, batches

# Embedding batch budget; each flush is one Ollama request. Measured throughput is
# nearly flat past ~32 documents (36.6 ms/doc at 32 vs 34.7 at 128 on EmbeddingGemma),
# because the cost is per-document compute rather than request overhead -- so the
# doc cap stays conservative, keeping the re-work small when a batch has to retry.
# The char budget only exists to stop a few long documents making an oversized
# request; the 2048-token limit is per *document*, not per batch, so it can be
# generous. Distilled embed_text runs a few hundred chars, so the doc cap normally
# binds first. Vectors are computed per input, so batching never changes them.
MAX_BATCH_DOCS = int(os.environ.get('JEB_EMBED_BATCH_DOCS') or 32)
MAX_BATCH_CHARS = int(os.environ.get('JEB_EMBED_BATCH_CHARS') or 48000)
# Concurrent Ollama requests. 1 restores the strictly serial behavior.
EMBED_WORKERS = max(1, int(os.environ.get('JEB_EMBED_WORKERS') or 2))


def serialize_meta(meta):
    return {k: v if isinstance(v, (str, int, float, bool)) else
            ','.join(map(str, v)) if isinstance(v, list) else '' if v is None else str(v)
            for k, v in meta.items()}


def document_batches(chunks):
    batch, chars = [], 0
    for chunk in chunks:
        size = len(chunk['embed_text'])
        if batch and (len(batch) >= MAX_BATCH_DOCS or chars + size > MAX_BATCH_CHARS):
            yield batch
            batch, chars = [], 0
        batch.append(chunk)
        chars += size
    if batch:
        yield batch


def _embed_with_retry(ollama_ef, values):
    for attempt in range(3):
        try:
            return embed_documents(ollama_ef, [c['embed_text'] for c in values],
                                   [c.get('embedding_title', '') for c in values])
        except Exception as exc:
            if isinstance(exc, ValueError) or getattr(exc, 'status_code', None) in (400, 404, 413, 422) or attempt == 2:
                raise
            time.sleep(2 ** attempt)


def store(collection, chunks, ollama_ef, reconcile=False):
    """Embed and write `chunks`, keeping up to EMBED_WORKERS Ollama requests in flight.

    Embedding is the dominant cost of an import and Chroma is not involved in it,
    so a batch is classified (one metadata read), handed to a worker, and written
    when its turn comes. Writes stay strictly in batch order on this thread, and
    each batch embeds exactly the inputs the serial version would, so the stored
    vectors and records are identical.
    """
    wanted, total, embedded, cache = set(), 0, 0, {}
    inflight = deque()
    ollama_ef.model_digest()  # resolve once, before any worker thread needs it
    executor = ThreadPoolExecutor(max_workers=EMBED_WORKERS) if EMBED_WORKERS > 1 else None

    def finish(entry):
        nonlocal embedded, cache
        future, keys, pending, known = entry
        vectors = dict(known)
        if future is not None:
            vectors.update(zip(keys, future.result()))
            embedded += len(keys)
        cache.update(vectors)
        if pending:
            collection.upsert(ids=[c['id'] for c in pending], documents=[c['page_content'] for c in pending],
                              metadatas=[c['metadata'] for c in pending],
                              embeddings=[vectors[c['metadata']['_embedding_hash']] for c in pending])
        # Bounded process-local cache; no second persistent index.
        if len(cache) > 1024:
            cache = dict(list(cache.items())[-512:])

    try:
        for batch in document_batches(chunks):
            got = collection.get(ids=[c['id'] for c in batch], include=['metadatas'])
            existing = dict(zip(got['ids'], got['metadatas']))
            pending, updates = [], []
            for chunk in batch:
                wanted.add(chunk['id'])
                total += 1
                meta = serialize_meta(chunk['metadata'])
                text, title = chunk['embed_text'], chunk.get('embedding_title', '')
                eh = digest([EMBEDDING_SCHEME, (collection.metadata or {}).get('embedding_model_digest'), text, title])
                ch = digest([eh, chunk['page_content'], meta])
                old = existing.get(chunk['id']) or {}
                if old.get('_content_hash') == ch:
                    continue
                meta.update(_content_hash=ch, _embedding_hash=eh, _embed_text=text, _embedding_title=title)
                prepared = dict(chunk, metadata=meta)
                (updates if old.get('_embedding_hash') == eh else pending).append(prepared)
            if updates:
                # The document may have changed, so it must be re-sent; passing it
                # without embeddings would re-embed via the collection's function and
                # skip the prompt prefixes, hence the explicit vector round trip.
                got = collection.get(ids=[c['id'] for c in updates], include=['embeddings'])
                vectors = dict(zip(got['ids'], got['embeddings']))
                collection.update(ids=[c['id'] for c in updates],
                                  documents=[c['page_content'] for c in updates],
                                  metadatas=[c['metadata'] for c in updates],
                                  embeddings=[vectors[c['id']] for c in updates])
            hashes = {c['metadata']['_embedding_hash'] for c in pending}
            known = {h: cache[h] for h in hashes if h in cache}
            unique = {c['metadata']['_embedding_hash']: c for c in pending
                      if c['metadata']['_embedding_hash'] not in known}
            future = None
            if unique:
                values = list(unique.values())
                future = (executor.submit(_embed_with_retry, ollama_ef, values) if executor
                          else _Done(_embed_with_retry(ollama_ef, values)))
            inflight.append((future, list(unique), pending, known))
            while len(inflight) >= max(EMBED_WORKERS, 1):
                finish(inflight.popleft())
        while inflight:
            finish(inflight.popleft())
    finally:
        if executor:
            executor.shutdown(wait=True, cancel_futures=True)
    if reconcile:
        stale = [r['id'] for r in scan(collection, include=()) if r['id'] not in wanted]
        delete_ids(collection, stale)
    print(f'{collection.name}: {total} records; {embedded} embedding inputs processed')
    return embedded


class _Done:
    """A completed result with the Future interface, for the serial path."""
    def __init__(self, value):
        self._value = value

    def result(self):
        return self._value


def semantic_collection(client, name, ef, rebuild=False):
    profile = embedding_profile(ef)
    if name in {c.name for c in client.list_collections()}:
        col = client.get_collection(name, embedding_function=ef)
        if any((col.metadata or {}).get(k) != v for k, v in profile.items()):
            if not rebuild or name == 'attacks':
                raise ValueError(f'{name} requires an evidence-preserving project rebuild.')
            client.delete_collection(name)
        else:
            return col
    return client.create_collection(name, embedding_function=ef, metadata=profile)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input_file', help='explicit previously exported chunk JSON')
    parser.add_argument('--db-path', required=True)
    parser.add_argument('--collection', choices=('structure', 'behavior'), required=True)
    args = parser.parse_args()
    with open(args.input_file) as handle:
        chunks = json.load(handle)
    with writer_lock(args.db_path):
        client = chromadb.PersistentClient(path=args.db_path)
        ef = make_ollama_ef()
        store(semantic_collection(client, args.collection, ef), chunks, ef)


if __name__ == '__main__':
    main()
