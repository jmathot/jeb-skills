"""
J.E.B. v2 — Phase 4: embed distilled chunks into a per-project ChromaDB.

Each chunk is `{id, embed_text, page_content, metadata}`. The vector is computed
from `embed_text` (distilled, value-suppressed) while `page_content` (raw HTTP /
readable node) is stored as the retrieval document. This separation is what
keeps headers/cookies out of the vectors while leaving them fully available for
deep-dive and `--where-document` substring filtering.
"""
import argparse
import hashlib
import json
import os
import sqlite3
import time

import chromadb

os.environ.setdefault('OLLAMA_TIMEOUT', '3600')
os.environ.setdefault('HTTPX_TIMEOUT', '3600')

from embedding import (COLLECTION_SCHEMA, DISTANCE_METRIC, EMBEDDING_SCHEME,
                       make_ollama_ef, embed_documents)

MAX_BATCH_CHARS = 10000


def resolve_db_path(input_file, db_path_arg):
    if db_path_arg:
        return os.path.abspath(db_path_arg)
    project_dir = os.path.dirname(os.path.abspath(input_file))
    return os.path.join(project_dir, "chroma_db")


def serialize_meta(meta):
    """ChromaDB metadata must be str/int/float/bool. Coerce anything else."""
    out = {}
    for k, v in meta.items():
        if isinstance(v, bool) or isinstance(v, (int, float, str)):
            out[k] = v
        elif isinstance(v, list):
            out[k] = ",".join(map(str, v))
        elif v is None:
            out[k] = ""
        else:
            out[k] = str(v)
    return out


def content_hash(chunk, metadata):
    material = json.dumps({
        'embed_text': chunk['embed_text'],
        'page_content': chunk['page_content'],
        'metadata': metadata,
    }, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(material.encode('utf-8')).hexdigest()


def update_lexical_index(db_path, collection_name, chunks):
    """Mirror distilled text into a dependency-free SQLite FTS5 index."""
    path = os.path.join(db_path, 'jeb_lexical.sqlite')
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE VIRTUAL TABLE IF NOT EXISTS retrieval_fts USING fts5("
            "doc_id UNINDEXED, collection_name UNINDEXED, parent_id UNINDEXED, text)"
        )
        for chunk in chunks:
            parent_id = chunk.get('metadata', {}).get('parent_id', chunk['id'])
            conn.execute(
                "DELETE FROM retrieval_fts WHERE doc_id = ? AND collection_name = ?",
                (chunk['id'], collection_name),
            )
            conn.execute(
                "INSERT INTO retrieval_fts(doc_id, collection_name, parent_id, text) "
                "VALUES (?, ?, ?, ?)",
                (chunk['id'], collection_name, parent_id, chunk['embed_text']),
            )


def update_identifier_index(db_path, collection_name, chunks):
    """Exact-match index of (field, value) identifier pairs per document, kept
    outside Chroma metadata (high-cardinality values don't belong in vector-DB
    metadata) and outside embed_text (no raw entropy in the vectors). Powers
    `jeb-query --identifier <value>` for instance-level cross-endpoint
    correlation, e.g. finding every place a specific user id appears."""
    path = os.path.join(db_path, 'jeb_lexical.sqlite')
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS identifier_index ("
            "value TEXT, field TEXT, doc_id TEXT, collection_name TEXT)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_identifier_value ON identifier_index(value)"
        )
        for chunk in chunks:
            conn.execute(
                "DELETE FROM identifier_index WHERE doc_id = ? AND collection_name = ?",
                (chunk['id'], collection_name),
            )
            pairs = chunk.get('identifier_pairs') or []
            conn.executemany(
                "INSERT INTO identifier_index(value, field, doc_id, collection_name) "
                "VALUES (?, ?, ?, ?)",
                [(value, field, chunk['id'], collection_name) for field, value in pairs],
            )


def upsert_with_retry(collection, documents, embeddings, metadatas, ids, max_retries=5):
    for attempt in range(max_retries):
        try:
            collection.upsert(documents=documents, embeddings=embeddings,
                              metadatas=metadatas, ids=ids)
            return True
        except Exception as e:
            if attempt < max_retries - 1:
                wait = (2 ** attempt) * 10
                print(f"  upsert failed ({attempt+1}/{max_retries}), retry in {wait}s: {str(e)[:120]}")
                time.sleep(wait)
            else:
                raise


def store(collection, chunks, ollama_ef):
    if not chunks:
        print("No chunks to store.")
        return 0

    existing = {}
    try:
        got = collection.get(include=['metadatas'])
        existing = {doc_id: (meta or {}).get('_content_hash', '')
                    for doc_id, meta in zip(got['ids'], got['metadatas'])}
        if existing:
            print(f"Found {len(existing)} existing docs; changed content will be refreshed.")
    except Exception as e:
        print(f"Warning: could not read existing ids: {e}")

    pending = []
    for chunk in chunks:
        metadata = serialize_meta(chunk['metadata'])
        digest = content_hash(chunk, metadata)
        if existing.get(chunk['id']) == digest:
            continue
        prepared = dict(chunk)
        prepared['metadata'] = dict(metadata, _content_hash=digest)
        pending.append(prepared)
    if not pending:
        print(f"All {len(chunks)} chunks already embedded.")
        return 0
    print(f"Embedding {len(pending)}/{len(chunks)} chunks...")

    total, idx, batch_num = 0, 0, 0
    n = len(pending)
    while idx < n:
        batch_num += 1
        batch, chars = [], 0
        while idx < n:
            size = len(pending[idx]['embed_text'])
            if batch and chars + size > MAX_BATCH_CHARS:
                break
            batch.append(pending[idx])
            chars += size
            idx += 1
        embed_texts = [c['embed_text'] for c in batch]
        documents = [c['page_content'] for c in batch]
        metadatas = [c['metadata'] for c in batch]
        ids = [c['id'] for c in batch]
        embeddings = embed_documents(ollama_ef, embed_texts)
        upsert_with_retry(collection, documents, embeddings, metadatas, ids)
        total += len(batch)
        bar_len = 40
        filled = int(bar_len * total / n)
        bar = '█' * filled + '░' * (bar_len - filled)
        print(f"[{bar}] {total:4d}/{n} - batch {batch_num}: {len(batch)} docs ({chars:,} chars)")

    print(f"✓ Embedded {total} documents.")
    return total


def main():
    ap = argparse.ArgumentParser(description="J.E.B. v3 Phase 4: vector storage")
    ap.add_argument('input_file')
    ap.add_argument('--db-path', default=None)
    ap.add_argument('--collection', required=True,
                    help="Target collection: structure | behavior | attacks")
    args = ap.parse_args()

    with open(args.input_file) as f:
        chunks = json.load(f)
    print(f"Loaded {len(chunks)} chunks from {args.input_file}")

    db_path = resolve_db_path(args.input_file, args.db_path)
    os.makedirs(db_path, exist_ok=True)
    print(f"Project ChromaDB at {db_path} (collection: {args.collection})")

    ollama_ef = make_ollama_ef()
    client = chromadb.PersistentClient(path=db_path)
    collection_meta = {"embedding_scheme": EMBEDDING_SCHEME,
                       "collection_schema": COLLECTION_SCHEMA,
                       "hnsw:space": DISTANCE_METRIC}
    existing_names = {c.name for c in client.list_collections()}
    if args.collection in existing_names:
        collection = client.get_collection(args.collection,
                                           embedding_function=ollama_ef)
        meta = collection.metadata or {}
        if meta.get('embedding_scheme') != EMBEDDING_SCHEME or \
                meta.get('hnsw:space') != DISTANCE_METRIC:
            raise SystemExit(
                f"Collection '{args.collection}' uses an incompatible embedding "
                f"scheme or distance metric. Rebuild this project's chroma_db "
                f"before importing with {COLLECTION_SCHEMA}.")
    else:
        collection = client.create_collection(
            name=args.collection,
            embedding_function=ollama_ef,
            metadata=collection_meta,
        )
    total = store(collection, chunks, ollama_ef)
    update_lexical_index(db_path, args.collection, chunks)
    update_identifier_index(db_path, args.collection, chunks)
    print(f"Updated lexical + identifier index for {len(chunks)} documents.")
    print(f"\n✓ Stored {total} documents in collection '{args.collection}'."
          if total else "Nothing new to store.")


if __name__ == '__main__':
    main()
