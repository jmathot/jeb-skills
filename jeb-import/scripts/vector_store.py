"""
J.E.B. v2 — Phase 4: embed distilled chunks into a per-project ChromaDB.

Each chunk is `{id, embed_text, page_content, metadata}`. The vector is computed
from `embed_text` (distilled, value-suppressed) while `page_content` (raw HTTP /
readable node) is stored as the retrieval document. This separation is what
keeps headers/cookies out of the vectors while leaving them fully available for
deep-dive and `--where-document` substring filtering.
"""
import argparse
import json
import os
import time

import chromadb

os.environ.setdefault('OLLAMA_TIMEOUT', '3600')
os.environ.setdefault('HTTPX_TIMEOUT', '3600')

from embedding import EMBEDDING_SCHEME, make_ollama_ef, embed_documents

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

    existing = set()
    try:
        existing = set(collection.get(include=[])['ids'])
        if existing:
            print(f"Found {len(existing)} already-embedded docs, skipping those.")
    except Exception as e:
        print(f"Warning: could not read existing ids: {e}")

    pending = [c for c in chunks if c['id'] not in existing]
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
        metadatas = [serialize_meta(c['metadata']) for c in batch]
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
    ap = argparse.ArgumentParser(description="J.E.B. v2 Phase 4: vector storage")
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
    collection = client.get_or_create_collection(
        name=args.collection,
        embedding_function=ollama_ef,
        metadata={"embedding_scheme": EMBEDDING_SCHEME},
    )
    total = store(collection, chunks, ollama_ef)
    print(f"\n✓ Stored {total} documents in collection '{args.collection}'."
          if total else "Nothing new to store.")


if __name__ == '__main__':
    main()
