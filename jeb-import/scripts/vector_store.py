import json
import os
import argparse
import chromadb
import hashlib
import time
from embedding import (
    EMBEDDING_SCHEME,
    make_ollama_ef,
    embed_documents,
)

# Set environment variables for longer timeouts BEFORE importing anything that uses them
os.environ['OLLAMA_TIMEOUT'] = '3600'  # 60 minutes
os.environ['HTTPX_TIMEOUT'] = '3600'


def get_doc_id(doc):
    # Create a unique hash for the document to avoid duplicates
    content = doc['page_content'].encode('utf-8')
    return hashlib.md5(content).hexdigest()


def resolve_db_path(input_file, db_path_arg):
    """
    Each project keeps its OWN ChromaDB inside its project folder. To guarantee
    project databases are never mixed, the DB is always co-located with the input
    chunks file's directory (the project folder) unless an explicit --db-path is
    given. There is deliberately no global/env-var default.
    """
    if db_path_arg:
        return os.path.abspath(db_path_arg)
    project_dir = os.path.dirname(os.path.abspath(input_file))
    return os.path.join(project_dir, "chroma_db")


def serialize_meta(meta):
    """ChromaDB metadata values must be str/int/float/bool. Join list fields."""
    meta = meta.copy()
    for list_key in ['url_params', 'cookies', 'body_params']:
        if list_key in meta and isinstance(meta[list_key], list):
            meta[list_key] = ",".join(meta[list_key])
    # Defensive: coerce any stray list/dict to a string.
    for k, v in list(meta.items()):
        if isinstance(v, (list, dict)):
            meta[k] = ",".join(map(str, v)) if isinstance(v, list) else json.dumps(v)
    return meta


def embed_with_retry(collection, documents, metadatas, ids, embeddings=None, max_retries=5):
    """Upsert with exponential backoff. If embeddings is given, the embedding
    function is bypassed (used for store-only chunks)."""
    for attempt in range(max_retries):
        try:
            kwargs = dict(documents=documents, metadatas=metadatas, ids=ids)
            if embeddings is not None:
                kwargs['embeddings'] = embeddings
            collection.upsert(**kwargs)
            return True
        except Exception as e:
            if attempt < max_retries - 1:
                wait_time = (2 ** attempt) * 10  # 10s, 20s, 40s, 80s, 160s
                print(f"  Upsert failed (attempt {attempt+1}/{max_retries}), "
                      f"retrying in {wait_time}s: {str(e)[:120]}")
                time.sleep(wait_time)
            else:
                raise


def store_embeddable(collection, chunks, ollama_ef):
    """Embed chunks with the document prompt, batched by chars."""
    MAX_BATCH_CHARS = 10000  # ~10KB per batch (small batches to avoid Ollama timeouts)
    
    if not chunks:
        print("No embeddable chunks to process")
        return 0
    
    # Get already-embedded document IDs to skip them
    existing_ids = set()
    try:
        existing = collection.get(include=[])  # Get IDs only, no data
        existing_ids = set(existing['ids'])
        if existing_ids:
            print(f"Found {len(existing_ids)} already-embedded documents, will skip them")
    except Exception as e:
        print(f"Warning: Could not retrieve existing IDs (will re-embed all): {e}")
    
    # Filter out already-embedded chunks
    chunks_to_embed = []
    for chunk in chunks:
        doc_id = get_doc_id(chunk)
        if doc_id not in existing_ids:
            chunks_to_embed.append(chunk)
    
    if not chunks_to_embed:
        print(f"All {len(chunks)} chunks already embedded, nothing to do")
        return 0
    
    print(f"Embedding {len(chunks_to_embed)}/{len(chunks)} chunks...")
    
    total = 0
    idx = 0
    batch_num = 0
    total_chunks = len(chunks_to_embed)
    
    while idx < total_chunks:
        batch_num += 1
        batch = []
        char_count = 0
        while idx < total_chunks:
            size = len(chunks_to_embed[idx]['page_content'])
            if batch and char_count + size > MAX_BATCH_CHARS:
                break
            batch.append(chunks_to_embed[idx])
            char_count += size
            idx += 1
            if not batch:  # safety (unreachable), keep at least one
                break
        documents = [c['page_content'] for c in batch]
        metadatas = [serialize_meta(c['metadata']) for c in batch]
        ids = [get_doc_id(c) for c in batch]
        try:
            embeddings = embed_documents(ollama_ef, documents)
            if embed_with_retry(collection, documents, metadatas, ids, embeddings=embeddings):
                total += len(documents)
                # Progress bar
                pct = (total / total_chunks) * 100
                bar_len = 40
                filled = int(bar_len * total / total_chunks)
                bar = '█' * filled + '░' * (bar_len - filled)
                print(f"[{bar}] {total:4d}/{total_chunks} ({pct:5.1f}%) - Batch {batch_num}: {len(documents)} docs ({char_count:,} chars)")
        except Exception as e:
            print(f"ERROR: Failed to embed batch {batch_num}: {e}")
            raise
    
    print(f"✓ Successfully embedded {total} documents")
    return total


def store_only(collection, chunks, ollama_ef):
    """Store chunks retrievable by id WITHOUT semantically embedding them.

    A single fixed placeholder vector (matching the collection's embedding
    dimension) is reused for all store-only chunks so huge vendor/minified
    bundles remain fetchable by id but do not add noise or embedding cost.
    """
    if not chunks:
        print("No store-only chunks to process")
        return 0
    
    print(f"\nStoring {len(chunks)} store-only chunks (vendor/minified/CSS)...")
    
    # Determine embedding dimensionality with one cheap probe.
    try:
        dim = len(ollama_ef(["probe"])[0])
        print(f"Embedding dimension: {dim}")
    except Exception as e:
        print(f"ERROR: Could not determine embedding dimension: {e}")
        raise
    
    placeholder = [1.0] + [0.0] * (dim - 1)  # non-zero norm avoids cosine errors
    total = 0
    BATCH = 200
    for start in range(0, len(chunks), BATCH):
        batch = chunks[start:start + BATCH]
        documents = [c['page_content'] for c in batch]
        metadatas = [serialize_meta(c['metadata']) for c in batch]
        ids = [get_doc_id(c) for c in batch]
        embeddings = [placeholder for _ in batch]
        try:
            if embed_with_retry(collection, documents, metadatas, ids, embeddings=embeddings):
                total += len(documents)
                pct = (total / len(chunks)) * 100
                print(f"Store-only: {total:4d}/{len(chunks)} ({pct:5.1f}%) - Batch {start//BATCH + 1}: {len(documents)} docs")
        except Exception as e:
            print(f"ERROR: Failed to store batch at offset {start}: {e}")
            raise
    
    print(f"✓ Successfully stored {total} store-only documents")
    return total


def main():
    parser = argparse.ArgumentParser(description="Phase 3: Vector Storage & Embedding")
    parser.add_argument("input_file", help="Path to chunks JSON", nargs='?', default="rag_chunks.json")
    parser.add_argument("--db-path", help="Path to ChromaDB directory (default: <project folder of input_file>/chroma_db)", default=None)
    parser.add_argument("--collection", help="Collection name", default="burp_traffic")
    args = parser.parse_args()

    try:
        with open(args.input_file, 'r') as f:
            chunks = json.load(f)
    except FileNotFoundError:
        print(f"Error: Could not find {args.input_file}")
        return

    print(f"Loaded {len(chunks)} chunks from {args.input_file}")

    db_path = resolve_db_path(args.input_file, args.db_path)
    os.makedirs(db_path, exist_ok=True)
    print(f"Using project ChromaDB at {db_path} (collection: {args.collection})")

    ollama_ef = make_ollama_ef()

    client = chromadb.PersistentClient(path=db_path)
    collection = client.get_or_create_collection(
        name=args.collection,
        embedding_function=ollama_ef,
        metadata={"embedding_scheme": EMBEDDING_SCHEME},
    )

    # Split chunks by their 'embed' flag (traffic chunks have no flag -> embed).
    embeddable = [c for c in chunks if c.get('metadata', {}).get('embed', True)]
    store_chunks = [c for c in chunks if not c.get('metadata', {}).get('embed', True)]

    print(f"\nProcessing {len(embeddable)} embeddable chunks and {len(store_chunks)} store-only chunks...")
    
    total = 0
    try:
        total = store_embeddable(collection, embeddable, ollama_ef)
    except Exception as e:
        print(f"ERROR during embedding: {e}")
        raise
    
    try:
        total += store_only(collection, store_chunks, ollama_ef)
    except Exception as e:
        print(f"ERROR during store-only: {e}")
        raise

    if total > 0:
        print(f"\n✓ Successfully stored {total} documents in ChromaDB collection '{args.collection}'.")
    else:
        print("No documents to store.")


if __name__ == '__main__':
    main()
