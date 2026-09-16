"""Small Chroma helpers shared by ingestion and query commands.

Lookup collections use fixed one-dimensional vectors and never call Ollama.
Their records are accessed exclusively through get()/metadata equality.
"""
import hashlib
import json
from contextlib import contextmanager
from pathlib import Path
from itertools import islice

LOOKUP_COLLECTIONS = ('captures', 'exchanges', 'identifiers')
LOOKUP_SCHEMA = 'jeb-observations-v1'
PAGE_SIZE = 500


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                                    separators=(',', ':')).encode()).hexdigest()


def origin(meta):
    host = meta.get('host', '')
    if ':' in host and not host.startswith('['):
        host = f'[{host}]'
    return f"{meta.get('scheme', '')}://{host}:{meta.get('port', '')}"


def lookup_collection(client, name):
    collection = client.get_or_create_collection(
        name, embedding_function=None, metadata={'lookup_schema': LOOKUP_SCHEMA})
    if (collection.metadata or {}).get('lookup_schema') != LOOKUP_SCHEMA:
        raise ValueError(f'Unsupported lookup schema in {name}; preserve the database before migration.')
    return collection


def scan(collection, include=('metadatas',), page_size=PAGE_SIZE, **kwargs):
    """Page deterministic lookups without silently imposing a corpus cap."""
    kwargs.pop('limit', None)
    offset = 0
    while True:
        page = collection.get(include=list(include), limit=page_size,
                              offset=offset, **kwargs)
        for index, record_id in enumerate(page['ids']):
            row = {'id': record_id}
            for field in include:
                row[field] = page[field][index]
            yield row
        if len(page['ids']) < page_size:
            break
        offset += len(page['ids'])


def get_all(collection, **kwargs):
    include = kwargs.pop('include', ['metadatas'])
    result = {'ids': [], **{key: [] for key in include}}
    for row in scan(collection, include=include, **kwargs):
        result['ids'].append(row['id'])
        for key in include:
            result[key].append(row[key])
    return result


def batches(records, size=PAGE_SIZE):
    iterator = iter(records)
    while batch := list(islice(iterator, size)):
        yield batch


def put_records(collection, records):
    for batch in batches(records):
        collection.upsert(ids=[r['id'] for r in batch],
                          metadatas=[r['metadata'] for r in batch],
                          documents=[r['document'] for r in batch],
                          embeddings=[[1.0] for _ in batch])


def delete_ids(collection, ids):
    for start in range(0, len(ids), PAGE_SIZE):
        collection.delete(ids=ids[start:start + PAGE_SIZE])


def sync_identifiers(client, source_collection, records, replace=False):
    """Stream occurrences and reconcile only the supplied source documents.

    New rows are written before stale rows are deleted; retries are idempotent.
    """
    collection = lookup_collection(client, 'identifiers')
    for record in records:
        desired = []
        for field, value in sorted(set(map(tuple, record.get('identifier_pairs', [])))):
            meta = {'value': str(value), 'field': field, 'doc_id': record['id'],
                    'source_collection': source_collection}
            if record.get('capture_id'):
                meta['capture_id'] = record['capture_id']
            desired.append({'id': digest(meta), 'metadata': meta,
                            'document': f'{field}: {value}'})
        put_records(collection, desired)
        if replace:
            wanted = {r['id'] for r in desired}
            stale = [r['id'] for r in scan(collection, include=(), where={'$and': [
                {'source_collection': source_collection}, {'doc_id': record['id']}]})
                     if r['id'] not in wanted]
            delete_ids(collection, stale)


def update_project(captures, **fields):
    """Project state lives in collection metadata, separate from capture history."""
    captures.modify(metadata={**(captures.metadata or {}), **fields})


@contextmanager
def writer_lock(db_path):
    """OS-released advisory lock: concurrent writers fail, crashed writers unlock."""
    import fcntl
    Path(db_path).mkdir(parents=True, exist_ok=True)
    with open(Path(db_path) / '.jeb-writer.lock', 'a') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError('Another J.E.B. writer is active for this project.') from exc
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)
