"""Streaming capture import and rebuild. Chroma is the only persistent data store."""
if __name__ == '__main__':
    import sys
    import runtime
    if not runtime.ACTIVE:
        sys.exit(runtime.run('import'))

from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
from urllib.parse import urlparse

import chromadb
import runtime
import build_graph
import distill as d
from ontology import ONTOLOGY_VERSION
from embedding import embedding_profile, make_embedding_ef
from parse import hydrate_item, iter_items, storable
from storage import (LOOKUP_COLLECTIONS, batches, digest, lookup_collection, put_records,
                     scan, delete_ids, sync_edges, sync_identifiers, writer_lock, update_project)
from streaming import (FEATURE_VERSION, IDENTIFIER_VERSION, LOAD_BATCH, PARSER_VERSION,
                       extract_features, identifier_pairs, annotate_features, hydrate_chunks)
from vector_store import semantic_collection, store

# The embedded collections, mirroring COLLECTIONS in the query skill;
# storage.LOOKUP_COLLECTIONS are never embedded.
EMBEDDED_COLLECTIONS = ('graph', 'attacks')
LEGACY_COLLECTIONS = ('structure', 'behavior')


def source_digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def collection_counts(client):
    """Record counts per collection, split the way the database is built.

    A project holds six collections and only the embedded two are semantic search
    targets; `status` reports the split so that is visible without reading the
    source. Absent names are omitted -- a project mid-import has fewer.
    """
    present = {c.name for c in client.list_collections()}
    groups = {'embedded': EMBEDDED_COLLECTIONS, 'lookup': LOOKUP_COLLECTIONS}
    return {group: {name: client.get_collection(name, embedding_function=None).count()
                    for name in names if name in present}
            for group, names in groups.items()}


def project_config(captures, auth_cookies=None, auto_detect=None):
    saved = (captures.metadata or {}).get('analysis_config')
    if saved:
        config = json.loads(saved)
    else:
        # Upgrade prior project-wide config only when historical records agree.
        configs = set()
        for row in scan(captures, include=('documents',)):
            old = json.loads(row['documents'])
            configs.add(json.dumps({k: old.get(k, default) for k, default in
                                   [('auth_cookies', []), ('auto_detect', True)]}, sort_keys=True))
        if len(configs) > 1:
            raise ValueError('Historical configurations disagree; reconcile them before upgrading this project.')
        config = json.loads(configs.pop()) if configs else {'auth_cookies': [], 'auto_detect': True}
    if auth_cookies is not None:
        config['auth_cookies'] = sorted(d.normalize_auth_cookie_names(auth_cookies))
    if auto_detect is not None:
        config['auto_detect'] = auto_detect
    serialized = json.dumps(config, sort_keys=True)
    fields = {'analysis_config': serialized}
    if serialized != saved:
        fields['index_state'] = 'pending'
    update_project(captures, **fields)
    return config


def migrate_attacks(client, ef):
    from findings import repair_identifiers
    names = {c.name for c in client.list_collections()}
    profile = embedding_profile(ef)
    backup_name = 'attacks_rebuild_backup'
    if 'attacks' not in names and backup_name not in names:
        return
    if backup_name not in names:
        attacks = client.get_collection('attacks', embedding_function=None)
        if all((attacks.metadata or {}).get(k) == v for k, v in profile.items()):
            repair_identifiers(client)
            return
        backup = client.create_collection(backup_name, embedding_function=None, metadata={'state': 'copying'})
    else:
        backup = client.get_collection(backup_name, embedding_function=None)
    if (backup.metadata or {}).get('state') == 'copying':
        if 'attacks' not in names:
            raise ValueError('Finding backup incomplete and source missing; restore the database.')
        source = client.get_collection('attacks', embedding_function=None)
        put_records(backup, ({'id': r['id'], 'metadata': r['metadatas'], 'document': r['documents']}
                            for r in scan(source, include=('metadatas', 'documents'), page_size=20)))
        backup.modify(metadata={'state': 'ready'})
    if 'attacks' in {c.name for c in client.list_collections()}:
        current = client.get_collection('attacks', embedding_function=None)
        if any((current.metadata or {}).get(k) != v for k, v in profile.items()):
            client.delete_collection('attacks')
    def chunks():
        for row in scan(backup, include=('metadatas', 'documents'), page_size=20):
            meta = row['metadatas']
            text = meta.get('_embed_text') or d.attack_embed_text({
                'vuln_class': meta.get('vuln_class', ''), 'method': meta.get('method', ''),
                'endpoint_template': meta.get('endpoint_template', ''), 'param': meta.get('param', ''),
                'payload': meta.get('payload', ''), 'status_code': meta.get('status_code', 0),
                'verdict': meta.get('verdict', '')})
            yield {'id': row['id'], 'metadata': {k: v for k, v in meta.items()
                                               if k not in ('_embedding_hash', '_content_hash')},
                   'embed_text': text, 'page_content': row['documents']}
    store(semantic_collection(client, 'attacks', ef), chunks(), ef)
    repair_identifiers(client)
    client.delete_collection(backup_name)


def ingest(client, captures, xml_file, config):
    exchanges = lookup_collection(client, 'exchanges')
    capture_id = source_digest(xml_file)
    previous = captures.get(ids=[capture_id], include=['metadatas', 'documents'])
    if previous['ids']:
        meta = previous['metadatas'][0]
        if meta.get('state') in ('ready', 'complete', 'indexing') and meta.get('parser_version') == PARSER_VERSION:
            print('Capture already retained; rebuilding only when analysis/index versions changed.')
            return capture_id
    # A capture with no prior record cannot have pre-existing exchange or identifier
    # rows (exchange ids derive from this capture's content digest), so the
    # reconciliation work below is only needed for a re-import.
    fresh = not previous['ids']
    meta = {'state': 'parsing', 'source': str(Path(xml_file).resolve()), 'parser_version': PARSER_VERSION}
    document = previous['documents'][0] if previous['ids'] else json.dumps(config)
    def save():
        put_records(captures, [{'id': capture_id, 'metadata': meta, 'document': document}])
    save()
    update_project(captures, index_state='pending')
    count, occurrences = 0, Counter()
    try:
        for group in batches(iter_items(xml_file), 20):
            records, pairs = [], []
            for item in group:
                p = urlparse(item['url'])
                if not p.scheme or not p.hostname or not item['method']:
                    raise ValueError(f'Capture item {count} lacks an absolute URL or HTTP method.')
                fingerprint = digest(item)
                ordinal = occurrences[fingerprint]
                occurrences[fingerprint] += 1
                exchange_id = digest([capture_id, count])
                overlap = digest([fingerprint, ordinal]) if item.get('time') else exchange_id
                item.update(_exchange_id=exchange_id, _capture_id=capture_id, _source_item=count)
                features = extract_features(item)
                records.append({'id': exchange_id, 'metadata': {
                    'capture_id': capture_id, 'source_item': count, 'overlap_key': overlap,
                    'host': p.hostname, 'scheme': p.scheme, 'port': p.port or (443 if p.scheme == 'https' else 80),
                    'method': item['method'].upper(), 'url': item['url'], 'time': item.get('time', ''),
                    'feature_version': FEATURE_VERSION, '_features': json.dumps(features),
                    'identifier_version': IDENTIFIER_VERSION}, 'document': json.dumps(storable(item))})
                pairs.append(identifier_pairs(item))
                count += 1
            sync_identifiers(client, 'exchanges', ({'id': r['id'], 'capture_id': capture_id,
                'identifier_pairs': pr} for r, pr in zip(records, pairs)),
                replace=not fresh)
            put_records(exchanges, records)
        if not fresh:
            # Parser upgrades can change the number of retained records.
            stale = [r['id'] for r in scan(exchanges, where={'capture_id': capture_id})
                     if r['metadatas']['source_item'] >= count]
            sync_identifiers(client, 'exchanges', ({'id': i, 'identifier_pairs': []} for i in stale), replace=True)
            delete_ids(exchanges, stale)
        meta.update(state='ready', exchange_count=count, error='')
        save()
        return capture_id
    except Exception as exc:
        meta.update(state='failed', error=str(exc), exchange_count=count)
        save()
        raise


def loss_ledger(annotated):
    """Counts of what the derived indexes dropped or merged, for `status` and the
    import summary. Cap-driven counters come from distill.LEDGER; the rest are
    read straight off the annotated observations."""
    ledger = d.ledger_snapshot()
    raw_routes = {(a['scheme'], a['host'], a['port'], a['endpoint']) for a in annotated}
    templates = {(a['scheme'], a['host'], a['port'], a['endpoint_template']) for a in annotated}
    ledger.update({
        'observations': len(annotated),
        'routes_raw': len(raw_routes),
        'routes_after_templating': len(templates),
        'routes_merged_by_templating': len(raw_routes) - len(templates),
        'response_bodies_truncated_in_preview': sum(1 for a in annotated if a.get('resp_body_truncated')),
        'request_bodies_truncated_in_preview': sum(1 for a in annotated if a.get('req_body_truncated')),
        'responses_undecodable': sum(1 for a in annotated if a.get('resp_decode_error')),
    })
    return dict(sorted(ledger.items()))


def rebuild_project(client, captures, config, force=False):
    exchanges = lookup_collection(client, 'exchanges')
    ef = make_embedding_ef()
    profile = embedding_profile(ef)
    version = digest([config, FEATURE_VERSION, IDENTIFIER_VERSION, ONTOLOGY_VERSION, profile])
    names = {c.name for c in client.list_collections()}
    if 'attacks_rebuild_backup' in names:
        force = True
    identifiers_missing = 'identifiers' not in names
    profiles_ok = {'graph', 'edges', 'identifiers'} <= names and not set(LEGACY_COLLECTIONS) & names and all(
        all((c.metadata or {}).get(k) == v for k, v in profile.items())
        for c in client.list_collections() if c.name in EMBEDDED_COLLECTIONS)
    if not force and profiles_ok and (captures.metadata or {}).get('index_state') == 'complete' \
            and (captures.metadata or {}).get('index_version') == version:
        print('Project indexes are current.')
        from findings import repair_identifiers
        repair_identifiers(client)
        return
    update_project(captures, index_state='building', index_error='')
    try:
        allowed = sorted(r['id'] for r in scan(captures)
                         if r['metadatas'].get('state') in ('ready', 'complete', 'indexing'))
        if not allowed:
            raise ValueError('No ready captures to rebuild. Import or resume a capture first; existing indexes retained.')
        def load_many(ids):
            """Fetch stored observations by id in one round trip."""
            ids = [i for i in dict.fromkeys(ids) if i]
            if not ids:
                return {}
            got = exchanges.get(ids=ids, include=['documents'])
            return {i: hydrate_item(json.loads(doc)) for i, doc in zip(got['ids'], got['documents'])}

        def resolve_features(rows, capture_id):
            """Compact features for a page of scanned rows.

            Rows whose features or identifiers predate the current versions are
            repaired together: one document fetch, one identifier sync and one
            metadata update per group instead of one of each per row.
            """
            resolved, stale = {}, []
            for row in rows:
                meta = row['metadatas']
                features = json.loads(meta['_features']) if meta.get('feature_version') == FEATURE_VERSION else None
                if features is None or identifiers_missing or meta.get('identifier_version') != IDENTIFIER_VERSION:
                    stale.append((row['id'], features))
                else:
                    resolved[row['id']] = features
            for group in batches(stale, LOAD_BATCH):
                items = load_many([record_id for record_id, _ in group])
                sync, updates = [], []
                for record_id, features in group:
                    item = items[record_id]
                    features = features or extract_features(item)
                    resolved[record_id] = features
                    sync.append({'id': record_id, 'capture_id': capture_id,
                                 'identifier_pairs': identifier_pairs(item)})
                    updates.append({'_features': json.dumps(features),
                                    'feature_version': FEATURE_VERSION,
                                    'identifier_version': IDENTIFIER_VERSION})
                sync_identifiers(client, 'exchanges', sync, replace=True)
                exchanges.update(ids=[record_id for record_id, _ in group], metadatas=updates)
            return resolved

        compact, seen, aliases = [], {}, {}
        # Raw bodies are never accumulated. Only compact features survive this pass.
        for capture_id in allowed:
            for page in batches(scan(exchanges, where={'capture_id': capture_id}, page_size=100), 100):
                features_by_id = resolve_features(page, capture_id)
                for row in page:
                    features = features_by_id[row['id']]
                    overlap = row['metadatas'].get('overlap_key', row['id'])
                    if overlap not in seen:
                        seen[overlap] = row['id']
                        compact.append(features)
                    aliases[row['id']] = seen[overlap]
        annotated, models = annotate_features(compact, load_many, config)
        # Derived associations live on exchanges; segments carry bounded facets only.
        by_id = {a['exchange_id']: a for a in annotated}
        for group in batches(aliases.items()):
            exchanges.update(ids=[i for i, _ in group], metadatas=[{
                'canonical_exchange_id': representative,
                'behavior_id': d.behavior_id(a), 'endpoint_template': a['endpoint_template'],
                'anon_matches_auth': a['anon_matches_auth'],
                'anon_schema_matches_credentialed': a['anon_schema_matches_credentialed'],
                'content_match_count': a['content_match_count'],
                'schema_match_count': a['schema_match_count'],
                'content_match_ids': json.dumps(a['content_match_ids']),
                'schema_match_ids': json.dumps(a['schema_match_ids'])}
                for _, representative in group for a in [by_id[representative]]])
        lookup_collection(client, 'identifiers')
        migrate_attacks(client, ef)
        if identifiers_missing:
            from findings import repair_identifiers
            repair_identifiers(client, force=True)
        chunks, edges = build_graph.build_graph(annotated, models)
        store(semantic_collection(client, 'graph', ef, True),
              hydrate_chunks(chunks, load_many), ef, reconcile=True)
        sync_edges(client, edges)
        del chunks, edges
        for legacy in LEGACY_COLLECTIONS:
            if legacy in names:
                client.delete_collection(legacy)
        from findings import sync_finding_edges
        sync_finding_edges(client)
        ledger = loss_ledger(annotated)
        update_project(captures, index_state='complete', index_version=version, index_error='',
                       loss_ledger=json.dumps(ledger, sort_keys=True))
        print(f'Indexed {len(annotated)} distinct observations from {len(allowed)} ready captures.')
        print('Loss ledger (what the caps cut; every exchange itself is retained verbatim): '
              + json.dumps(ledger, sort_keys=True))
    except Exception as exc:
        update_project(captures, index_state='failed', index_error=str(exc))
        raise


def main():
    parser = runtime.import_parser()
    args = parser.parse_args(runtime.import_argv(sys.argv[1:]))
    db_path = str(Path(args.project_dir).resolve() / 'chroma_db')
    if args.command != 'import' and not Path(db_path).is_dir():
        parser.error('Project database does not exist.')
    with writer_lock(db_path, shared=args.command in ('status', 'export')):
        d.ledger_reset()
        client = chromadb.PersistentClient(path=db_path)
        captures = lookup_collection(client, 'captures')
        if args.command == 'status':
            print(json.dumps({'project': captures.metadata,
                              'collections': collection_counts(client),
                              'captures': list(scan(captures))}, indent=2))
            return
        if args.command == 'export':
            col = client.get_collection(args.collection, embedding_function=None)
            with open(args.output, 'x') as handle:
                for row in scan(col, include=('metadatas', 'documents'), page_size=20):
                    handle.write(json.dumps(row) + '\n')
            return
        if args.command == 'abandon':
            got = captures.get(ids=[args.capture_id], include=['metadatas'])
            if not got['ids'] or got['metadatas'][0].get('state') not in ('failed', 'parsing', 'abandoned'):
                raise ValueError('Only failed or interrupted captures can be abandoned.')
            captures.update(ids=[args.capture_id], metadatas=[{'state': 'abandoned'}])
            update_project(captures, index_state='pending')
            print('Capture excluded; source records retained. Run rebuild to refresh derived indexes.')
            return
        runtime.persist(captures)
        config = project_config(captures, args.auth_cookies, args.auto_detect)
        if args.command == 'import':
            ingest(client, captures, args.xml_file, config)
        rebuild_project(client, captures, config, args.command == 'rebuild' or args.rebuild)


if __name__ == '__main__':
    main()
