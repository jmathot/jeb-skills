"""Streaming capture import and rebuild. Chroma is the only persistent data store."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
from urllib.parse import urlparse

import chromadb
import build_behavior
import build_structure
import distill as d
from embedding import embedding_profile, make_ollama_ef
from parse import iter_items
from storage import (batches, digest, lookup_collection, put_records, scan, delete_ids,
                     sync_identifiers, writer_lock, update_project)
from streaming import (FEATURE_VERSION, IDENTIFIER_VERSION, PARSER_VERSION,
                       extract_features, identifier_pairs, annotate_features, hydrate_chunks)
from vector_store import semantic_collection, store


def source_digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


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
            records = []
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
                    'identifier_version': ''}, 'document': json.dumps(item)})
                count += 1
            put_records(exchanges, records)
            sync_identifiers(client, 'exchanges', ({'id': r['id'], 'capture_id': capture_id,
                'identifier_pairs': identifier_pairs(json.loads(r['document']))} for r in records),
                replace=not fresh)
            exchanges.update(ids=[r['id'] for r in records],
                             metadatas=[{'identifier_version': IDENTIFIER_VERSION} for _ in records])
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


def rebuild_project(client, captures, config, force=False):
    exchanges = lookup_collection(client, 'exchanges')
    ef = make_ollama_ef()
    profile = embedding_profile(ef)
    version = digest([config, FEATURE_VERSION, IDENTIFIER_VERSION, profile])
    names = {c.name for c in client.list_collections()}
    if 'attacks_rebuild_backup' in names:
        force = True
    identifiers_missing = 'identifiers' not in names
    profiles_ok = {'structure', 'behavior', 'identifiers'} <= names and all(
        all((c.metadata or {}).get(k) == v for k, v in profile.items())
        for c in client.list_collections() if c.name in ('structure', 'behavior', 'attacks'))
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
            return {i: json.loads(doc) for i, doc in zip(got['ids'], got['documents'])}

        load_item = lambda record_id: load_many([record_id])[record_id]
        compact, seen, aliases = [], {}, {}
        # Raw bodies are never accumulated. Only compact features survive this pass.
        for capture_id in allowed:
            for row in scan(exchanges, where={'capture_id': capture_id}, page_size=100):
                meta = row['metadatas']
                features = json.loads(meta['_features']) if meta.get('feature_version') == FEATURE_VERSION else None
                if features is None or identifiers_missing or meta.get('identifier_version') != IDENTIFIER_VERSION:
                    item = load_item(row['id'])
                    features = features or extract_features(item)
                    sync_identifiers(client, 'exchanges', [{'id': row['id'], 'capture_id': capture_id,
                                      'identifier_pairs': identifier_pairs(item)}], replace=True)
                    exchanges.update(ids=[row['id']], metadatas=[{'_features': json.dumps(features),
                        'feature_version': FEATURE_VERSION, 'identifier_version': IDENTIFIER_VERSION}])
                overlap = meta.get('overlap_key', row['id'])
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
        nodes = build_structure.build_endpoint_nodes(annotated)
        entities, entity_of = build_structure.build_entities(nodes)
        def structure_chunks():
            yield from (build_structure.endpoint_chunk(n, entity_of) for n in nodes)
            yield from (build_structure.auth_model_chunk(o, m) for o, m in models.items())
            yield from (build_structure.entity_chunk(e, entity_of[e['schema_sig']]) for e in entities)
            yield from build_structure.build_segments(nodes, models, entity_of, entities)
        store(semantic_collection(client, 'structure', ef, True), structure_chunks(), ef, reconcile=True)
        del nodes, entities, entity_of
        def behavior_chunks():
            yield from build_behavior.build(annotated)
            yield from build_behavior.build_segments(annotated)
            yield from build_behavior.build_variants(annotated)
        store(semantic_collection(client, 'behavior', ef, True),
              hydrate_chunks(behavior_chunks(), load_many), ef, reconcile=True)
        update_project(captures, index_state='complete', index_version=version, index_error='')
        print(f'Indexed {len(annotated)} distinct observations from {len(allowed)} ready captures.')
    except Exception as exc:
        update_project(captures, index_state='failed', index_error=str(exc))
        raise


def main():
    argv = sys.argv[1:]
    commands = ('import', 'rebuild', 'status', 'abandon', 'export')
    if argv and argv[0] not in commands and argv[0] not in ('--help', '-h'):
        argv.insert(0, 'import')  # legacy capture.xml [project_dir] invocation
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest='command', required=True)
    for command in commands:
        p = subs.add_parser(command)
        if command == 'import':
            p.add_argument('xml_file')
        if command == 'abandon':
            p.add_argument('capture_id')
        p.add_argument('project_dir', nargs='?', default='.')
        if command in ('import', 'rebuild'):
            p.add_argument('--auth-cookies', action='append', default=None,
                           help='explicitly replace project custom cookie names; empty string clears')
            group = p.add_mutually_exclusive_group()
            group.add_argument('--auto-detect-auth-cookies', dest='auto_detect', action='store_true')
            group.add_argument('--no-auto-detect-auth-cookies', dest='auto_detect', action='store_false')
            p.set_defaults(auto_detect=None)
            p.add_argument('--rebuild', action='store_true', help='force derived index rebuild')
        if command == 'export':
            p.add_argument('--collection', choices=('structure', 'behavior', 'attacks', 'captures', 'exchanges'), required=True)
            p.add_argument('--output', required=True, help='explicit NDJSON destination; must not exist')
    args = parser.parse_args(argv)
    db_path = str(Path(args.project_dir).resolve() / 'chroma_db')
    if args.command != 'import' and not Path(db_path).is_dir():
        parser.error('Project database does not exist.')
    with writer_lock(db_path):
        client = chromadb.PersistentClient(path=db_path)
        captures = lookup_collection(client, 'captures')
        if args.command == 'status':
            print(json.dumps({'project': captures.metadata, 'captures': list(scan(captures))}, indent=2))
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
        config = project_config(captures, args.auth_cookies, args.auto_detect)
        if args.command == 'import':
            ingest(client, captures, args.xml_file, config)
        rebuild_project(client, captures, config, args.command == 'rebuild' or args.rebuild)


if __name__ == '__main__':
    main()
