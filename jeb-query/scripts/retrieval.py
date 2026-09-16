"""Semantic-only retrieval. Cosine distances are not confidence scores."""
from embedding import embed_query

DEFAULT_MAX_DISTANCE = {'structure': 0.65, 'behavior': 0.70, 'attacks': 0.70}


def search(agent, query, n_results=8, where=None, where_document=None,
           snippet_len=200, candidate_k=40, max_distance='default',
           max_per_endpoint=2, post=None):
    limit = max(1, min(int(n_results), 100))
    candidate_k = max(limit, min(int(candidate_k), 500))
    if max_distance == 'default':
        max_distance = DEFAULT_MAX_DISTANCE.get(agent.collection_name)
    if max_distance is not None and not 0 <= float(max_distance) <= 2:
        raise ValueError('Cosine distance cutoff must be between 0 and 2.')
    if max_distance is not None:
        max_distance = float(max_distance)
    diagnostics = {'candidates': 0, 'eligible_after_filter': 0,
                   'dropped_by_distance': 0, 'dropped_by_diversity': 0}
    if not agent.collection.count():
        return {'results': [], 'fallback': [], 'diagnostics': diagnostics}
    vector = embed_query(agent.ollama_ef, agent.collection_name, query)
    kwargs = {'query_embeddings': [vector], 'n_results': candidate_k,
              'include': ['metadatas', 'distances']}
    if agent.has_segments:
        kinds = ['parent', 'variant'] if where_document else ['segment', 'variant']
        kwargs['where'] = agent._and_where(where, {'granularity': {'$in': kinds}})
    elif where:
        kwargs['where'] = where
    if where_document:
        kwargs['where_document'] = where_document
    ceiling = 1000
    while True:
        found = agent.collection.query(**kwargs)
        hits = []
        diagnostics['candidates'] = len(found['ids'][0])
        for doc_id, meta, distance in zip(found['ids'][0], found['metadatas'][0],
                                          found['distances'][0]):
            meta = meta or {}
            if all(predicate(meta) for predicate in (post or [])):
                hits.append((doc_id, meta, float(distance)))
        diagnostics['dropped_by_post_filter'] = diagnostics['candidates'] - len(hits)
        eligible = {m.get('parent_id', i) for i, m, distance in hits
                    if max_distance is None or distance <= max_distance}
        if len(eligible) >= limit or diagnostics['candidates'] < candidate_k or candidate_k >= ceiling:
            break
        candidate_k = min(ceiling, candidate_k * 2)
        kwargs['n_results'] = candidate_k
    parents = agent.get_many([m.get('parent_id', i) for i, m, _ in hits])
    ranked = {}
    for doc_id, meta, distance in sorted(hits, key=lambda hit: (hit[2], hit[0])):
        parent_id = meta.get('parent_id', doc_id)
        if parent_id not in parents:
            continue
        result = ranked.setdefault(parent_id, {
            **agent._summarize(parent_id, parents[parent_id]['metadata'], distance, snippet_len),
            'distance': distance, 'matched_ids': [], 'representations': [],
            'matched_variants': [],
        })
        result['matched_ids'].append(doc_id)
        representation = meta.get('representation', 'parent')
        if representation not in result['representations']:
            result['representations'].append(representation)
        if meta.get('granularity') == 'variant':
            result['matched_variants'].append(doc_id)
    diagnostics['eligible_after_filter'] = len(ranked)
    selected, fallback, counts = [], [], {}
    for result in ranked.values():
        distance = result['distance']
        result['distance'] = round(distance, 4)
        if not result['matched_variants']:
            del result['matched_variants']
        if max_distance is not None and distance > max_distance:
            diagnostics['dropped_by_distance'] += 1
            if len(fallback) < 3:
                fallback.append(result)
            continue
        meta = parents[result['id']]['metadata']
        key = tuple(meta.get(k, '') for k in ('scheme', 'host', 'port', 'method',
                                               'endpoint_template'))
        # Synthetic entity/auth-model nodes are distinct results, not one route.
        if meta.get('node_kind') in ('entity', 'auth_model'):
            key += (result['id'],)
        if max_per_endpoint > 0 and counts.get(key, 0) >= max_per_endpoint:
            diagnostics['dropped_by_diversity'] += 1
            continue
        counts[key] = counts.get(key, 0) + 1
        if len(selected) < limit:
            selected.append(result)
    diagnostics['candidate_limit_reached'] = diagnostics['candidates'] >= candidate_k
    diagnostics['candidate_budget'] = candidate_k
    return {'results': selected, 'fallback': fallback if not selected else [],
            'diagnostics': diagnostics}
