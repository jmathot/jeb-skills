"""Semantic-only retrieval. Cosine distances are not confidence scores."""
import os

from embedding import embed_query, PRESET
import ontology


def _env_float(name, default):
    value = os.environ.get(name)
    return float(value) if value not in (None, '') else default


# Cutoffs are calibrated for embeddinggemma-2, whose cosine distances are compressed
# (relevant hits 0.20-0.37, off-topic queries 0.41+ on the fixture).
# Query-time knobs (safe to tune without a rebuild); the plugin supplies the
# JEB_* env vars from opencode.json plugin options.
DEFAULT_MAX_DISTANCE = {
    'graph': _env_float('JEB_MAX_DISTANCE_GRAPH', 0.38 if PRESET == 'ollama-embeddinggemma2' else None),
    'attacks': _env_float('JEB_MAX_DISTANCE_ATTACKS', 0.38 if PRESET == 'ollama-embeddinggemma2' else None),
}

# Neighbours summarised per result.
MAX_NEIGHBORS = 6


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
    # Cheap local count, and it avoids an Ollama round trip on an empty project.
    if not agent.collection.count():
        return {'results': [], 'fallback': [], 'diagnostics': diagnostics}
    vector = embed_query(agent.embedding_ef, agent.collection_name, query)
    kwargs = {'query_embeddings': [vector], 'n_results': candidate_k,
              'include': ['metadatas', 'distances']}
    if where:
        kwargs['where'] = where
    if where_document:
        kwargs['where_document'] = where_document
    ceiling = int(os.environ.get('JEB_CANDIDATE_CEILING') or 1000)
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
        # Count what diversity will actually keep, not raw nodes: a route and its
        # behaviors share one anchor, so ten hits can be a single endpoint.
        kept, per_key = 0, {}
        for doc_id, meta, distance in hits:
            if max_distance is not None and distance > max_distance:
                continue
            key = _diversity_key(doc_id, meta)
            if max_per_endpoint <= 0 or per_key.get(key, 0) < max_per_endpoint:
                per_key[key] = per_key.get(key, 0) + 1
                kept += 1
        if kept >= limit or diagnostics['candidates'] < candidate_k or candidate_k >= ceiling:
            break
        candidate_k = min(ceiling, candidate_k * 2)
        kwargs['n_results'] = candidate_k
    diagnostics['eligible_after_filter'] = len(hits)
    selected, fallback, counts = [], [], {}
    for doc_id, meta, distance in sorted(hits, key=lambda hit: (hit[2], hit[0])):
        result = {**agent._summarize(doc_id, meta, distance, snippet_len), 'distance': round(distance, 4)}
        if max_distance is not None and distance > max_distance:
            diagnostics['dropped_by_distance'] += 1
            if len(fallback) < 3:
                fallback.append(result)
            continue
        key = _diversity_key(doc_id, meta)
        if max_per_endpoint > 0 and counts.get(key, 0) >= max_per_endpoint:
            diagnostics['dropped_by_diversity'] += 1
            continue
        counts[key] = counts.get(key, 0) + 1
        if len(selected) < limit:
            selected.append(result)
    _attach_neighbors(agent, selected)
    diagnostics['candidate_limit_reached'] = diagnostics['candidates'] >= candidate_k
    diagnostics['candidate_budget'] = candidate_k
    return {'results': selected, 'fallback': fallback if not selected else [],
            'diagnostics': diagnostics}


def _diversity_key(doc_id, meta):
    """Results fold into the route they hang off. Synthetic nodes and findings are
    results in their own right, so each gets its own key."""
    if meta.get('doc_kind') == 'attack' or meta.get('node_type') in ontology.SYNTHETIC_TYPES:
        return (doc_id,)
    return (meta.get('anchor_id') or doc_id,)


SYMMETRIC_RELS = ('RELATED',)


def _fold_symmetric(rows):
    """One row per (rel, other) for relations stored in both directions."""
    seen, folded = {}, []
    for rel, direction, other in rows:
        if rel in SYMMETRIC_RELS:
            if (rel, other) in seen:
                folded[seen[(rel, other)]] = (rel, 'both', other)
                continue
            seen[(rel, other)] = len(folded)
        folded.append((rel, direction, other))
    return folded


def _attach_neighbors(agent, results):
    """A bounded one-hop summary per result: one edges read, one graph read."""
    if agent.collection_name != 'graph' or not results:
        return
    ids = [r['id'] for r in results]
    edges = agent.neighbors(ids, direction='both', limit=len(ids) * MAX_NEIGHBORS * 4)
    by_node = {}
    for m in edges:
        for node, other, direction in ((m['src'], m['dst'], 'out'), (m['dst'], m['src'], 'in')):
            if node in ids:
                by_node.setdefault(node, []).append((m['rel'], direction, other))
    labels = agent.get_many([other for rows in by_node.values()
                             for _, _, other in rows[:MAX_NEIGHBORS]])
    for result in results:
        rows = _fold_symmetric(by_node.get(result['id'], []))
        if not rows:
            continue
        result['neighbors'] = [
            {'rel': rel, 'dir': direction, 'id': other,
             **{k: v for k, v in (labels.get(other, {}).get('metadata') or {}).items()
                if k in ('node_type', 'method', 'endpoint_template') and v != ''}}
            for rel, direction, other in rows[:MAX_NEIGHBORS]]
        if len(rows) > MAX_NEIGHBORS:
            result['neighbors_total'] = len(rows)
