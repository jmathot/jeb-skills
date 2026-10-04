"""
J.E.B. v4 — visualizer (standalone).

Two modes against a project's ChromaDB:

  --mode embedding (default)
    Renders the vector space as an interactive scatter (UMAP/t-SNE/PCA) so
    you can inspect canonical documents and protocol-aware semantic child
    vectors. Alongside the scatter it emits nearest-neighbour, tight-cluster,
    collection/schema, representation coverage, and parent-child distance
    diagnostics.

  --mode graph
    Renders the `structure` collection as a site map: a tree of
    pages/endpoints/actions under each host's auth_model root, entity nodes
    linked to the endpoints that produce/consume them, colored by
    access_control posture, with an optional ring showing the worst
    recorded `attacks` verdict per endpoint.

Usage:
  python visualize.py --db-path ./chroma_db --collection all \
      --color-by collection --out vector_space.html
  python visualize.py --db-path ./chroma_db --mode graph --out site_map.html

Deps (viz only): numpy, scikit-learn, plotly, optional umap-learn.
  pip install -r requirements-viz.txt
"""
import argparse
import html
import os
import sys
from collections import Counter, defaultdict

try:
    import numpy as np
    import chromadb
    from sklearn.neighbors import NearestNeighbors
    from sklearn.cluster import DBSCAN
    from sklearn.decomposition import PCA
except ImportError as e:
    sys.exit(f"Missing a viz dependency ({e.name}). Install with:\n"
             f"  pip install -r {os.path.join(os.path.dirname(__file__), 'requirements-viz.txt')}")

KNOWN_COLLECTIONS = ('structure', 'behavior', 'attacks')
DEFAULT_COLOR = {
    'structure': 'node_kind',
    'behavior': 'auth_role',
    'attacks': 'vuln_class',
    'canonical': 'doc_kind',
    'segments': 'representation',
    'all': 'collection',
}
NEAR_DUP_EPS = 0.05

ACCESS_CONTROL_COLOR = {
    'open-data': '#dc2626',
    'soft-auth-wall': '#d97706',
    'enforced': '#16a34a',
    'unknown': '#6b7280',
}
NODE_KIND_COLOR = {
    'auth_model': '#2563eb',
    'entity': '#7c3aed',
}
VERDICT_RING = {
    'vulnerable': '#dc2626',
    'not_vulnerable': '#16a34a',
    'inconclusive': '#6b7280',
}
VERDICT_PRIORITY = ('vulnerable', 'inconclusive', 'not_vulnerable')


def neighbors_int(value):
    value = int(value)
    if value < 2:
        raise argparse.ArgumentTypeError("must be at least 2")
    return value


def nonnegative_int(value):
    value = int(value)
    if value < 0:
        raise argparse.ArgumentTypeError("must be 0 or greater")
    return value


def unit_float(value):
    value = float(value)
    if not 0.0 <= value <= 1.0:
        raise argparse.ArgumentTypeError("must be between 0 and 1")
    return value


def html_escape(value):
    return html.escape(str(value), quote=True)


def _connect(db_path):
    client = chromadb.PersistentClient(path=os.path.abspath(db_path))
    have = {c.name for c in client.list_collections()}
    return client, have


# ---------------------------------------------------------------------------
# Embedding-space mode
# ---------------------------------------------------------------------------

def load(db_path, collections, sample=0):
    """structure/behavior hold both canonical ('parent') and semantic child
    ('segment') documents together, distinguished by the `granularity`
    metadata field (v4+) rather than by collection name. --collection
    canonical/segments load every known collection and keep only one record
    type; a plain collection name loads both types from that collection."""
    client, have = _connect(db_path)
    record_filter = None
    if collections == ['all']:
        collections = [c for c in KNOWN_COLLECTIONS if c in have]
    elif len(collections) == 1 and collections[0] in ('canonical', 'segments'):
        record_filter = 'canonical' if collections[0] == 'canonical' else 'segment'
        collections = [c for c in KNOWN_COLLECTIONS if c in have]
    ids, embs, metas = [], [], []
    collection_info = {}
    population = []
    from storage import get_all
    record_where = ({'granularity': 'parent'} if record_filter == 'canonical'
                    else {'granularity': 'segment'} if record_filter else None)
    for name in collections:
        if name not in have:
            continue
        col = client.get_collection(name)
        collection_info[name] = dict(col.metadata or {})
        population.extend((name, i) for i in get_all(
            col, include=[], **({'where': record_where} if record_where else {}))['ids'])
    population.sort()
    total_count = len(population)
    if sample and total_count > sample:
        indices = np.random.RandomState(42).choice(total_count, sample, replace=False)
        population = [population[int(i)] for i in sorted(indices)]
    selected_by_collection = defaultdict(list)
    for name, doc_id in population:
        selected_by_collection[name].append(doc_id)
    for name in collections:
        if name not in have:
            print(f"  (skipping '{name}': not in DB)")
            continue
        col = client.get_collection(name)
        collection_info[name] = dict(col.metadata or {})
        selected = selected_by_collection[name]
        got = {'ids': [], 'embeddings': [], 'metadatas': []}
        for start in range(0, len(selected), 500):
            page = col.get(ids=selected[start:start + 500], include=['embeddings', 'metadatas'])
            for field in got:
                got[field].extend(page[field])
        n = len(got['ids'])
        if not n:
            continue
        kept = 0
        for doc_id, emb, m in zip(got['ids'], got['embeddings'], got['metadatas']):
            m = dict(m or {})
            record_type = m.get('granularity', 'parent')
            record_type = 'canonical' if record_type == 'parent' else record_type
            if record_filter and record_type != record_filter:
                continue
            m.setdefault('doc_kind', name)
            m['collection'] = name
            m['document_id'] = doc_id
            m['record_type'] = record_type
            ids.append(f"{name}:{doc_id}")
            embs.append(emb)
            metas.append(m)
            kept += 1
        print(f"  {name}: {kept} vectors" + ("" if kept == n else f" (of {n} loaded)"))
    if not ids:
        sys.exit("No vectors found. Did you run the import pipeline?")
    return ids, np.asarray(embs, dtype=float), metas, collection_info, total_count


def reduce_dims(embs, method, neighbors, min_dist):
    n = len(embs)
    if n == 1:
        return np.zeros((1, 2)), 'single-point'
    if n == 2:
        first, second = embs
        denom = np.linalg.norm(first) * np.linalg.norm(second)
        distance = 1.0 - float(np.dot(first, second) / denom) if denom else 1.0
        return np.asarray([[0.0, 0.0], [distance, 0.0]]), 'cosine-distance'
    if n < 4 or method == 'pca':
        return PCA(n_components=2).fit_transform(embs), 'pca'
    if method in ('umap', None):
        try:
            import umap
            reducer = umap.UMAP(n_components=2, metric='cosine',
                                n_neighbors=min(neighbors, n - 1),
                                min_dist=min_dist, random_state=42)
            return reducer.fit_transform(embs), 'umap'
        except ImportError:
            print("  umap-learn not installed; falling back to PCA "
                  "(pip install umap-learn for better structure).")
            return PCA(n_components=2).fit_transform(embs), 'pca'
    if method == 'tsne':
        from sklearn.manifold import TSNE
        per = max(2, min(30, (n - 1) // 3, n - 1))
        return TSNE(n_components=2, metric='cosine', init='random',
                    perplexity=per, random_state=42).fit_transform(embs), 'tsne'
    return PCA(n_components=2).fit_transform(embs), 'pca'


def _hover(m):
    """Hover text for an embedding-space point. Branches by node_kind/
    collection so structure entity/auth_model docs and attacks docs — whose
    useful fields aren't method/status_code/auth_role — show what they
    actually carry instead of blanks."""
    collection = m.get('collection', '')
    kind = m.get('node_kind', '')
    if collection == 'structure' and kind == 'entity':
        lines = [
            f"<b>ENTITY</b> identifier_field={m.get('identifier_field', '') or '-'}",
            f"schema_sig={str(m.get('schema_sig', ''))[:12]}",
            f"produced_by={m.get('produced_by', '') or '-'}",
            f"consumed_by={m.get('consumed_by', '') or '-'}",
        ]
    elif collection == 'structure' and kind == 'auth_model':
        lines = [
            f"<b>AUTH_MODEL</b> @ {m.get('host', '')}",
            f"mechanisms={m.get('auth_mechanisms', '') or '-'}",
            f"cookies_set={m.get('cookies_set', '') or '-'} "
            f"cookies_sent={m.get('cookies_sent', '') or '-'}",
            f"cors={m.get('cors', '') or '-'}",
        ]
    elif collection == 'attacks':
        lines = [
            f"<b>ATTACK</b> {m.get('vuln_class', '')} verdict={m.get('verdict', '')} "
            f"severity={m.get('severity', '') or '-'}",
            f"{m.get('method', '')} {m.get('endpoint_template', '')} "
            f"param={m.get('param', '') or '-'}",
            f"status={m.get('status_code', '')}",
        ]
    else:
        lines = [
            f"<b>{collection}</b> {m.get('method', '')} {m.get('endpoint_template', '')}",
            f"representation={m.get('representation', 'canonical')} "
            f"parent={m.get('parent_id', '-')}",
            f"status={m.get('status_code', '')} "
            f"auth={m.get('auth_role', m.get('auth_mechanisms', ''))}",
        ]
    lines.append(m.get('summary', ''))
    return "<br>".join(lines)


def _cors_group_value(m, color_by):
    """behavior.cors carries a `' creds'` suffix that structure.cors doesn't
    (see agent_interface.py's CORS_OPEN note). Grouping raw would split one
    posture into misleading separate legend buckets across --collection all;
    strip it for grouping only, hover text still shows the raw value."""
    v = m.get(color_by, '')
    if color_by == 'cors' and isinstance(v, str):
        v = v.replace(' creds', '')
    return str(v or '(none)')


def build_scatter(coords, ids, metas, color_by, size_by, reducer):
    import plotly.graph_objects as go
    groups = {}
    for i, m in enumerate(metas):
        groups.setdefault(_cors_group_value(m, color_by), []).append(i)

    def size_of(m):
        v = m.get(size_by, 1)
        try:
            v = float(v)
        except (TypeError, ValueError):
            v = 1.0
        return 8 + min(30, 4 * np.log1p(max(v, 1)))

    fig = go.Figure()
    for label in sorted(groups):
        idx = groups[label]
        fig.add_trace(go.Scattergl(
            x=coords[idx, 0], y=coords[idx, 1], mode='markers', name=label,
            marker=dict(size=[size_of(metas[i]) for i in idx], opacity=0.75,
                        line=dict(width=0.5, color='white')),
            text=[_hover(metas[i]) for i in idx],
            customdata=[ids[i] for i in idx],
            hovertemplate='%{text}<br><i>%{customdata}</i><extra></extra>'))
    fig.update_layout(
        title=f"J.E.B. vector space — {reducer.upper()} (color: {color_by}, size: {size_by})",
        legend_title=color_by, height=720, template='plotly_white',
        xaxis_title=f"{reducer}-1", yaxis_title=f"{reducer}-2")
    return fig


def nn_histogram(embs):
    import plotly.graph_objects as go
    if len(embs) < 2:
        fig = go.Figure()
        fig.update_layout(title="Nearest-neighbour cosine distance (needs 2+ vectors)",
                          height=340, template='plotly_white')
        return fig, np.asarray([]), 0
    nn = NearestNeighbors(n_neighbors=2, metric='cosine').fit(embs)
    dist, indices = nn.kneighbors(embs)
    d = dist[:, 1]
    near_pairs = {tuple(sorted((idx, int(indices[idx, 1]))))
                  for idx, distance in enumerate(d) if distance < NEAR_DUP_EPS}
    fig = go.Figure(go.Histogram(x=d, nbinsx=40, marker_color='#636efa'))
    fig.update_layout(
        title="Nearest-neighbour cosine distance (a spike near 0 = residual near-duplicates)",
        xaxis_title="distance to nearest neighbour", yaxis_title="docs",
        height=340, template='plotly_white')
    return fig, d, len(near_pairs)


def cluster_report(embs, ids, metas, near_dup):
    if len(embs) < 2:
        return "<h3>Tightest clusters</h3><p>At least two vectors are required.</p>"
    labels = DBSCAN(eps=0.12, min_samples=2, metric='cosine').fit_predict(embs)
    rows = []
    for lab in set(labels):
        if lab == -1:
            continue
        idx = [i for i, l in enumerate(labels) if l == lab]
        if len(idx) < 2:
            continue
        tmpl = Counter(metas[i].get('endpoint_template', '') for i in idx).most_common(1)[0][0]
        collection = Counter(metas[i].get('collection', '')
                             for i in idx).most_common(1)[0][0]
        representation = Counter(metas[i].get('representation', 'canonical')
                                 for i in idx).most_common(1)[0][0]
        rows.append((len(idx), collection, representation, tmpl, ids[idx[0]]))
    rows.sort(reverse=True)
    out = ["<h3>Tightest clusters (candidate over-collapse / filter targets)</h3>",
           f"<p>{int(near_dup)} near-duplicate pairs (distance &lt; {NEAR_DUP_EPS}).</p>",
           "<table border=1 cellpadding=4 style='border-collapse:collapse'>",
           "<tr><th>size</th><th>collection</th><th>representation</th>"
           "<th>dominant endpoint_template</th><th>example id</th></tr>"]
    for size, collection, representation, tmpl, eid in rows[:20]:
        out.append(f"<tr><td>{size}</td><td>{html_escape(collection)}</td>"
                   f"<td>{html_escape(representation)}</td><td>{html_escape(tmpl)}</td>"
                   f"<td>{html_escape(eid)}</td></tr>")
    out.append("</table>")
    if not rows:
        out.append("<p>No dense clusters (good separation).</p>")
    return "\n".join(out)


def collection_report(collection_info, metas, scope=''):
    counts = Counter(m.get('collection', '') for m in metas)
    rows = []
    for name in sorted(collection_info):
        meta = collection_info[name]
        rows.append(
            f"<tr><td>{html_escape(name)}</td><td>{counts.get(name, 0)}</td>"
            f"<td>{html_escape(meta.get('collection_schema', 'legacy/unknown'))}</td>"
            f"<td>{html_escape(meta.get('embedding_scheme', 'unknown'))}</td>"
            f"<td>{html_escape(meta.get('hnsw:space', 'default'))}</td></tr>"
        )
    return (f"<h3>{html_escape(scope)}Collection configuration</h3>"
            "<table border=1 cellpadding=4 style='border-collapse:collapse'>"
            "<tr><th>collection</th><th>vectors</th><th>schema</th>"
            "<th>embedding scheme</th><th>distance metric</th></tr>" +
            "".join(rows) + "</table>")


def segment_report(embs, metas, collection_info, scope=''):
    canonical = {}
    representations = Counter()
    parents = defaultdict(set)
    segment_indices = []
    for idx, meta in enumerate(metas):
        if meta.get('record_type') == 'canonical':
            canonical[(meta.get('collection'), meta.get('document_id'))] = idx
            continue
        parent_key = (meta.get('collection', ''), meta.get('parent_id', ''))
        representations[(meta.get('collection', ''),
                         meta.get('representation', '(none)'))] += 1
        parents[parent_key].add(meta.get('representation', '(none)'))
        segment_indices.append((idx, parent_key))

    if not segment_indices:
        return (f"<h3>{html_escape(scope)}Semantic segment diagnostics</h3>"
                "<p>No segment-granularity documents loaded.</p>", np.asarray([]))

    distances, unresolved = [], 0
    for segment_idx, parent_key in segment_indices:
        parent_idx = canonical.get(parent_key)
        if parent_idx is None:
            # e.g. --collection segments loads segment-granularity docs only.
            unresolved += 1
            continue
        segment = embs[segment_idx]
        parent = embs[parent_idx]
        denom = np.linalg.norm(segment) * np.linalg.norm(parent)
        distance = 1.0 - float(np.dot(segment, parent) / denom) if denom else 1.0
        distances.append(distance)

    coverage = Counter(len(reps) for reps in parents.values())
    rep_rows = "".join(
        f"<tr><td>{html_escape(collection)}</td><td>{html_escape(rep)}</td><td>{count}</td></tr>"
        for (collection, rep), count in sorted(representations.items())
    )
    coverage_text = ", ".join(f"{count} representation(s): {parents_count} parent(s)"
                              for count, parents_count in sorted(coverage.items()))
    distance_text = "not available (canonical parents not loaded)"
    if distances:
        distance_text = (f"median={np.median(distances):.3f}, "
                         f"p90={np.percentile(distances, 90):.3f}, "
                         f"max={np.max(distances):.3f}")
    report = (
        f"<h3>{html_escape(scope)}Semantic segment diagnostics</h3>"
        f"<p>parents represented: <b>{len(parents)}</b>; child vectors without a "
        f"loaded parent: <b>{unresolved}</b>; parent-child cosine distance: "
        f"<b>{distance_text}</b></p>"
        f"<p>coverage: {html_escape(coverage_text or 'none')}</p>"
        "<table border=1 cellpadding=4 style='border-collapse:collapse'>"
        "<tr><th>segment collection</th><th>representation</th><th>vectors</th></tr>"
        f"{rep_rows}</table>"
    )
    return report, np.asarray(distances)


def parent_distance_histogram(distances):
    import plotly.graph_objects as go
    if not len(distances):
        return None
    fig = go.Figure(go.Histogram(x=distances, nbinsx=40,
                                 marker_color='#d97706'))
    fig.update_layout(
        title="Semantic child-to-parent cosine distance",
        xaxis_title="distance from child vector to canonical parent vector",
        yaxis_title="segments", height=340, template='plotly_white')
    return fig


def stats_header(ids, embs, metas, near_dup, total_count=None):
    collections = Counter(m.get('collection', '') for m in metas)
    record_types = Counter(m.get('record_type', '') for m in metas)
    sil = None
    collection_labels = [m.get('collection', '') for m in metas]
    if len(set(collection_labels)) > 1 and len(ids) <= 5000:
        try:
            from sklearn.metrics import silhouette_score
            sil = silhouette_score(embs, collection_labels, metric='cosine')
        except Exception:
            sil = None
    count_text = f"{len(ids)} vectors"
    if total_count is not None and total_count != len(ids):
        count_text = f"displaying {len(ids)} sampled vectors from {total_count} total"
    parts = [f"<h2>J.E.B. embedding space — {count_text}</h2>",
             "<p>collections: " + ", ".join(
                 f"{html_escape(k)}={v}" for k, v in collections.items()) + "</p>",
             "<p>record types: " + ", ".join(
                 f"{html_escape(k)}={v}" for k, v in record_types.items()) + "</p>",
             f"<p>near-duplicate pairs (&lt;{NEAR_DUP_EPS}): <b>{near_dup}</b>"]
    if sil is not None:
        parts.append(f" &nbsp;|&nbsp; inter-collection silhouette: <b>{sil:.3f}</b> "
                      "(higher = collections better separated)")
    parts.append("</p>")
    return "\n".join(parts), near_dup


def run_embedding_mode(args):
    out = args.out or 'vector_space.html'
    color_by = args.color_by or DEFAULT_COLOR.get(args.collection, 'doc_kind')
    print(f"Loading vectors from {args.db_path} ...")
    ids, embs, metas, collection_info, total_count = load(args.db_path, [args.collection], args.sample)
    full_embs, full_metas = embs, metas
    full_scope = 'Sample-only (missing parents may be outside sample) ' if args.sample else 'Full-corpus '
    collections_html = collection_report(collection_info, full_metas, full_scope)
    segments_html, parent_distances = segment_report(
        full_embs, full_metas, collection_info, full_scope)
    parent_hist = parent_distance_histogram(parent_distances)

    print(f"Reducing {len(ids)} vectors with {args.reduce} ...")
    coords, reducer = reduce_dims(embs, args.reduce, args.neighbors, args.min_dist)

    scatter = build_scatter(coords, ids, metas, color_by, args.size_by, reducer)
    hist, _dists, near_dup = nn_histogram(embs)
    header_html, near_dup = stats_header(ids, embs, metas, near_dup, total_count)
    clusters_html = cluster_report(embs, ids, metas, near_dup)

    title = args.label or os.path.basename(os.path.abspath(args.db_path))
    body = [
        f"<html><head><meta charset='utf-8'><title>J.E.B. vector space — "
        f"{html_escape(title)}</title>",
        "<style>body{font-family:system-ui,Arial,sans-serif;margin:24px;color:#222}"
        "table{font-size:13px} h2,h3{margin:12px 0}</style></head><body>",
        header_html,
        collections_html,
        segments_html,
        scatter.to_html(full_html=False, include_plotlyjs='inline'),
        hist.to_html(full_html=False, include_plotlyjs=False),
    ]
    if parent_hist is not None:
        body.append(parent_hist.to_html(full_html=False, include_plotlyjs=False))
    body.extend([clusters_html, "</body></html>"])
    with open(out, 'w') as f:
        f.write("\n".join(body))
    print(f"\n✓ Wrote {out}  ({len(ids)} points, {reducer}, {near_dup} near-dup pairs)")


# ---------------------------------------------------------------------------
# Site-map graph mode
# ---------------------------------------------------------------------------

def load_structure(db_path, host=None):
    """Loads canonical `structure` docs (+ `attacks` docs, if present) for
    the graph view. entity docs carry host='' (they're cross-host by
    design, see build_structure.py's entity_chunk), so --host never filters
    them out."""
    client, have = _connect(db_path)
    if 'structure' not in have:
        sys.exit("No 'structure' collection in this DB. Did you run the import pipeline?")
    col = client.get_collection('structure')
    got = col.get(where={'granularity': 'parent'}, include=['metadatas'])
    nodes = {}
    for doc_id, m in zip(got['ids'], got['metadatas']):
        m = dict(m or {})
        if host and m.get('node_kind') != 'entity' and m.get('host') != host:
            continue
        nodes[doc_id] = m
    if not nodes:
        sys.exit("No structure nodes found (check --host, or did the import run?).")
    attacks = []
    if 'attacks' in have:
        acol = client.get_collection('attacks')
        agot = acol.get(where={'granularity': 'parent'}, include=['metadatas'])
        attacks = [dict(m or {}) for m in agot['metadatas']]
    return nodes, attacks


def _worst_verdict(counts):
    if not counts:
        return None
    for v in VERDICT_PRIORITY:
        if counts.get(v):
            return v
    return None


def build_site_graph(nodes, attacks):
    """Splits loaded structure docs into route nodes (page/endpoint/action/
    auth_model) and entity nodes, and stamps each route node with its worst
    recorded attack verdict (if any) for the ring overlay. Attack docs whose
    `host` is blank (record-attack was given a bare path, not a full URL)
    fall back to matching by endpoint_template alone."""
    route_nodes = {i: m for i, m in nodes.items() if m.get('node_kind') != 'entity'}
    entity_nodes = {i: m for i, m in nodes.items() if m.get('node_kind') == 'entity'}

    from storage import origin
    by_host_template = defaultdict(Counter)
    for a in attacks:
        verdict = a.get('verdict', 'inconclusive')
        template = a.get('endpoint_template', '')
        if a.get('scheme') and a.get('host') and a.get('port') and a.get('method'):
            by_host_template[(origin(a), a['method'], template)][verdict] += 1

    for m in route_nodes.values():
        key = (origin(m), m.get('method', ''), m.get('endpoint_template', ''))
        counts = by_host_template.get(key)
        m['_origin'] = origin(m)
        m['_attack_counts'] = dict(counts) if counts else {}
        m['_attack_verdict'] = _worst_verdict(counts)

    hosts = sorted({m['_origin'] for m in route_nodes.values() if m.get('host')})
    return hosts, route_nodes, entity_nodes


class _TrieNode:
    __slots__ = ('children', 'template', 'depth', 'x')

    def __init__(self, depth):
        self.children = {}
        self.template = None
        self.depth = depth
        self.x = 0.0


def _path_segments(template):
    return [s for s in template.strip('/').split('/') if s]


def _trie_insert(root, template):
    node = root
    for seg in _path_segments(template):
        node = node.children.setdefault(seg, _TrieNode(node.depth + 1))
    node.template = template


def _trie_assign_x(node, counter):
    if not node.children:
        node.x = counter[0]
        counter[0] += 1
        return node.x
    xs = [_trie_assign_x(c, counter) for c in node.children.values()]
    node.x = sum(xs) / len(xs)
    return node.x


def _trie_collect(node, out):
    if node.template is not None:
        out.append(node)
    for child in node.children.values():
        _trie_collect(child, out)


def layout_site_graph(hosts, route_nodes, entity_nodes, host_gap=3.0):
    """Hand-rolled hierarchical tree layout (no networkx): per host, splits
    every endpoint_template on '/' into a trie so `/api/orders/{id}` sits
    under `/api/orders` under `/api`, assigns x by the classic
    leaves-get-sequential-x / internal-nodes-average-children recursion, and
    y by path depth. Each host's auth_model doc is that host's tree root.
    Entity nodes have no path position, so they're dropped below the
    tallest tree at the mean x of the endpoints they're linked to."""
    templates_by_host = defaultdict(set)
    for m in route_nodes.values():
        if m.get('host'):
            templates_by_host[m['_origin']].add(m['endpoint_template'])

    pos = {}
    template_pos = {}          # (host, template) -> (x, y) of the shared path node
    parent_template_of = {}    # (host, template) -> parent template, nearest real ancestor
    x_offset = 0.0
    for h in hosts:
        root = _TrieNode(0)
        root.template = '{auth-model}'
        for t in sorted(templates_by_host.get(h, ())):
            if t != '{auth-model}':
                _trie_insert(root, t)
        counter = [0]
        _trie_assign_x(root, counter)
        width = max(counter[0], 1)

        def _walk(node, nearest_real):
            if node.template is not None:
                template_pos[(h, node.template)] = (x_offset + node.x, node.depth)
                if nearest_real is not None:
                    parent_template_of[(h, node.template)] = nearest_real
                nearest_real = node.template
            for child in node.children.values():
                _walk(child, nearest_real)

        _walk(root, None)
        x_offset += width + host_gap

    method_fanout = Counter()
    for doc_id, m in route_nodes.items():
        key = (m.get('_origin', ''), m.get('endpoint_template', ''))
        base = template_pos.get(key)
        if base is None:
            continue
        n = method_fanout[key]
        method_fanout[key] += 1
        pos[doc_id] = (base[0] + n * 0.35, base[1])

    entity_links = defaultdict(list)   # entity doc id -> [route doc id, ...]
    for doc_id, m in route_nodes.items():
        for eid in (m.get('entity_ids') or '').split(','):
            eid = eid.strip()
            if eid:
                entity_links[eid].append(doc_id)

    max_y = max((y for _, y in pos.values()), default=0)
    entity_y = max_y + 2
    slot_seen = Counter()
    for eid, m in entity_nodes.items():
        linked = [d for d in entity_links.get(eid, []) if d in pos]
        ex = (sum(pos[d][0] for d in linked) / len(linked)) if linked else x_offset / 2
        slot = round(ex)
        pos[eid] = (ex + slot_seen[slot] * 0.6, entity_y)
        slot_seen[slot] += 1

    return pos, template_pos, parent_template_of, entity_links


def build_hierarchy_edges(route_nodes, pos, template_pos, parent_template_of):
    edges = []
    for doc_id, m in route_nodes.items():
        if doc_id not in pos:
            continue
        key = (m.get('_origin', ''), m.get('endpoint_template', ''))
        parent_t = parent_template_of.get(key)
        if parent_t is None:
            continue
        parent_pos = template_pos.get((key[0], parent_t))
        if parent_pos is None:
            continue
        x0, y0 = pos[doc_id]
        x1, y1 = parent_pos
        edges.append((x0, y0, x1, y1))
    return edges


def build_entity_edges(route_nodes, entity_nodes, pos, entity_links):
    edges = {'produces': [], 'consumes': []}
    for eid, em in entity_nodes.items():
        if eid not in pos:
            continue
        ex, ey = pos[eid]
        produced = set((em.get('produced_by') or '').split(','))
        consumed = set((em.get('consumed_by') or '').split(','))
        for doc_id in entity_links.get(eid, []):
            m = route_nodes.get(doc_id)
            if m is None or doc_id not in pos:
                continue
            rx, ry = pos[doc_id]
            mt = f"{m.get('method', '')} {m.get('_origin', '')}{m.get('endpoint_template', '')}"
            if mt in produced:
                edges['produces'].append((rx, ry, ex, ey))
            if mt in consumed:
                edges['consumes'].append((rx, ry, ex, ey))
    return edges


def _hover_structure(m):
    kind = m.get('node_kind', '')
    if kind == 'entity':
        lines = [
            f"<b>ENTITY</b> identifier_field={m.get('identifier_field', '') or '-'}",
            f"schema_sig={str(m.get('schema_sig', ''))[:12]}",
            f"produced_by: {m.get('produced_by', '') or '-'}",
            f"consumed_by: {m.get('consumed_by', '') or '-'}",
        ]
    elif kind == 'auth_model':
        lines = [
            f"<b>AUTH MODEL</b> @ {m.get('host', '')}",
            f"mechanisms={m.get('auth_mechanisms', '') or '-'}",
            f"cookies_set={m.get('cookies_set', '') or '-'}",
            f"cookies_sent={m.get('cookies_sent', '') or '-'}",
            f"security-headers-missing={m.get('security_headers_missing', '') or '-'}",
            f"cors={m.get('cors', '') or '-'}",
        ]
    else:
        lines = [
            f"<b>{kind.upper()}</b> {m.get('method', '')} {m.get('endpoint_template', '')}",
            f"access_control={m.get('access_control', '')} "
            f"(anon_allowed={m.get('anon_allowed')}, soft_denied={m.get('anon_soft_denied')})",
            f"auth_mechanisms={m.get('auth_mechanisms', '') or '-'}",
            f"cookies_sent={m.get('cookies_sent', '') or '-'} "
            f"cookies_set={m.get('cookies_set', '') or '-'}",
            f"security-headers-missing={m.get('security_headers_missing', '') or '-'}",
            f"entity_ids={m.get('entity_ids', '') or '-'}",
            f"seen {m.get('instance_count', '?')}×",
        ]
    counts = m.get('_attack_counts')
    if counts:
        lines.append("attacks: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    lines.append(m.get('summary', ''))
    return "<br>".join(lines)


def _node_color(m):
    kind = m.get('node_kind', '')
    if kind in NODE_KIND_COLOR:
        return NODE_KIND_COLOR[kind]
    return ACCESS_CONTROL_COLOR.get(m.get('access_control'), ACCESS_CONTROL_COLOR['unknown'])


def _node_size(m):
    v = m.get('instance_count', 1)
    try:
        v = float(v)
    except (TypeError, ValueError):
        v = 1.0
    return 10 + min(30, 4 * np.log1p(max(v, 1)))


def build_graph_figure(route_nodes, entity_nodes, pos, hierarchy_edges, entity_edges,
                       show_attacks):
    import plotly.graph_objects as go
    fig = go.Figure()

    def _edge_trace(edges, name, color, dash=None, width=1):
        if not edges:
            return
        xs, ys = [], []
        for x0, y0, x1, y1 in edges:
            xs += [x0, x1, None]
            ys += [y0, y1, None]
        fig.add_trace(go.Scatter(x=xs, y=ys, mode='lines', name=name,
                                 line=dict(color=color, width=width, dash=dash),
                                 hoverinfo='skip'))

    _edge_trace(hierarchy_edges, 'path hierarchy', '#cbd5e1', width=1)
    _edge_trace(entity_edges.get('produces', []), 'entity: produced_by', '#7c3aed', width=1.5)
    _edge_trace(entity_edges.get('consumes', []), 'entity: consumed_by', '#7c3aed',
               dash='dot', width=1.5)

    all_nodes = dict(route_nodes)
    all_nodes.update(entity_nodes)
    groups = defaultdict(list)
    for doc_id, m in all_nodes.items():
        if doc_id in pos:
            groups[m.get('node_kind', 'unknown')].append(doc_id)

    for label in sorted(groups):
        ids = groups[label]
        line_colors, line_widths = [], []
        for i in ids:
            verdict = all_nodes[i].get('_attack_verdict') if show_attacks else None
            if verdict:
                line_colors.append(VERDICT_RING.get(verdict, '#000000'))
                line_widths.append(3)
            else:
                line_colors.append('white')
                line_widths.append(0.5)
        fig.add_trace(go.Scattergl(
            x=[pos[i][0] for i in ids], y=[pos[i][1] for i in ids],
            mode='markers', name=label,
            marker=dict(size=[_node_size(all_nodes[i]) for i in ids],
                        color=[_node_color(all_nodes[i]) for i in ids], opacity=0.9,
                        line=dict(width=line_widths, color=line_colors)),
            text=[_hover_structure(all_nodes[i]) for i in ids],
            customdata=ids,
            hovertemplate='%{text}<br><i>%{customdata}</i><extra></extra>'))

    subtitle = "color: access_control (auth_model=blue, entity=purple)"
    if show_attacks:
        subtitle += "; ring: worst recorded attack verdict"
    fig.update_layout(
        title=f"J.E.B. site map — {subtitle}",
        height=820, template='plotly_white', showlegend=True,
        xaxis=dict(visible=False), yaxis=dict(visible=False, autorange='reversed'))
    return fig


def graph_stats_header(route_nodes, entity_nodes, attacks, show_attacks):
    kind_counts = Counter(m.get('node_kind', '') for m in route_nodes.values())
    hosts = sorted({m['host'] for m in route_nodes.values() if m.get('host')})
    parts = [
        "<h2>J.E.B. site map</h2>",
        f"<p>hosts: {html_escape(', '.join(hosts) or '(none)')}</p>",
        "<p>" + ", ".join(f"{html_escape(k)}={v}" for k, v in sorted(kind_counts.items())) +
        f", entity={len(entity_nodes)}</p>",
    ]
    if show_attacks:
        tested = sum(1 for m in route_nodes.values() if m.get('_attack_verdict'))
        vuln = sum(1 for m in route_nodes.values() if m.get('_attack_verdict') == 'vulnerable')
        parts.append(f"<p>attacks recorded: {len(attacks)}; endpoints with a recorded "
                     f"attack: {tested}; flagged vulnerable: <b>{vuln}</b></p>")
    return "\n".join(parts)


def run_graph_mode(args):
    out = args.out or 'site_map.html'
    print(f"Loading structure from {args.db_path} ...")
    nodes, attacks = load_structure(args.db_path, host=args.host)
    show_attacks = args.show_attacks
    if show_attacks is None:
        show_attacks = bool(attacks)

    hosts, route_nodes, entity_nodes = build_site_graph(nodes, attacks)
    pos, template_pos, parent_template_of, entity_links = layout_site_graph(
        hosts, route_nodes, entity_nodes)
    hierarchy_edges = build_hierarchy_edges(route_nodes, pos, template_pos, parent_template_of)
    entity_edges = build_entity_edges(route_nodes, entity_nodes, pos, entity_links)
    fig = build_graph_figure(route_nodes, entity_nodes, pos, hierarchy_edges, entity_edges,
                             show_attacks)
    header = graph_stats_header(route_nodes, entity_nodes, attacks, show_attacks)

    title = args.label or os.path.basename(os.path.abspath(args.db_path))
    body = [
        f"<html><head><meta charset='utf-8'><title>J.E.B. site map — "
        f"{html_escape(title)}</title>",
        "<style>body{font-family:system-ui,Arial,sans-serif;margin:24px;color:#222}"
        "table{font-size:13px} h2,h3{margin:12px 0}</style></head><body>",
        header,
        fig.to_html(full_html=False, include_plotlyjs='inline'),
        "</body></html>",
    ]
    with open(out, 'w') as f:
        f.write("\n".join(body))
    print(f"\n✓ Wrote {out}  ({len(route_nodes)} route/page/action/auth_model nodes, "
          f"{len(entity_nodes)} entity nodes"
          f"{', attack overlay on' if show_attacks else ''})")


def main():
    ap = argparse.ArgumentParser(description="J.E.B. v4 visualizer")
    ap.add_argument('--db-path', default='./chroma_db')
    ap.add_argument('--mode', choices=['embedding', 'graph'], default='embedding',
                    help="embedding: vector-space scatter + diagnostics (default). "
                         "graph: structure collection as a site map.")
    ap.add_argument('--collection', default='all',
                    help="[embedding mode] structure | behavior | attacks (loads both "
                         "parent and segment docs) | canonical | segments (parent-only / "
                         "segment-only, across every collection) | all")
    ap.add_argument('--reduce', choices=['umap', 'tsne', 'pca'], default='umap',
                    help="[embedding mode]")
    ap.add_argument('--color-by', default=None, help="[embedding mode]")
    ap.add_argument('--size-by', default='instance_count', help="[embedding mode]")
    ap.add_argument('--neighbors', type=neighbors_int, default=15, help="[embedding mode]")
    ap.add_argument('--min-dist', type=unit_float, default=0.1, help="[embedding mode]")
    ap.add_argument('--sample', type=nonnegative_int, default=0,
                    help="[embedding mode] subsample to N points")
    ap.add_argument('--host', default=None,
                    help="[graph mode] restrict to one host (a multi-host capture "
                         "otherwise draws every host's tree side by side)")
    attacks_flag = ap.add_mutually_exclusive_group()
    attacks_flag.add_argument('--show-attacks', dest='show_attacks', action='store_true',
                              default=None,
                              help="[graph mode] force the attack-verdict ring on")
    attacks_flag.add_argument('--no-attacks', dest='show_attacks', action='store_false',
                              help="[graph mode] force the attack-verdict ring off")
    ap.add_argument('--out', default=None,
                    help="default: vector_space.html (embedding) / site_map.html (graph)")
    ap.add_argument('--label', default='')
    args = ap.parse_args()

    if args.mode == 'graph':
        run_graph_mode(args)
    else:
        run_embedding_mode(args)


if __name__ == '__main__':
    main()
