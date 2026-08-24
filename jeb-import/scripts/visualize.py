"""
J.E.B. v3 — embedding-space inspector (standalone).

Renders a project's ChromaDB vectors as an interactive, self-contained HTML
scatter so you can inspect canonical documents and protocol-aware semantic child
vectors. Alongside the scatter it emits nearest-neighbour, tight-cluster,
collection/schema, representation coverage, and parent-child distance diagnostics.

Usage:
  python visualize.py --db-path ./chroma_db --collection all \
      --color-by collection --out vector_space.html

Deps (viz only): numpy, scikit-learn, plotly, optional umap-learn.
  pip install -r requirements-viz.txt
"""
import argparse
import html
import os
import sys

try:
    import numpy as np
    import chromadb
    from sklearn.neighbors import NearestNeighbors
    from sklearn.cluster import DBSCAN
    from sklearn.decomposition import PCA
except ImportError as e:
    sys.exit(f"Missing a viz dependency ({e.name}). Install with:\n"
             f"  pip install -r {os.path.join(os.path.dirname(__file__), 'requirements-viz.txt')}")

KNOWN_COLLECTIONS = (
    'structure', 'structure_segments', 'behavior', 'behavior_segments', 'attacks',
)
DEFAULT_COLOR = {
    'structure': 'node_kind',
    'structure_segments': 'representation',
    'behavior': 'auth_role',
    'behavior_segments': 'representation',
    'attacks': 'vuln_class',
    'canonical': 'doc_kind',
    'segments': 'representation',
    'all': 'collection',
}
COLLECTION_GROUPS = {
    'canonical': ('structure', 'behavior', 'attacks'),
    'segments': ('structure_segments', 'behavior_segments'),
}
NEAR_DUP_EPS = 0.05


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


def load(db_path, collections):
    client = chromadb.PersistentClient(path=os.path.abspath(db_path))
    have = {c.name for c in client.list_collections()}
    if collections == ['all']:
        collections = [c for c in KNOWN_COLLECTIONS if c in have]
    elif len(collections) == 1 and collections[0] in COLLECTION_GROUPS:
        collections = [c for c in COLLECTION_GROUPS[collections[0]] if c in have]
    ids, embs, metas = [], [], []
    collection_info = {}
    for name in collections:
        if name not in have:
            print(f"  (skipping '{name}': not in DB)")
            continue
        col = client.get_collection(name)
        collection_info[name] = dict(col.metadata or {})
        got = col.get(include=['embeddings', 'metadatas'])
        n = len(got['ids'])
        if not n:
            continue
        ids.extend(f"{name}:{doc_id}" for doc_id in got['ids'])
        embs.extend(got['embeddings'])
        for doc_id, m in zip(got['ids'], got['metadatas']):
            m = dict(m or {})
            m.setdefault('doc_kind', name)
            m['collection'] = name
            m['document_id'] = doc_id
            m['record_type'] = 'segment' if name.endswith('_segments') else 'canonical'
            metas.append(m)
        print(f"  {name}: {n} vectors")
    if not ids:
        sys.exit("No vectors found. Did you run the import pipeline?")
    return ids, np.asarray(embs, dtype=float), metas, collection_info


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
    return ("<br>".join([
        f"<b>{m.get('collection','')}</b> {m.get('method','')} {m.get('endpoint_template','')}",
        f"representation={m.get('representation','canonical')} parent={m.get('parent_id','-')}",
        f"status={m.get('status_code','')} auth={m.get('auth_role', m.get('auth_mechanisms',''))}",
        m.get('summary', ''),
    ]))


def build_scatter(coords, ids, metas, color_by, size_by, reducer):
    import plotly.graph_objects as go
    groups = {}
    for i, m in enumerate(metas):
        groups.setdefault(str(m.get(color_by, '') or '(none)'), []).append(i)

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
        from collections import Counter
        tmpl = Counter(metas[i].get('endpoint_template', '') for i in idx).most_common(1)[0][0]
        collection = Counter(metas[i].get('collection', '')
                             for i in idx).most_common(1)[0][0]
        representation = Counter(metas[i].get('representation', 'canonical')
                                 for i in idx).most_common(1)[0][0]
        rows.append((len(idx), collection, representation, tmpl, ids[idx[0]]))
    rows.sort(reverse=True)
    html = ["<h3>Tightest clusters (candidate over-collapse / filter targets)</h3>",
            f"<p>{int(near_dup)} near-duplicate pairs (distance &lt; {NEAR_DUP_EPS}).</p>",
            "<table border=1 cellpadding=4 style='border-collapse:collapse'>",
            "<tr><th>size</th><th>collection</th><th>representation</th>"
            "<th>dominant endpoint_template</th><th>example id</th></tr>"]
    for size, collection, representation, tmpl, eid in rows[:20]:
        html.append(f"<tr><td>{size}</td><td>{html_escape(collection)}</td>"
                    f"<td>{html_escape(representation)}</td><td>{html_escape(tmpl)}</td>"
                    f"<td>{html_escape(eid)}</td></tr>")
    html.append("</table>")
    if not rows:
        html.append("<p>No dense clusters (good separation).</p>")
    return "\n".join(html)


def html_escape(value):
    return html.escape(str(value), quote=True)


def collection_report(collection_info, metas, scope=''):
    from collections import Counter
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
    from collections import Counter, defaultdict
    canonical = {}
    representations = Counter()
    parents = defaultdict(set)
    segment_indices = []
    for idx, meta in enumerate(metas):
        if meta.get('record_type') == 'canonical':
            canonical[(meta.get('collection'), meta.get('document_id'))] = idx
            continue
        parent_collection = meta.get('collection', '').removesuffix('_segments')
        parent_key = (parent_collection, meta.get('parent_id', ''))
        representations[(meta.get('collection', ''),
                         meta.get('representation', '(none)'))] += 1
        parents[parent_key].add(meta.get('representation', '(none)'))
        segment_indices.append((idx, parent_key))

    loaded_collections = set(collection_info)
    loaded_segments = {name for name in loaded_collections
                       if name.endswith('_segments')}
    if not loaded_segments:
        return (f"<h3>{html_escape(scope)}Semantic segment diagnostics</h3>"
                "<p>No segment collections loaded.</p>", np.asarray([]))
    if not segment_indices:
        return (f"<h3>{html_escape(scope)}Semantic segment diagnostics</h3>"
                "<p>Loaded segment collections contain no vectors.</p>",
                np.asarray([]))

    distances, orphaned, unresolved = [], 0, 0
    for segment_idx, parent_key in segment_indices:
        parent_idx = canonical.get(parent_key)
        if parent_idx is None:
            if parent_key[0] in loaded_collections:
                orphaned += 1
            else:
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
        f"<p>parents represented: <b>{len(parents)}</b>; orphaned child vectors: "
        f"<b>{orphaned}</b>; unresolved without loaded parent collection: "
        f"<b>{unresolved}</b>; parent-child cosine distance: <b>{distance_text}</b></p>"
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
    from collections import Counter
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


def main():
    ap = argparse.ArgumentParser(description="J.E.B. v3 embedding-space inspector")
    ap.add_argument('--db-path', default='./chroma_db')
    ap.add_argument('--collection', default='all',
                    help="structure | structure_segments | behavior | "
                         "behavior_segments | attacks | canonical | segments | all")
    ap.add_argument('--reduce', choices=['umap', 'tsne', 'pca'], default='umap')
    ap.add_argument('--color-by', default=None)
    ap.add_argument('--size-by', default='instance_count')
    ap.add_argument('--neighbors', type=neighbors_int, default=15)
    ap.add_argument('--min-dist', type=unit_float, default=0.1)
    ap.add_argument('--sample', type=nonnegative_int, default=0,
                    help="subsample to N points")
    ap.add_argument('--out', default='vector_space.html')
    ap.add_argument('--label', default='')
    args = ap.parse_args()

    color_by = args.color_by or DEFAULT_COLOR.get(args.collection, 'doc_kind')
    print(f"Loading vectors from {args.db_path} ...")
    ids, embs, metas, collection_info = load(args.db_path, [args.collection])
    full_embs, full_metas = embs, metas
    total_count = len(ids)
    full_scope = 'Full-corpus ' if args.sample and total_count > args.sample else ''
    collections_html = collection_report(collection_info, full_metas, full_scope)
    segments_html, parent_distances = segment_report(
        full_embs, full_metas, collection_info, full_scope)
    parent_hist = parent_distance_histogram(parent_distances)

    if args.sample and len(ids) > args.sample:
        sel = np.random.RandomState(42).choice(len(ids), args.sample, replace=False)
        ids = [ids[i] for i in sel]
        metas = [metas[i] for i in sel]
        embs = embs[sel]
        print(f"  subsampled to {len(ids)} points")

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
    with open(args.out, 'w') as f:
        f.write("\n".join(body))
    print(f"\n✓ Wrote {args.out}  ({len(ids)} points, {reducer}, {near_dup} near-dup pairs)")


if __name__ == '__main__':
    main()
