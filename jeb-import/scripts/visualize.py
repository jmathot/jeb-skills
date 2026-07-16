"""
J.E.B. v2 — embedding-space inspector (standalone).

Renders a project's ChromaDB vectors as an interactive, self-contained HTML
scatter so you can *see* whether the v2 distillation is working — distinct
endpoints separating, SPA shells collapsed, statics/boilerplate contained — and
where to tune next. Alongside the scatter it emits optimisation diagnostics:
nearest-neighbour distance histogram, tightest-cluster / near-duplicate report,
and per-collection separation stats.

Usage:
  python visualize.py --db-path ./chroma_db --collection all \
      --color-by doc_kind --out vector_space.html

Deps (viz only): numpy, scikit-learn, plotly, optional umap-learn.
  pip install -r requirements-viz.txt
"""
import argparse
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

KNOWN_COLLECTIONS = ('structure', 'behavior', 'attacks')
DEFAULT_COLOR = {'structure': 'node_kind', 'behavior': 'auth_role',
                 'attacks': 'vuln_class', 'all': 'doc_kind'}
NEAR_DUP_EPS = 0.05


def load(db_path, collections):
    client = chromadb.PersistentClient(path=os.path.abspath(db_path))
    have = {c.name for c in client.list_collections()}
    if collections == ['all']:
        collections = [c for c in KNOWN_COLLECTIONS if c in have]
    ids, embs, metas = [], [], []
    for name in collections:
        if name not in have:
            print(f"  (skipping '{name}': not in DB)")
            continue
        col = client.get_collection(name)
        got = col.get(include=['embeddings', 'metadatas'])
        n = len(got['ids'])
        if not n:
            continue
        ids.extend(got['ids'])
        embs.extend(got['embeddings'])
        for m in got['metadatas']:
            m = dict(m or {})
            m.setdefault('doc_kind', name)
            metas.append(m)
        print(f"  {name}: {n} vectors")
    if not ids:
        sys.exit("No vectors found. Did you run the import pipeline?")
    return ids, np.asarray(embs, dtype=float), metas


def reduce_dims(embs, method, neighbors, min_dist):
    n = len(embs)
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
        per = max(5, min(30, (n - 1) // 3))
        return TSNE(n_components=2, metric='cosine', init='random',
                    perplexity=per, random_state=42).fit_transform(embs), 'tsne'
    return PCA(n_components=2).fit_transform(embs), 'pca'


def _hover(m):
    return ("<br>".join([
        f"<b>{m.get('doc_kind','')}</b> {m.get('method','')} {m.get('endpoint_template','')}",
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
    nn = NearestNeighbors(n_neighbors=2, metric='cosine').fit(embs)
    dist, _ = nn.kneighbors(embs)
    d = dist[:, 1]
    fig = go.Figure(go.Histogram(x=d, nbinsx=40, marker_color='#636efa'))
    fig.update_layout(
        title="Nearest-neighbour cosine distance (a spike near 0 = residual near-duplicates)",
        xaxis_title="distance to nearest neighbour", yaxis_title="docs",
        height=340, template='plotly_white')
    return fig, d


def cluster_report(embs, ids, metas, near_dup):
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
        kind = Counter(metas[i].get('doc_kind', '') for i in idx).most_common(1)[0][0]
        rows.append((len(idx), kind, tmpl, ids[idx[0]]))
    rows.sort(reverse=True)
    html = ["<h3>Tightest clusters (candidate over-collapse / filter targets)</h3>",
            f"<p>{int(near_dup)} near-duplicate pairs (distance &lt; {NEAR_DUP_EPS}).</p>",
            "<table border=1 cellpadding=4 style='border-collapse:collapse'>",
            "<tr><th>size</th><th>doc_kind</th><th>dominant endpoint_template</th><th>example id</th></tr>"]
    for size, kind, tmpl, eid in rows[:20]:
        html.append(f"<tr><td>{size}</td><td>{kind}</td><td>{tmpl}</td><td>{eid}</td></tr>")
    html.append("</table>")
    if not rows:
        html.append("<p>No dense clusters (good separation).</p>")
    return "\n".join(html)


def stats_header(ids, embs, metas, dists):
    from collections import Counter
    kinds = Counter(m.get('doc_kind', '') for m in metas)
    near_dup = int(np.sum(dists < NEAR_DUP_EPS))
    sil = None
    kind_labels = [m.get('doc_kind', '') for m in metas]
    if len(set(kind_labels)) > 1 and len(ids) <= 5000:
        try:
            from sklearn.metrics import silhouette_score
            sil = silhouette_score(embs, kind_labels, metric='cosine')
        except Exception:
            sil = None
    parts = [f"<h2>J.E.B. embedding space — {len(ids)} vectors</h2>",
             "<p>counts: " + ", ".join(f"{k}={v}" for k, v in kinds.items()) + "</p>",
             f"<p>near-duplicate pairs (&lt;{NEAR_DUP_EPS}): <b>{near_dup}</b>"]
    if sil is not None:
        parts.append(f" &nbsp;|&nbsp; inter-doc_kind silhouette: <b>{sil:.3f}</b> "
                     "(higher = collections better separated)")
    parts.append("</p>")
    return "\n".join(parts), near_dup


def main():
    ap = argparse.ArgumentParser(description="J.E.B. v2 embedding-space inspector")
    ap.add_argument('--db-path', default='./chroma_db')
    ap.add_argument('--collection', default='all',
                    help="structure | behavior | attacks | all (default: all)")
    ap.add_argument('--reduce', choices=['umap', 'tsne', 'pca'], default='umap')
    ap.add_argument('--color-by', default=None)
    ap.add_argument('--size-by', default='instance_count')
    ap.add_argument('--neighbors', type=int, default=15)
    ap.add_argument('--min-dist', type=float, default=0.1)
    ap.add_argument('--sample', type=int, default=0, help="subsample to N points")
    ap.add_argument('--out', default='vector_space.html')
    ap.add_argument('--label', default='')
    args = ap.parse_args()

    color_by = args.color_by or DEFAULT_COLOR.get(args.collection, 'doc_kind')
    print(f"Loading vectors from {args.db_path} ...")
    ids, embs, metas = load(args.db_path, [args.collection])

    if args.sample and len(ids) > args.sample:
        sel = np.random.RandomState(42).choice(len(ids), args.sample, replace=False)
        ids = [ids[i] for i in sel]
        metas = [metas[i] for i in sel]
        embs = embs[sel]
        print(f"  subsampled to {len(ids)} points")

    print(f"Reducing {len(ids)} vectors with {args.reduce} ...")
    coords, reducer = reduce_dims(embs, args.reduce, args.neighbors, args.min_dist)

    scatter = build_scatter(coords, ids, metas, color_by, args.size_by, reducer)
    hist, dists = nn_histogram(embs)
    header_html, near_dup = stats_header(ids, embs, metas, dists)
    clusters_html = cluster_report(embs, ids, metas, near_dup)

    title = args.label or os.path.basename(os.path.abspath(args.db_path))
    body = [
        f"<html><head><meta charset='utf-8'><title>J.E.B. vector space — {title}</title>",
        "<style>body{font-family:system-ui,Arial,sans-serif;margin:24px;color:#222}"
        "table{font-size:13px} h2,h3{margin:12px 0}</style></head><body>",
        header_html,
        scatter.to_html(full_html=False, include_plotlyjs='inline'),
        hist.to_html(full_html=False, include_plotlyjs=False),
        clusters_html,
        "</body></html>",
    ]
    with open(args.out, 'w') as f:
        f.write("\n".join(body))
    print(f"\n✓ Wrote {args.out}  ({len(ids)} points, {reducer}, {near_dup} near-dup pairs)")


if __name__ == '__main__':
    main()
