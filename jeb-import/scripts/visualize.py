"""
J.E.B. v4 — visualizer (standalone).

Two modes against a project's ChromaDB:

  --mode embedding (default)
    Renders the vector space as an interactive scatter (UMAP/t-SNE/PCA) so
    you can inspect every embedded graph node. Alongside the scatter it emits
    nearest-neighbour, tight-cluster, collection/schema and node-type
    diagnostics.

  --mode graph
    Renders the `graph` + `edges` collections as a site map: a tree of
    pages/endpoints/actions under each origin node (HAS_ROUTE / CHILD_OF),
    data objects linked to the routes that return/accept them, colored by
    access_control posture, with an optional ring showing the worst
    recorded `attacks` verdict per endpoint (via TARGETS edges).

Usage:
  python visualize.py --db-path ./chroma_db --collection all \
      --color-by collection --out vector_space.html
  python visualize.py --db-path ./chroma_db --mode graph --out site_map.html

Deps (viz only): numpy, scikit-learn, plotly, optional umap-learn.
  pip install -r requirements-viz.txt
"""
if __name__ == '__main__':
    import sys
    import runtime
    if not runtime.ACTIVE:
        sys.exit(runtime.run('visualize'))

import argparse
import runtime
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

KNOWN_COLLECTIONS = ('graph', 'attacks')
DEFAULT_COLOR = {
    'graph': 'node_type',
    'attacks': 'vuln_class',
    'all': 'node_type',
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
    """`graph` holds every embedded node, told apart by its `node_type`
    metadata; `attacks` holds findings. A plain collection name loads that
    collection, `all` loads every known one."""
    client, have = _connect(db_path)
    if collections == ['all']:
        collections = [c for c in KNOWN_COLLECTIONS if c in have]
    ids, embs, metas = [], [], []
    collection_info = {}
    population = []
    from storage import get_all
    for name in collections:
        if name not in have:
            continue
        col = client.get_collection(name)
        collection_info[name] = dict(col.metadata or {})
        population.extend((name, i) for i in get_all(col, include=[])['ids'])
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
            record_type = m.get('node_type') or 'finding'
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
    collection so graph data-object/origin nodes and attacks docs — whose
    useful fields aren't method/status_code/auth_role — show what they
    actually carry instead of blanks."""
    collection = m.get('collection', '')
    kind = m.get('node_kind', '')
    if collection == 'graph' and kind == 'entity':
        lines = [
            f"<b>DATA OBJECT</b> identifier_field={m.get('identifier_field', '') or '-'}",
            f"schema_sig={str(m.get('schema_sig', ''))[:12]}",
            f"context={m.get('context', '') or '-'}",
        ]
    elif collection == 'graph' and kind == 'auth_model':
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
            f"<b>{m.get('node_type', collection).upper()}</b> {m.get('method', '')} "
            f"{m.get('endpoint_template', '')}",
            f"anchor={m.get('anchor_id', '-')}",
            f"status={m.get('status_code', '')} "
            f"auth={m.get('auth_role', m.get('auth_mechanisms', ''))}",
            f"context={m.get('context', '') or '-'}",
        ]
    lines.append(m.get('summary', ''))
    return "<br>".join(lines)


def _cors_group_value(m, color_by):
    """Behavior nodes' cors carries a `' creds'` suffix that route nodes' doesn't
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
        representation = Counter(metas[i].get('record_type', '')
                                 for i in idx).most_common(1)[0][0]
        rows.append((len(idx), collection, representation, tmpl, ids[idx[0]]))
    rows.sort(reverse=True)
    out = ["<h3>Tightest clusters (candidate over-collapse / filter targets)</h3>",
           f"<p>{int(near_dup)} near-duplicate pairs (distance &lt; {NEAR_DUP_EPS}).</p>",
           "<table border=1 cellpadding=4 style='border-collapse:collapse'>",
           "<tr><th>size</th><th>collection</th><th>node type</th>"
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


def node_type_report(metas, scope=''):
    counts = Counter((m.get('collection', ''), m.get('record_type', '')) for m in metas)
    rows = "".join(
        f"<tr><td>{html_escape(collection)}</td><td>{html_escape(kind)}</td><td>{count}</td></tr>"
        for (collection, kind), count in sorted(counts.items()))
    return (f"<h3>{html_escape(scope)}Embedded nodes by type</h3>"
            "<table border=1 cellpadding=4 style='border-collapse:collapse'>"
            "<tr><th>collection</th><th>node type</th><th>vectors</th></tr>"
            f"{rows}</table>")


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
    full_scope = 'Sample-only ' if args.sample else 'Full-corpus '
    collections_html = collection_report(collection_info, full_metas, full_scope)
    segments_html = node_type_report(full_metas, full_scope)

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
    body.extend([clusters_html, "</body></html>"])
    with open(out, 'w') as f:
        f.write("\n".join(body))
    print(f"\n✓ Wrote {out}  ({len(ids)} points, {reducer}, {near_dup} near-dup pairs)")


# ---------------------------------------------------------------------------
# Site-map graph mode
# ---------------------------------------------------------------------------

def load_graph(db_path, host=None):
    """Loads the structural `graph` nodes (routes, origins, data objects), every
    stored edge, and the findings (id -> metadata) for the site-map view.
    Data objects carry host='' (they are cross-host by design), so --host never
    filters them out."""
    client, have = _connect(db_path)
    if not {'graph', 'edges'} <= have:
        sys.exit("No 'graph'/'edges' collections in this DB. Run process_burp.sh rebuild <project_dir>.")
    from storage import scan
    col = client.get_collection('graph', embedding_function=None)
    got = col.get(where={'node_type': {'$in': ['route', 'origin', 'data_object']}},
                  include=['metadatas'])
    nodes = {}
    for doc_id, m in zip(got['ids'], got['metadatas']):
        m = dict(m or {})
        if host and m.get('node_type') != 'data_object' and m.get('host') != host:
            continue
        nodes[doc_id] = m
    if not nodes:
        sys.exit("No graph nodes found (check --host, or did the import run?).")
    edges = [dict(r['metadatas']) for r in scan(client.get_collection('edges', embedding_function=None))]
    attacks = {}
    if 'attacks' in have:
        acol = client.get_collection('attacks', embedding_function=None)
        agot = acol.get(include=['metadatas'])
        attacks = {i: dict(m or {}) for i, m in zip(agot['ids'], agot['metadatas'])}
    return nodes, edges, attacks


def _worst_verdict(counts):
    if not counts:
        return None
    for v in VERDICT_PRIORITY:
        if counts.get(v):
            return v
    return None


def build_site_graph(nodes, edges, attacks):
    """Splits loaded nodes into route-side nodes (page/endpoint/action/origin) and
    data-object nodes, and stamps each route with its worst recorded finding
    verdict (found through `TARGETS` edges) for the ring overlay."""
    route_nodes = {i: m for i, m in nodes.items() if m.get('node_type') != 'data_object'}
    entity_nodes = {i: m for i, m in nodes.items() if m.get('node_type') == 'data_object'}

    from storage import origin
    counts = defaultdict(Counter)
    for e in edges:
        if e['rel'] == 'TARGETS' and e['src'] in attacks:
            counts[e['dst']][attacks[e['src']].get('verdict', 'inconclusive')] += 1

    for doc_id, m in route_nodes.items():
        m['_origin'] = origin(m) if m.get('host') else ''
        found = counts.get(doc_id)
        m['_attack_counts'] = dict(found) if found else {}
        m['_attack_verdict'] = _worst_verdict(found)

    hosts = sorted({m['_origin'] for m in route_nodes.values() if m.get('host')})
    return hosts, route_nodes, entity_nodes


def layout_site_graph(hosts, route_nodes, entity_nodes, edges, host_gap=3.0):
    """Hierarchical tree layout (no networkx) read straight from the stored edges:
    each origin node roots its routes (`HAS_ROUTE`), and `CHILD_OF` nests a route
    under its nearest ancestor route. x is the classic leaves-get-sequential-x /
    internal-nodes-average-children recursion; y is tree depth. Data objects have
    no path position, so they sit below the tallest tree at the mean x of the
    routes they are linked to (`RETURNS` = produces, `ACCEPTS` = consumes)."""
    children, parent_of = defaultdict(list), {}
    for e in edges:
        if e['rel'] == 'CHILD_OF' and e['src'] in route_nodes and e['dst'] in route_nodes:
            children[e['dst']].append(e['src'])
            parent_of[e['src']] = e['dst']
    roots = defaultdict(list)
    origin_node = {}
    for doc_id, m in route_nodes.items():
        if m.get('node_type') == 'origin':
            origin_node[m['_origin']] = doc_id
    for e in edges:
        if e['rel'] == 'HAS_ROUTE' and e['src'] in route_nodes and e['dst'] in route_nodes \
                and e['dst'] not in parent_of:
            roots[e['src']].append(e['dst'])

    def order(ids):
        return sorted(ids, key=lambda i: (route_nodes[i].get('endpoint_template', ''),
                                          route_nodes[i].get('method', ''), i))

    pos, x_offset = {}, 0.0
    for h in hosts:
        top = origin_node.get(h)
        if top is None:
            continue
        counter = [0]

        def assign(node_id, depth):
            kids = order(children.get(node_id, [])) if node_id in children else []
            if node_id == top:
                kids = order(roots.get(top, []))
            if not kids:
                x = counter[0]
                counter[0] += 1
            else:
                xs = [assign(k, depth + 1) for k in kids]
                x = sum(xs) / len(xs)
            pos[node_id] = (x_offset + x, depth)
            return x

        assign(top, 0)
        x_offset += max(counter[0], 1) + host_gap

    produces, consumes = defaultdict(list), defaultdict(list)
    for e in edges:
        if e['dst'] in entity_nodes and e['src'] in route_nodes and e['src_type'] == 'route':
            if e['rel'] == 'RETURNS':
                produces[e['dst']].append(e['src'])
            elif e['rel'] == 'ACCEPTS':
                consumes[e['dst']].append(e['src'])
    entity_links = {eid: {'produces': produces.get(eid, []), 'consumes': consumes.get(eid, [])}
                    for eid in entity_nodes}

    max_y = max((y for _, y in pos.values()), default=0)
    entity_y = max_y + 2
    slot_seen = Counter()
    for eid in entity_nodes:
        linked = [r for r in produces.get(eid, []) + consumes.get(eid, []) if r in pos]
        ex = (sum(pos[r][0] for r in linked) / len(linked)) if linked else x_offset / 2
        slot = round(ex)
        pos[eid] = (ex + slot_seen[slot] * 0.6, entity_y)
        slot_seen[slot] += 1

    hierarchy = []
    for e in edges:
        if e['rel'] in ('CHILD_OF', 'HAS_ROUTE') and e['src'] in pos and e['dst'] in pos:
            if e['rel'] == 'HAS_ROUTE' and e['dst'] in parent_of:
                continue
            child, par = (e['src'], e['dst']) if e['rel'] == 'CHILD_OF' else (e['dst'], e['src'])
            hierarchy.append((pos[child][0], pos[child][1], pos[par][0], pos[par][1]))
    return pos, hierarchy, entity_links


def build_entity_edges(pos, entity_links):
    edges = {'produces': [], 'consumes': []}
    for eid, links in entity_links.items():
        if eid not in pos:
            continue
        ex, ey = pos[eid]
        for kind in ('produces', 'consumes'):
            edges[kind] += [(pos[r][0], pos[r][1], ex, ey) for r in links[kind] if r in pos]
    return edges


def _hover_structure(m):
    kind = m.get('node_kind', '')
    if kind == 'entity':
        lines = [
            f"<b>DATA OBJECT</b> identifier_field={m.get('identifier_field', '') or '-'}",
            f"schema_sig={str(m.get('schema_sig', ''))[:12]}",
            f"context: {m.get('context', '') or '-'}",
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
            f"context: {m.get('context', '') or '-'}",
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
    print(f"Loading graph from {args.db_path} ...")
    nodes, edges, attacks = load_graph(args.db_path, host=args.host)
    show_attacks = args.show_attacks
    if show_attacks is None:
        show_attacks = bool(attacks)

    hosts, route_nodes, entity_nodes = build_site_graph(nodes, edges, attacks)
    pos, hierarchy_edges, entity_links = layout_site_graph(hosts, route_nodes, entity_nodes, edges)
    entity_edges = build_entity_edges(pos, entity_links)
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
    ap = argparse.ArgumentParser(description="J.E.B. v4 visualizer", allow_abbrev=False)
    runtime.add_server_args(ap)
    location = ap.add_mutually_exclusive_group()
    location.add_argument('--db-path')
    location.add_argument('--project-dir')
    ap.add_argument('--mode', choices=['embedding', 'graph'], default='embedding',
                    help="embedding: vector-space scatter + diagnostics (default). "
                         "graph: the graph collection as a site map.")
    ap.add_argument('--collection', default='all',
                    help="[embedding mode] graph | attacks | all")
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
    args.db_path = os.path.join(args.project_dir, 'chroma_db') if args.project_dir else (args.db_path or './chroma_db')

    if args.mode == 'graph':
        run_graph_mode(args)
    else:
        run_embedding_mode(args)


if __name__ == '__main__':
    main()
