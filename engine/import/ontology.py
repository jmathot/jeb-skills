"""
Ontology (T-box) for the `graph` + `edges` collections.

Node classes and edge relations with their domain and range live here and nowhere
else; `build_graph` checks every edge it emits against `RELATIONS`.

Embedded classes become records in the `graph` collection (`node_type`). Literal
classes are only ever edge endpoints: their ids are `<class>:<value>` (`param:id`,
`cookie:session`) or the id of a record in another collection (`exchange`,
`finding`).
"""

# Bump when node classes, relations, ids or the rendering of node text change.
ONTOLOGY_VERSION = 'ontology-v1'

ORIGIN = 'origin'
ROUTE = 'route'
BEHAVIOR = 'behavior'
SECTION = 'section'
FORM = 'form'
DATA_OBJECT = 'data_object'
POSTURE = 'posture'

EMBEDDED_TYPES = (ORIGIN, ROUTE, BEHAVIOR, SECTION, FORM, DATA_OBJECT, POSTURE)

PARAM = 'param'
COOKIE = 'cookie'
LIB = 'lib'
EXCHANGE = 'exchange'
FINDING = 'finding'

LITERAL_TYPES = (PARAM, COOKIE, LIB, EXCHANGE, FINDING)
NODE_TYPES = EMBEDDED_TYPES + LITERAL_TYPES

# Route kinds (`route_kind`, also `node_kind` for the `kind=` filter).
ROUTE_KINDS = ('page', 'action', 'endpoint', 'asset')

# Nodes that describe structure rather than one observed response; `map` and
# `endpoint` scope to these, and `parent_index` returns them.
STRUCTURAL_TYPES = (ORIGIN, ROUTE, DATA_OBJECT)

# Synthetic nodes are results in their own right, not facets of one route, so
# retrieval never folds them into a route's diversity budget.
SYNTHETIC_TYPES = (ORIGIN, DATA_OBJECT, POSTURE)

# relation -> (domain, range)
RELATIONS = {
    'HAS_ROUTE': ({ORIGIN}, {ROUTE}),
    'CHILD_OF': ({ROUTE}, {ROUTE}),
    'HAS_BEHAVIOR': ({ROUTE}, {BEHAVIOR}),
    'RETURNS': ({BEHAVIOR, ROUTE}, {DATA_OBJECT}),
    'ACCEPTS': ({ROUTE}, {DATA_OBJECT, PARAM}),
    'CONTAINS': ({ROUTE}, {SECTION, FORM}),
    'LINKS_TO': ({ROUTE}, {ROUTE}),
    'SUBMITS_TO': ({FORM}, {ROUTE}),
    'HAS_FIELD': ({FORM}, {PARAM}),
    'CALLS': ({ROUTE}, {ROUTE}),
    'LOADS': ({ROUTE}, {ROUTE}),
    'HAS_POSTURE': ({ROUTE}, {POSTURE}),
    'SETS_COOKIE': ({ROUTE}, {COOKIE}),
    'SENDS_COOKIE': ({ROUTE}, {COOKIE}),
    'USES_LIB': ({ROUTE}, {LIB}),
    'RELATED': ({DATA_OBJECT}, {DATA_OBJECT}),
    'OBSERVED_IN': ({BEHAVIOR}, {EXCHANGE}),
    'TARGETS': ({FINDING}, {ROUTE}),
}


def validate_edge(edge):
    """Raise ValueError unless `edge` is a well-formed instance of its relation."""
    rel = edge['rel']
    if rel not in RELATIONS:
        raise ValueError(f'Unknown relation {rel}.')
    domain, range_ = RELATIONS[rel]
    if edge['src_type'] not in domain:
        raise ValueError(f"{rel}: {edge['src_type']} is outside the domain {sorted(domain)}.")
    if edge['dst_type'] not in range_:
        raise ValueError(f"{rel}: {edge['dst_type']} is outside the range {sorted(range_)}.")
    if not edge['src'] or not edge['dst']:
        raise ValueError(f'{rel}: edge has an empty endpoint.')
    return edge
