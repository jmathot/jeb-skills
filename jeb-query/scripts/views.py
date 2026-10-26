"""Brief result views: what an agent acts on, in a fixed order.

Internal, redundant and default-valued keys are left out, and so are false booleans
(an absent flag means false). Nothing else is dropped, so new metadata still shows.
`--full` turns the views off; `get` always prints the full record.
"""
FULL = False
ORDER = ('id', 'node_type', 'node_kind', 'method', 'host', 'endpoint_template', 'status_codes',
         'status_code', 'distance', 'summary')
# Redundant with another key, a digest, or bookkeeping no query reads.
DROP = {'doc_kind', 'route_kind', 'path_depth', 'param_count', 'authenticated', 'resp_body_sha256',
        'req_schema_sig', 'capture_id', 'feature_version', 'identifier_version', 'overlap_key'}
DEFAULTS = {'scheme': 'https', 'port': 443, 'observed': True}
# False is a finding here, not the absence of one.
KEEP_FALSE = {'anon_allowed', 'complete', 'credential_present'}


def _keep(key, value, record):
    if key in DROP or DEFAULTS.get(key, object()) == value:
        return False
    if key in ('anchor_id', 'canonical_exchange_id') and value == record.get('id'):
        return False
    if value is False:
        return key in KEEP_FALSE
    return value is not None and value != '' and value != [] and value != {}


def brief(record):
    """One result record, ordered and without noise."""
    if FULL:
        return record
    out = {key: record[key] for key in ORDER if key in record and _keep(key, record[key], record)}
    for key in sorted(record):
        if key not in out and _keep(key, record[key], record):
            out[key] = record[key]
    return out


def prune(value, keep=()):
    """A whole report with the same rules applied at every level; `keep` names
    top-level keys that always stay, even when empty."""
    if FULL:
        return value
    if isinstance(value, list):
        return [prune(v) for v in value]
    if not isinstance(value, dict):
        return value
    out = {}
    for key, item in value.items():
        item = prune(item)
        if key in keep or _keep(key, item, value):
            out[key] = item
    return out
