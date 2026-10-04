"""Bit-identical gate for exported collections.

A line-wise `diff` of two NDJSON exports is invalid here: Chroma returns
metadata dict keys in a varying order, so identical content produces different
line text. Everything below compares field by field instead.

`_content_hash` / `_embedding_hash` live in the exported metadata, so this
detects any drift in distilled text or in the embedding inputs.

    gate.py digest --export new.ndjson --out baseline/structure.digest.json
    gate.py check  --export new.ndjson --digest baseline/structure.digest.json
    gate.py diff   --base base.ndjson --new new.ndjson
"""
import argparse
import hashlib
import json
import sys
from collections import Counter


def load(path):
    with open(path) as handle:
        return {row['id']: row for row in (json.loads(line) for line in handle)}


def record_digest(row):
    """Order-insensitive digest of one exported record."""
    payload = json.dumps({'document': row.get('documents'),
                          'metadata': row.get('metadatas') or {}},
                         sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(payload.encode()).hexdigest()[:32]


def make_digest(export_path, out_path):
    rows = load(export_path)
    digests = {record_id: record_digest(row) for record_id, row in rows.items()}
    with open(out_path, 'w') as handle:
        json.dump({'records': len(digests), 'digests': digests}, handle,
                  indent=0, sort_keys=True)
        handle.write('\n')
    print(f'{out_path}: {len(digests)} record digests')


def check_digest(export_path, digest_path, label):
    rows = load(export_path)
    with open(digest_path) as handle:
        want = json.load(handle)['digests']
    got = {record_id: record_digest(row) for record_id, row in rows.items()}
    missing, extra = sorted(set(want) - set(got)), sorted(set(got) - set(want))
    changed = sorted(i for i in set(want) & set(got) if want[i] != got[i])
    if not (missing or extra or changed):
        print(f'  ok {label}: {len(got)} records identical')
        return True
    print(f'  x  {label}: {len(missing)} missing, {len(extra)} new, '
          f'{len(changed)} changed')
    for record_id in changed[:3]:
        row = rows[record_id]
        print(f'      changed {record_id}')
        print(f'        _content_hash={(row.get("metadatas") or {}).get("_content_hash")}')
        print(f'        document[:100]={str(row.get("documents"))[:100]!r}')
    for record_id in (missing[:3] + extra[:3]):
        print(f'      id delta {record_id}')
    return False


def diff(base_path, new_path, label):
    """Field-by-field comparison of two live exports."""
    base, new = load(base_path), load(new_path)
    missing = (set(base) - set(new)) | (set(new) - set(base))
    fields, example = Counter(), {}
    for record_id in set(base) & set(new):
        if base[record_id].get('documents') != new[record_id].get('documents'):
            fields['documents'] += 1
            example.setdefault('documents', (record_id, base[record_id]['documents'],
                                             new[record_id]['documents']))
        left = base[record_id].get('metadatas') or {}
        right = new[record_id].get('metadatas') or {}
        for key in set(left) | set(right):
            if left.get(key) != right.get(key):
                fields[key] += 1
                example.setdefault(key, (record_id, left.get(key), right.get(key)))
    if not (missing or fields):
        print(f'  ok {label}: {len(base)} records identical')
        return True
    print(f'  x  {label}: {len(missing)} id mismatches, {len(fields)} differing fields')
    for key, count in fields.most_common(6):
        record_id, left, right = example[key]
        print(f'      {key} ({count} records) in {record_id}')
        print(f'        base: {str(left)[:120]}')
        print(f'        new : {str(right)[:120]}')
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    make = sub.add_parser('digest')
    make.add_argument('--export', required=True)
    make.add_argument('--out', required=True)
    check = sub.add_parser('check')
    check.add_argument('--export', required=True)
    check.add_argument('--digest', required=True)
    check.add_argument('--label', default='collection')
    compare = sub.add_parser('diff')
    compare.add_argument('--base', required=True)
    compare.add_argument('--new', required=True)
    compare.add_argument('--label', default='collection')
    args = parser.parse_args()
    if args.mode == 'digest':
        make_digest(args.export, args.out)
        return 0
    if args.mode == 'check':
        return 0 if check_digest(args.export, args.digest, args.label) else 1
    return 0 if diff(args.base, args.new, args.label) else 1


if __name__ == '__main__':
    sys.exit(main())
