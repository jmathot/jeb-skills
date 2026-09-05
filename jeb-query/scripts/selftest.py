#!/usr/bin/env python3
"""
Contract tests for the jeb-query interface, run against a real project database.

    jeb-import/scripts/venv/bin/python jeb-query/scripts/selftest.py \
        --db-path <project>/chroma_db [--endpoint /api/orders]

Every check asserts something an agent depends on: that a named endpoint
resolves in one call, that a metadata-only filter works, that vulnerability
vocabulary is screened out of the structural collections but not out of
`attacks`, and that every command answers with a JSON object rather than a bare
list or a crash.
"""
import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, 'agent_interface.py')

PASS, FAIL = [], []


def run(*argv, db_path):
    proc = subprocess.run([sys.executable, SCRIPT, *argv, '--db-path', db_path],
                          capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def check(name, condition, detail=''):
    (PASS if condition else FAIL).append(name)
    print(f"  {'PASS' if condition else 'FAIL'}  {name}"
          + (f"\n          {detail}" if detail and not condition else ""))


def as_json(name, code, out):
    """Every command must answer with a JSON object and exit 0."""
    if code != 0:
        check(name, False, f"exit {code}")
        return None
    try:
        payload = json.loads(out)
    except ValueError as e:
        check(name, False, f"not JSON: {e}; got {out[:160]!r}")
        return None
    if not isinstance(payload, dict):
        check(name, False, f"expected an object, got {type(payload).__name__}")
        return None
    if name:
        check(name, True)
    return payload


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--db-path', required=True)
    ap.add_argument('--endpoint', default=None,
                    help="a route known to exist; discovered from `map` if omitted")
    args = ap.parse_args()
    db = os.path.abspath(args.db_path)

    print("== envelope contract ==")
    for argv in (['map'], ['search', 'login'], ['attacks'], ['identifier', '1'],
                 ['endpoint', '/']):
        code, out, _ = run(*argv, db_path=db)
        payload = as_json(f"{argv[0]} returns a JSON object, exit 0", code, out)
        if payload is not None:
            check(f"{argv[0]} carries command/count/next",
                  {'command', 'count'} <= set(payload) and 'next' in payload,
                  f"keys={sorted(payload)}")

    print("\n== the site map ==")
    code, out, _ = run('map', '--limit', '200', db_path=db)
    site = as_json("map", code, out) or {'results': []}
    routes = [r for r in site['results']
              if r.get('node_kind') in ('endpoint', 'page', 'action')]
    check("map returns routes", bool(routes))
    check("map excludes semantic segments",
          not any('parent_id' in r for r in site['results']))
    target = args.endpoint or (routes[0]['endpoint_template'] if routes else '/')
    print(f"  (using endpoint target {target!r})")

    print("\n== endpoint ==")
    code, out, _ = run('endpoint', target, db_path=db)
    rep = as_json("endpoint <known route>", code, out) or {}
    check("endpoint matches the route", bool(rep.get('matches')))
    check("endpoint reports the auth model", 'auth_model' in rep,
          "no auth_model node for this origin")
    if rep.get('raw_example'):
        raw = rep['raw_example']
        check("raw example carries the exchange",
              '--- REQUEST ---' in raw.get('text', '')
              and '--- RESPONSE ---' in raw.get('text', ''))
        check("raw example byte counts are coherent",
              0 < raw['bytes_shown'] <= raw['bytes_total'],
              f"{raw['bytes_shown']} of {raw['bytes_total']}")
    # every id the report hands out must actually resolve
    for match in rep.get('matches', []):
        for eid in match.get('example_ids', []):
            code, out, _ = run('get', eid, db_path=db)
            got = as_json(f"example id {eid[:8]} resolves", code, out) or {}
            check(f"example id {eid[:8]} resolves",
                  got.get('collection') == 'behavior')
            break
        break
    for ent in rep.get('related_by_entity', []):
        code, out, _ = run('get', ent['entity_id'], db_path=db)
        got = as_json("entity id resolves", code, out) or {}
        check("entity id resolves",
              got.get('document', {}).get('metadata', {}).get('node_kind') == 'entity')
        break

    code, out, _ = run('endpoint', target, '--depth', 'quick', db_path=db)
    quick = as_json("endpoint --depth quick", code, out) or {}
    check("--depth quick omits the raw example", 'raw_example' not in quick)

    code, out, _ = run('endpoint', '/definitely/not/here/at/all', db_path=db)
    miss = as_json("endpoint <unknown>", code, out) or {}
    check("unknown endpoint answers with guidance, not a crash",
          miss.get('count') == 0 and bool(miss.get('notes')) and bool(miss.get('next')))

    print("\n== metadata-only filtering ==")
    code, out, _ = run('search', '--in', 'structure', '--anon', db_path=db)
    anon = as_json("search --in structure --anon (no query text)", code, out) or {}
    check("a filter with no query text runs at all", 'results' in anon)
    seen = [(r.get('host'), r.get('method'), r.get('endpoint_template'))
            for r in anon.get('results', [])]
    check("filter results are canonical docs, not duplicated segments",
          len(seen) == len(set(seen)), f"{seen}")

    print("\n== vulnerability-term screening ==")
    code, out, _ = run('search', 'sql injection', db_path=db)
    pure = as_json("search 'sql injection'", code, out) or {}
    check("a pure vuln query is screened, exit 0",
          code == 0 and pure.get('rejected_terms') == ['sql injection'])
    check("screening explains itself and offers a next step",
          bool(pure.get('notes')) and any('vuln-class' in n or 'attacks' in n
                                          for n in pure.get('next', [])))

    code, out, _ = run('search', 'api orders ssrf xss sql injection', db_path=db)
    mixed = as_json("search with mixed structural + vuln terms", code, out) or {}
    check("vuln terms are stripped, structural residue survives",
          mixed.get('query') and mixed.get('query') != mixed.get('query_original')
          and len(mixed.get('rejected_terms', [])) == 3,
          f"query={mixed.get('query')!r} rejected={mixed.get('rejected_terms')}")

    code, out, _ = run('search', 'SQLi', '--in', 'attacks', db_path=db)
    att = as_json("search --in attacks", code, out) or {}
    check("attacks is exempt from screening", not att.get('rejected_terms'))

    print("\n== pivots ==")
    if routes:
        seed = routes[0]['id']
        code, out, _ = run('similar', seed, db_path=db)
        sim = as_json("similar <structure id>", code, out) or {}
        check("similar auto-detects the collection", sim.get('collection') == 'structure')
        ids = [r['id'] for r in sim.get('results', [])]
        check("similar never returns the seed", seed not in ids)
        resolved = all(
            (as_json('', *run('get', i, db_path=db)[:2]) or {}).get('count') == 1
            for i in ids[:3])
        check("similar returns addressable canonical ids", resolved)

    code, out, _ = run('get', 'deadbeefdeadbeefdeadbeefdeadbeef', db_path=db)
    missing = as_json("get <unknown id>", code, out) or {}
    check("unknown id answers with guidance, not a crash",
          code == 0 and missing.get('count') == 0 and bool(missing.get('notes')))

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed: " + ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
