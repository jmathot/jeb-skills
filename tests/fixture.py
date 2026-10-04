"""Build or reuse the benchmark project database.

The capture is large, so importing it on every run would make the suite
unusable. The database is keyed by the capture's sha256, so editing the capture
invalidates it automatically and an unchanged capture is imported exactly once.

    python3 tests/fixture.py            # build if missing, else report
    python3 tests/fixture.py --fresh    # discard and rebuild from scratch
    python3 tests/fixture.py --path     # print the project dir and exit
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time

TESTS = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(TESTS)
ENGINE = os.path.join(REPO, 'engine')
PYTHON = os.path.join(ENGINE, '.venv', 'bin', 'python')
CAPTURE = os.path.join(TESTS, 'capture.xml')
MANIFEST = os.path.join(TESTS, 'ground_truth.json')
WORK = os.path.join(TESTS, '.work')


def interpreter():
    return PYTHON if os.path.exists(PYTHON) else sys.executable


def capture_key():
    with open(CAPTURE, 'rb') as handle:
        return hashlib.sha256(handle.read()).hexdigest()[:16]


def project_dir():
    return os.path.join(WORK, capture_key())


def manifest():
    with open(MANIFEST) as handle:
        return json.load(handle)


def run_import(project, fresh=False):
    """Import the capture into `project`. Returns elapsed seconds."""
    if fresh and os.path.isdir(project):
        shutil.rmtree(project)
    os.makedirs(project, exist_ok=True)
    started = time.monotonic()
    proc = subprocess.run(
        [interpreter(), os.path.join(ENGINE, 'import', 'import_project.py'),
         'import', CAPTURE, project],
        cwd=os.path.join(ENGINE, 'import'), capture_output=True, text=True)
    elapsed = time.monotonic() - started
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout + proc.stderr)
        raise SystemExit(f'import failed (exit {proc.returncode})')
    return elapsed, proc.stdout


def query(args, project=None, check=True):
    """Run the query CLI and return its parsed JSON envelope."""
    project = project or project_dir()
    proc = subprocess.run(
        [interpreter(), os.path.join(ENGINE, 'query', 'agent_interface.py')]
        + list(args) + ['--db-path', os.path.join(project, 'chroma_db')],
        cwd=os.path.join(ENGINE, 'query'), capture_output=True, text=True)
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise SystemExit(f'non-JSON output from {args}:\n{proc.stdout}\n{proc.stderr}')
    if check and 'error' in payload:
        raise SystemExit(f'query {args} failed: {payload["error"]}')
    return payload


def importer(args, project=None):
    """Run the import CLI (status/export/rebuild) and return (rc, stdout)."""
    project = project or project_dir()
    proc = subprocess.run(
        [interpreter(), os.path.join(ENGINE, 'import', 'import_project.py')]
        + list(args[:1]) + [project] + list(args[1:]),
        cwd=os.path.join(ENGINE, 'import'), capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def ensure(fresh=False, quiet=False):
    """Return the project dir, importing the capture if needed."""
    project = project_dir()
    marker = os.path.join(project, '.imported')
    if fresh or not os.path.exists(marker):
        if not quiet:
            print(f'[fixture] importing {os.path.basename(CAPTURE)} '
                  f'({os.path.getsize(CAPTURE) / 1024:.0f} KB) -> {project}')
        elapsed, output = run_import(project, fresh=fresh)
        with open(marker, 'w') as handle:
            handle.write(json.dumps({'seconds': round(elapsed, 2),
                                     'capture_sha256': capture_key()}))
        if not quiet:
            print(output.strip())
            print(f'[fixture] import completed in {elapsed:.1f}s')
    elif not quiet:
        with open(marker) as handle:
            info = json.load(handle)
        print(f'[fixture] reusing {project} (imported in {info["seconds"]}s)')
    return project


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fresh', action='store_true')
    parser.add_argument('--path', action='store_true')
    args = parser.parse_args()
    if args.path:
        print(project_dir())
        return
    ensure(fresh=args.fresh)


if __name__ == '__main__':
    main()
