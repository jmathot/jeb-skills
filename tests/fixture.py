"""Build or reuse the benchmark project database.

The capture is large, so importing it on every run would make the suite
unusable. The database is keyed by the capture's sha256, so editing the capture
invalidates it automatically and an unchanged capture is imported exactly once.

    Called by tests/run.sh --live --revision REVISION --tier a|b|c.
    Configuration is authorized in process, never inherited from JEB envvars.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from policy import configure_live
import runtime

TESTS = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(TESTS)
IMPORT = os.path.join(REPO, 'jeb-import', 'scripts')
QUERY = os.path.join(REPO, 'jeb-query', 'scripts')
PYTHON = os.path.join(IMPORT, 'venv', 'bin', 'python')
CAPTURE = os.path.join(TESTS, 'capture.xml')
MANIFEST = os.path.join(TESTS, 'ground_truth.json')
WORK = os.path.join(TESTS, '.work')
CLI_PREFIX = [str(Path(__file__).with_name('live_cli.py')), '--live']
CONFIG_CWD = os.getcwd()


def interpreter():
    return PYTHON if os.path.exists(PYTHON) else sys.executable


def capture_key():
    """Cache key: the capture plus everything that shapes the imported database.

    Feature extraction is persisted per observation and reused by rebuilds, so an
    engine change keyed only on the capture would silently test a stale import.
    """
    h = hashlib.sha256()
    selected = configure_live()
    for key in ('preset', 'model', 'dimensions', 'revision', 'context_tokens'):
        h.update(f'{key}={selected[key]}'.encode())
    with open(os.path.join(IMPORT, 'embedding-profiles.json'), 'rb') as handle:
        h.update(handle.read())
    with open(CAPTURE, 'rb') as handle:
        h.update(handle.read())
    import_dir = IMPORT
    for name in sorted(os.listdir(import_dir)):
        if name.endswith('.py'):
            h.update(name.encode())
            with open(os.path.join(import_dir, name), 'rb') as handle:
                h.update(handle.read())
    return h.hexdigest()[:16]


def project_dir():
    return os.path.join(WORK, capture_key())


def manifest():
    with open(MANIFEST) as handle:
        return json.load(handle)


def run_import(project, fresh=False):
    """Import the capture into `project`. Returns elapsed seconds."""
    selected = configure_live()
    if fresh and os.path.isdir(project):
        shutil.rmtree(project)
    os.makedirs(project, exist_ok=True)
    started = time.monotonic()
    proc = subprocess.run(
        [interpreter(), *CLI_PREFIX, os.path.join(IMPORT, 'import_project.py'),
         'import', CAPTURE, project, *runtime.selection_argv(selected)],
        cwd=CONFIG_CWD, capture_output=True, text=True)
    elapsed = time.monotonic() - started
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout + proc.stderr)
        raise SystemExit(f'import failed (exit {proc.returncode})')
    return elapsed, proc.stdout


def query(args, project=None, check=True, full=True):
    """Run the query CLI and return its parsed JSON envelope. Ground truth is
    checked against complete records, so `full` bypasses the brief view."""
    configure_live()
    project = project or project_dir()
    proc = subprocess.run(
        [interpreter(), *CLI_PREFIX, os.path.join(QUERY, 'agent_interface.py')]
        + list(args) + ['--db-path', os.path.join(project, 'chroma_db')] + (['--full'] if full else []),
        cwd=CONFIG_CWD, capture_output=True, text=True)
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise SystemExit(f'non-JSON output from {args}:\n{proc.stdout}\n{proc.stderr}')
    if check and 'error' in payload:
        raise SystemExit(f'query {args} failed: {payload["error"]}')
    return payload


def importer(args, project=None):
    """Run the import CLI (status/export/rebuild) and return (rc, stdout)."""
    configure_live()
    project = project or project_dir()
    proc = subprocess.run(
        [interpreter(), *CLI_PREFIX, os.path.join(IMPORT, 'import_project.py')]
        + list(args[:1]) + [project] + list(args[1:]),
        cwd=CONFIG_CWD, capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def ensure(fresh=False, quiet=False):
    """Return the project dir, importing the capture if needed."""
    configure_live()
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
        configure_live()
        print(project_dir())
        return
    ensure(fresh=args.fresh)


if __name__ == '__main__':
    main()
