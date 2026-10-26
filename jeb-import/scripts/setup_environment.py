"""Prepare the shared environment with an OS-released lock and readiness stamp."""
import fcntl
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from runtime import JsonArgumentParser


def report(**fields):
    print(json.dumps({'command': 'setup', **fields}))


def main():
    parser = JsonArgumentParser(prog='jeb setup', description=__doc__)
    parser.add_argument('--viz', action='store_true', help='Also install visualization requirements')
    args = parser.parse_args()
    if sys.version_info < (3, 10):
        parser.error('Python 3.10+ required')
    here = Path(__file__).resolve().parent
    files = [here / 'requirements.txt']
    if args.viz:
        files.append(here / 'requirements-viz.txt')
    signature = hashlib.sha256(b''.join(p.read_bytes() for p in files)).hexdigest()
    venv = here / 'venv'
    python = venv / 'bin/python'
    stamp = venv / ('.jeb-viz-requirements' if args.viz else '.jeb-requirements')
    base = hashlib.sha256(files[0].read_bytes()).hexdigest()
    with (here / '.venv.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if python.is_file() and stamp.is_file() and stamp.read_text() == signature:
            # The viz install includes the base requirements; launchers check this stamp.
            (venv / '.jeb-requirements').write_text(base)
            report(status='ready', viz=args.viz, changed=False)
            return 0
        try:
            if not python.is_file():
                subprocess.run([sys.executable, '-m', 'venv', str(venv)], check=True, timeout=120)
            subprocess.run([str(python), '-m', 'pip', 'install', '--disable-pip-version-check',
                            *[arg for p in files for arg in ('-r', str(p))]],
                           check=True, timeout=600, stdout=sys.stderr)
        except (subprocess.SubprocessError, OSError) as exc:
            report(error=f'Environment setup failed ({exc}); see the pip output above and retry.')
            return 1
        stamp.write_text(signature)
        (venv / '.jeb-requirements').write_text(base)
    report(status='ready', viz=args.viz, changed=True,
           next='Model preparation is a separate manual step; see the embedding reference.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
