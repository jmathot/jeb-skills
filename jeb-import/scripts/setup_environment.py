"""Prepare the shared environment with an OS-released lock and readiness stamp."""
import argparse
import fcntl
import hashlib
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
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
    with (here / '.venv.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if python.is_file() and stamp.is_file() and stamp.read_text() == signature:
            print('Shared environment is ready.')
            return
        if not python.is_file():
            subprocess.run([sys.executable, '-m', 'venv', str(venv)], check=True, timeout=120)
        subprocess.run([str(python), '-m', 'pip', 'install', '--disable-pip-version-check',
                        *[arg for p in files for arg in ('-r', str(p))]], check=True, timeout=600)
        stamp.write_text(signature)
    print('Shared environment is ready. Model preparation is a separate manual step.')


if __name__ == '__main__':
    main()
