"""Compatibility launcher for the switch-based test runner; requires --live."""
from pathlib import Path
import subprocess
import sys

args = sys.argv[1:]
if '--live' not in args:
    raise SystemExit('Use --live --revision PINNED-REVISION to authorize Qwen embedding costs.')
# Old callers may separate runner flags with --. No secrets or JEB envvars needed.
args = [arg for arg in args if arg != '--']
sys.exit(subprocess.call([sys.executable, str(Path(__file__).with_name('run.py')), *args]))
