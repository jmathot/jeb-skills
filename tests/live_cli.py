"""Test-only launcher enforcing Qwen policy in each live benchmark subprocess."""
from pathlib import Path
import runpy
import sys

if len(sys.argv) < 3 or sys.argv.pop(1) != '--live':
    raise SystemExit('Explicit --live opt-in required.')
script = Path(sys.argv.pop(1)).resolve()
imports = script.parent if script.name == 'import_project.py' else script.parents[2] / 'jeb-import/scripts'
sys.path.insert(0, str(imports))
sys.path.insert(0, str(script.parent))
import runtime
runtime.TEST_MODE = 'live-qwen'
sys.argv[0] = str(script)
runpy.run_path(str(script), run_name='__main__')
