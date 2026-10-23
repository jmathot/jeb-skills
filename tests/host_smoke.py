"""Opt-in isolated OpenCode V2 discovery/provider smoke; no model calls or plugins."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def main():
    executable = shutil.which('opencode')
    if not executable:
        raise SystemExit('OpenCode V2 is required.')
    with tempfile.TemporaryDirectory(prefix='jeb-skills-host-', dir='/tmp/opencode') as directory:
        base = Path(directory)
        project = base / 'project'
        project.mkdir()
        config = base / 'config/opencode'
        # No real provider credentials or application config inherited.
        env = {'PATH': os.environ['PATH'], 'HOME': str(base / 'home'),
               'XDG_CONFIG_HOME': str(base / 'config'), 'XDG_DATA_HOME': str(base / 'data'),
               'XDG_STATE_HOME': str(base / 'state'), 'XDG_CACHE_HOME': str(base / 'cache'),
               'OPENCODE_CONFIG_DIR': str(config), 'OPENCODE_DB': str(base / 'opencode.db'),
               'ANONYMIZED_TELEMETRY': 'False'}
        subprocess.run(['bash', str(ROOT / 'install-skills.sh')], env=env, cwd=project,
                       capture_output=True, text=True, check=True)
        (config / 'opencode.json').write_text(json.dumps({'$schema': 'https://opencode.ai/config.json',
            'providers': {'offline': {'package': '@opencode/ai/providers/openai-compatible',
                'activation': 'enabled', 'settings': {'baseURL': 'https://offline.invalid/v1', 'apiKey': 'host-dummy-key'},
                'headers': {'X-Jeb-Test': 'dummy'}, 'models': {'offline': {}}}}}))
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        url = f'http://127.0.0.1:{port}'
        with (base / 'server.log').open('w+') as log:
            server = subprocess.Popen([executable, 'serve', '--hostname', '127.0.0.1', '--port', str(port)],
                                      env=env, cwd=project, stdout=log, stderr=subprocess.STDOUT)
            password = ''
            try:
                def api(path, method='GET', body=None):
                    headers = {'x-opencode-directory': str(project)}
                    if password:
                        headers['Authorization'] = 'Basic ' + base64.b64encode(f'opencode:{password}'.encode()).decode()
                    headers['Content-Type'] = 'application/json'
                    request = Request(url + path + '?' + urlencode({'location[directory]': str(project)}),
                                      headers=headers, method=method,
                                      data=json.dumps(body).encode() if body is not None else None)
                    with urlopen(request, timeout=10) as response:
                        raw = response.read()
                        payload = json.loads(raw) if raw else True
                    return payload.get('data', payload) if isinstance(payload, dict) else payload

                deadline = time.monotonic() + 45
                while time.monotonic() < deadline:
                    if server.poll() is not None:
                        raise RuntimeError('Private OpenCode server exited during startup.')
                    log.seek(0)
                    match = re.search(r'^server password (\S+)', log.read(), re.M)
                    if match:
                        password = match.group(1)
                    try:
                        api('/api/info')
                        break
                    except (HTTPError, URLError, TimeoutError):
                        time.sleep(.2)
                else:
                    raise RuntimeError('Private OpenCode server did not become ready.')
                api('/api/session', 'POST', {'title': 'Skills discovery (no model calls)',
                                            'location': {'directory': str(project)}})
                api('/api/location/reload', 'POST', {})
                deadline = time.monotonic() + 15
                while True:
                    skills = api('/api/skill')
                    if {'jeb-import', 'jeb-query'} <= {s['id'] for s in skills}:
                        break
                    if time.monotonic() >= deadline:
                        raise AssertionError('Skills not discovered: ' + repr([s['id'] for s in skills]))
                    time.sleep(.2)
                for skill in skills:
                    if skill['id'] in ('jeb-import', 'jeb-query'):
                        assert str(config) in skill['path'], 'Unexpected skill source.'
                agents = api('/api/agent')
                assert any(a['id'] == 'J.E.B.E.D.I.A.H.' and a['mode'] in ('primary', 'all') for a in agents), 'Agent not discovered.'
                plugins = api('/api/plugin')
                assert not any(p.get('id') == 'jebediah' for p in plugins), 'Unexpected Jebediah plugin.'
                spec = importlib.util.spec_from_file_location('host_runtime', config / 'skills/jeb-import/scripts/runtime.py')
                runtime = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(runtime)
                runtime.SELECTION = {'provider': 'offline', 'opencode_server': url}
                previous = Path.cwd()
                try:
                    os.chdir(project)
                    # Real, unmodified resolver. Only the CLI's standard private
                    # server authentication context is supplied by this harness.
                    with patch.dict(os.environ, {**env, 'OPENCODE_PASSWORD': password}, clear=True):
                        connection = runtime.connection()
                finally:
                    os.chdir(previous)
                assert connection == {'base_url': 'https://offline.invalid/v1', 'api_key': 'host-dummy-key',
                                      'headers': {'X-Jeb-Test': 'dummy'}}, 'Provider connection mismatch.'
                assert not (config / 'skills/jeb-import/scripts/venv').exists(), 'Unexpected dependency setup.'
                assert not (project / 'chroma_db').exists(), 'Unexpected database creation.'
                print('PASS: two skills, primary agent, no Jebediah plugin; private OpenCode provider lookup.')
                print('No model calls, dependency downloads, or normal OpenCode configuration changes.')
            finally:
                server.terminate()
                try:
                    server.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()


if __name__ == '__main__':
    main()
