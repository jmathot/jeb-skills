"""Isolated OpenCode host test. No shared-service or global config writes.

Default: offline registration and permission checks. --live explicitly enables
Qwen-only tools against a small capture; never invokes a chat model. All real
host processes and their configuration/data live under /tmp/opencode.
"""
import argparse
import base64
import json
import os
import re
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--live', action='store_true')
    parser.add_argument('--copy', action='store_true')
    parser.add_argument('--revision', help='Pinned Qwen gateway deployment revision')
    args = parser.parse_args()
    if args.live and (os.environ.get('JEB_TEST_LIVE') != '1' or not args.revision):
        parser.error('--live requires JEB_TEST_LIVE=1 and --revision')
    executable = shutil.which('opencode')
    if not executable:
        parser.error('OpenCode V2 is required')
    # Read the existing public provider only to obtain the authorized connection;
    # credentials stay in process environment, never in the temporary config.
    provider = None
    if args.live:
        result = subprocess.run([executable, 'api', 'get', '/api/provider/litellm'], capture_output=True, text=True, check=True)
        provider = json.loads(result.stdout)['data']
    with tempfile.TemporaryDirectory(prefix='jeb-host-', dir='/tmp/opencode') as directory:
        base = Path(directory)
        project = base / 'project'
        project.mkdir()
        config = base / 'config/opencode'
        env = {**os.environ, 'HOME': str(base / 'home'), 'XDG_CONFIG_HOME': str(base / 'config'),
               'XDG_DATA_HOME': str(base / 'data'), 'XDG_STATE_HOME': str(base / 'state'),
               'XDG_CACHE_HOME': str(base / 'cache'), 'OPENCODE_DB': str(base / 'opencode.db'),
               'JEB_TEST_MODE': 'live-qwen' if args.live else 'unit', 'ANONYMIZED_TELEMETRY': 'False'}
        for name in ('OPENCODE_CONFIG_CONTENT', 'OPENCODE_CONFIG', 'OPENCODE_CONFIG_DIR', 'OPENCODE_SERVER', 'OPENCODE_SERVER_URL'):
            env.pop(name, None)
        install_env = {**env, 'OPENCODE_CONFIG_DIR': str(config)}
        command = ['bash', str(ROOT / 'install.sh'), '--preset', 'litellm-qwen3-embedding-8b',
                   '--provider', 'litellm', '--model', 'qwen/qwen3-embedding-8b',
                   '--model-revision', args.revision or 'offline-no-embedding-calls']
        command += ['--copy'] if args.copy else ['--skip-deps']
        subprocess.run(command, env=install_env, cwd=project, check=True)
        document_path = config / 'opencode.jsonc'
        # Installer creates strict JSON in a new configuration; add the test-only
        # provider and probe, without modifying the installed production plugin.
        document = json.loads(document_path.read_text())
        settings = provider.get('settings', {}) if provider else {}
        env['JEB_HOST_API_KEY'] = settings.get('apiKey') or os.environ.get('LITELLM_API_KEY', '')
        headers = {}
        for index, (key, value) in enumerate((provider.get('headers', {}) if provider else {}).items()):
            env[f'JEB_HOST_HEADER_{index}'] = value
            headers[key] = f'{{env:JEB_HOST_HEADER_{index}}}'
        document['providers'] = {'litellm': {
            'package': '@opencode/ai/providers/openai-compatible', 'activation': 'enabled',
            'settings': {'baseURL': settings.get('baseURL', 'http://127.0.0.1:9/v1'), 'apiKey': '{env:JEB_HOST_API_KEY}'},
            'headers': headers, 'models': {'qwen/qwen3-embedding-8b': {}},
        }}
        probe = base / 'probe'
        probe.mkdir()
        (probe / 'package.json').write_text('{"type":"module"}')
        (probe / 'index.js').write_text((ROOT / 'tests/host-probe.mjs').read_text())
        document['plugins'].append(str(probe))
        document_path.write_text(json.dumps(document, indent=2))
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        server_url = f'http://127.0.0.1:{port}'
        with (base / 'server.log').open('w+') as log:
            server = subprocess.Popen([executable, 'serve', '--hostname', '127.0.0.1', '--port', str(port), '--log-level', 'debug'],
                                      env=env, cwd=project, stdout=log, stderr=subprocess.STDOUT)
            password = ''
            try:
                def api(method, path, body=None, check=True):
                    # The server is owned by this harness, not the shared service.
                    # Supply its generated Basic credential directly; CLI service
                    # discovery must not accidentally select the user's server.
                    headers = {'x-opencode-directory': str(project), 'Content-Type': 'application/json'}
                    if path.startswith('/api/rpc/'):
                        body = {'input': body}
                    if password:
                        auth = base64.b64encode(f'opencode:{password}'.encode()).decode()
                        headers['Authorization'] = f'Basic {auth}'
                    request = Request(server_url + path + '?' + urlencode({'location[directory]': str(project)}),
                                      headers=headers, method=method.upper(),
                                      data=json.dumps(body).encode() if body is not None else None)
                    try:
                        with urlopen(request, timeout=180) as response:
                            raw = response.read()
                            payload = json.loads(raw) if raw else True
                    except (HTTPError, URLError, TimeoutError) as exc:
                        if check:
                            raise RuntimeError(f'{method} {path} failed: {getattr(exc, "code", "connection error")}') from None
                        return None
                    if path.startswith('/api/rpc/'):
                        return payload.get('output')
                    return payload.get('data', payload) if isinstance(payload, dict) else payload

                deadline = time.monotonic() + 40
                while time.monotonic() < deadline:
                    if server.poll() is not None:
                        raise RuntimeError('Isolated server exited during startup')
                    log.seek(0)
                    match = re.search(r'^server password (\S+)', log.read(), re.M)
                    if match:
                        password = match.group(1)
                    if api('get', '/api/info', check=False):
                        break
                    time.sleep(0.2)
                else:
                    raise RuntimeError('Isolated server did not become ready')
                session = api('post', '/api/session', {'title': 'JEB host test (no generation)',
                              'location': {'directory': str(project)}, 'agent': 'jebediah',
                              'permissions': [{'action': '*', 'resource': '*', 'effect': 'allow'}]})
                session_id = session['id']
                api('post', '/api/location/reload', {})
                # Session creation admits no prompt and triggers location activation.
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    names = api('post', '/api/rpc/jeb-test/tools', {}, check=False)
                    if names is not None:
                        break
                    time.sleep(0.2)
                else:
                    states = api('get', '/api/plugin')
                    configs = api('get', '/api/config')
                    sources = [(c.get('path'), [p if isinstance(p, str) else p.get('package')
                                for p in c.get('info', {}).get('plugins', [])]) for c in configs]
                    raise RuntimeError('Host registration failed: ' + json.dumps({
                        'configs': sources, 'plugins': [p for p in states if p.get('source', {}).get('type') != 'builtin']}))
                assert sorted(names) == ['jeb_import', 'jeb_query', 'jeb_visualize'], names
                plugins = api('get', '/api/plugin')
                own = [p for p in plugins if p.get('id') == 'jebediah']
                assert len(own) == 1 and own[0]['state']['status'] == 'active', own
                agents = api('get', '/api/agent')
                assert any(a['id'] == 'jebediah' and a['mode'] in ('primary', 'all') for a in agents)
                print('Host registration: one active plugin, primary agent, all three tools')

                def invoke(name, input, check=True):
                    result = api('post', '/api/rpc/jeb-test/invoke', {'name': name, 'input': input, 'sessionID': session_id}, check=check)
                    if result is None:
                        return None
                    content = result['content']
                    try:
                        return json.loads(content)
                    except json.JSONDecodeError:
                        raise RuntimeError(f'{name} returned non-JSON output: {content[:500]}') from None

                invalid = invoke('jeb_query', {'command': 'graph'})
                assert 'requires target' in invalid.get('error', ''), invalid
                api('patch', f'/api/session/{session_id}', {'permissions': [{'action': '*', 'resource': '*', 'effect': 'allow'},
                                      {'action': 'edit', 'resource': '*', 'effect': 'deny'}]})
                assert invoke('jeb_import', {'command': 'rebuild'}, check=False) is None
                assert not (project / 'chroma_db').exists(), 'Denied operation wrote a database'
                print('Host permissions: denied edit blocks tool execution')
                if not args.live:
                    print('Offline host smoke passed; no model calls')
                    return
                api('patch', f'/api/session/{session_id}', {'permissions': [{'action': '*', 'resource': '*', 'effect': 'allow'}]})
                # Keep the live smoke small; source evidence is a generated fixture.
                source = ET.parse(ROOT / 'tests/capture.xml').getroot()
                small = ET.Element(source.tag, source.attrib)
                for item in list(source)[:4]:
                    small.append(item)
                capture = project / 'capture.xml'
                ET.ElementTree(small).write(capture, encoding='utf-8', xml_declaration=True)
                imported = invoke('jeb_import', {'command': 'import', 'xml_file': str(capture)})
                assert 'error' not in imported, imported
                status = invoke('jeb_import', {'command': 'status'})
                assert 'error' not in status, status
                mapped = invoke('jeb_query', {'command': 'map', 'project_dir': str(project)})
                assert mapped.get('results'), mapped
                target = mapped['results'][0]['id']
                graph = invoke('jeb_query', {'command': 'graph', 'target': target, 'project_dir': str(project)})
                assert 'error' not in graph, graph
                search = invoke('jeb_query', {'command': 'search', 'text': 'HTTP endpoints and response behavior', 'project_dir': str(project)})
                assert 'error' not in search and search.get('results'), search
                finding = invoke('jeb_query', {'command': 'record-attack', 'vuln_class': 'host-smoke', 'endpoint': 'https://app.example/api/orders',
                                             'verdict': 'inconclusive', 'evidence': 'disposable host smoke', 'event_id': 'host-smoke'})
                assert finding.get('recorded'), finding
                rebuilt = invoke('jeb_import', {'command': 'rebuild'})
                assert 'error' not in rebuilt, rebuilt
                attacks = invoke('jeb_query', {'command': 'attacks'})
                assert any(r['id'] == finding['recorded'] for r in attacks.get('results', [])), attacks
                for mode in ('graph', 'embedding'):
                    path = project / f'{mode}.html'
                    result = invoke('jeb_visualize', {'mode': mode, 'out': str(path), 'db_path': str(project / 'chroma_db')})
                    assert 'error' not in result and path.stat().st_size > 0, result
                print('Live Qwen host smoke: import/status/map/search/graph/finding/rebuild/visualizations passed')
            except Exception:
                for path in (base / 'data').glob('**/opencode.log'):
                    records = [line for line in path.read_text(errors='replace').splitlines()
                               if 'plugin' in line.lower() and ('jebediah' in line or 'probe' in line or 'error' in line.lower())]
                    print('Plugin diagnostic:', '\n'.join(records[-10:]), file=sys.stderr)
                log.flush()
                log.seek(0)
                text = log.read()[-5000:]
                text = re.sub(r'(server password )\S+', r'\1[redacted]', text)
                for key in ('JEB_HOST_API_KEY',):
                    if env.get(key):
                        text = text.replace(env[key], '[redacted]')
                print('Isolated server log tail:', text, file=sys.stderr)
                raise
            finally:
                server.terminate()
                try:
                    server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()


if __name__ == '__main__':
    main()
