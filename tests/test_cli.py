"""End-to-end installed commands in a disposable project, with no network."""
import json
import io
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='jeb-cli-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.directory = Path(cls.temp.name)
        cls.project = cls.directory / 'engagement with spaces'
        cls.project.mkdir()
        cls.config = cls.directory / 'config'
        cls.env = {**os.environ, 'OPENCODE_CONFIG_DIR': str(cls.config),
                   'ANONYMIZED_TELEMETRY': 'False'}
        result = subprocess.run(['bash', str(ROOT / 'install-skills.sh')], env=cls.env, capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stderr)
        cls.imports = cls.config / 'skills/jeb-import/scripts'
        cls.queries = cls.config / 'skills/jeb-query/scripts'
        python = cls.imports / 'venv/bin/python'
        python.parent.mkdir(parents=True)
        python.write_text('#!/bin/sh\nexec ' + shlex.join([sys.executable, str(ROOT / 'tests/offline_cli.py')]) + ' "$@"\n')
        python.chmod(0o755)
        fake_bin = cls.directory / 'bin'
        fake_bin.mkdir()
        fake = fake_bin / 'opencode'
        fake.write_text('#!' + sys.executable + '\n' + '''import json, sys
path = sys.argv[-1]
if path == '/api/provider/litellm':
    data = {'integrationID': 'litellm', 'settings': {'baseURL': 'https://offline.invalid/v1'}}
elif path == '/api/integration/litellm':
    data = {'connections': [{'type': 'credential', 'id': 'key-1', 'method': 'key'}]}
elif path == '/api/credential':
    data = [{'id': 'key-1', 'integrationID': 'litellm', 'active': True, 'value': {'type': 'key', 'key': 'offline-secret'}}]
else:
    sys.exit(2)
print(json.dumps({'data': data}))
''')
        fake.chmod(0o755)
        cls.env['PATH'] = str(fake_bin) + os.pathsep + cls.env['PATH']
        cls.capture = cls.directory / 'capture.xml'
        cls.capture.write_text('''<?xml version="1.0"?><items><item>
<url>https://app.example/api/orders/42</url><method>GET</method><time>2026-10-22T10:00:00Z</time>
<status>200</status><mimetype>JSON</mimetype>
<request base64="false"><![CDATA[GET /api/orders/42 HTTP/1.1\r
Host: app.example\r
\r
]]></request><response base64="false"><![CDATA[HTTP/1.1 200 OK\r
Content-Type: application/json\r
\r
{"id":42,"status":"ready","email":"test@example.invalid"}]]></response>
</item></items>''')

    def run_cli(self, script, *args, check=True):
        result = subprocess.run(['bash', str(script), *map(str, args)], cwd=self.project,
                                env=self.env, capture_output=True, text=True, timeout=60)
        self.assertNotIn('offline-secret', result.stdout + result.stderr)
        if check:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def query(self, *args):
        return json.loads(self.run_cli(self.queries / 'jeb-query.sh', *args).stdout)

    def test_full_workflow_and_profile_migration(self):
        self.run_cli(self.imports / 'process_burp.sh', 'import', self.capture, self.project,
                     '--embedding-provider', 'litellm', '--embedding-preset', 'litellm-qwen3-embedding-8b',
                     '--embedding-model', 'qwen/qwen3-embedding-8b', '--embedding-revision', 'offline-rev-1',
                     '--embedding-dimensions', '32', '--embed-batch-docs', '3', '--embed-workers', '1',
                     '--candidate-ceiling', '250', '--max-distance-graph', 'none', '--depth-deep-candidate-k', '150')
        status = json.loads(self.run_cli(self.imports / 'process_burp.sh', 'status', self.project).stdout)
        self.assertEqual(status['project']['index_state'], 'complete')
        self.assertEqual(status['collections']['lookup']['exchanges'], 1)
        saved = json.loads(status['project']['embedding_config'])
        self.assertEqual(saved['provider'], 'litellm')
        self.assertEqual(saved['batch_docs'], 3)
        self.assertEqual(saved['workers'], 1)
        self.assertEqual(saved['candidate_ceiling'], 250)
        self.assertIsNone(saved['max_distance_graph'])
        self.assertEqual(saved['depth']['deep']['candidate_k'], 150)
        self.assertNotIn('https://offline.invalid', json.dumps(saved))
        mapped = self.query('map', '--project-dir', self.project)
        route = next(r for r in mapped['results'] if r.get('node_type') == 'route')
        fake = self.directory / 'bin/opencode'
        program = fake.read_text()
        try:
            fake.write_text('#!/bin/sh\nexit 99\n')
            self.assertTrue(self.query('endpoint', '/api/orders/42')['count'])
            self.assertTrue(self.query('graph', route['id'])['count'])
            self.assertTrue(self.query('identifier', '42')['count'])
            unavailable = self.run_cli(self.queries / 'jeb-query.sh', 'search', 'order status', check=False)
            self.assertNotEqual(unavailable.returncode, 0)
            self.assertIn('Could not resolve OpenCode', json.loads(unavailable.stdout)['error'])
        finally:
            fake.write_text(program)
        self.assertTrue(self.query('graph', route['id'], '--project-dir', self.project)['count'])
        self.assertTrue(self.query('endpoint', 'https://app.example/api/orders/42')['count'])
        self.assertTrue(self.query('search', 'order status', '--loose')['count'])
        self.assertTrue(self.query('identifier', '42')['count'])
        finding = self.query('record-attack', '--vuln-class', 'offline-test', '--endpoint',
                             'https://app.example/api/orders/42', '--verdict', 'inconclusive',
                             '--evidence', 'offline evidence', '--event-id', 'offline-event')
        finding_id = finding['recorded']
        endpoint = self.query('endpoint', '/api/orders/42')
        for hint in endpoint['next']:
            if '<' in hint:
                continue
            result = subprocess.run(shlex.split(hint), cwd=self.directory, env=self.env,
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.query('get', finding_id)['document']['id'], finding_id)
        for preset, dimensions, revision in [('litellm-gemini-embedding-2', '128', 'offline-rev-2'),
                                             ('litellm-qwen3-embedding-8b', '32', 'offline-rev-3')]:
            self.run_cli(self.imports / 'process_burp.sh', 'rebuild', self.project,
                         '--embedding-preset', preset, '--embedding-dimensions', dimensions,
                         '--embedding-revision', revision)
            self.assertEqual(self.query('attacks')['results'][0]['id'], finding_id)
            evidence = self.query('get', finding_id)['document']['document']
            self.assertIn('offline evidence', json.dumps(evidence))
        try:
            fake.write_text('#!/bin/sh\nexit 99\n')
            failed = self.run_cli(self.imports / 'process_burp.sh', 'rebuild', self.project,
                                  '--embedding-revision', 'recovery-revision', check=False)
            self.assertNotEqual(failed.returncode, 0)
            status = json.loads(self.run_cli(self.imports / 'process_burp.sh', 'status', self.project).stdout)
            self.assertEqual(status['project']['index_state'], 'failed')
            self.assertEqual(status['collections']['lookup']['exchanges'], 1)
        finally:
            fake.write_text(program)
        self.run_cli(self.imports / 'process_burp.sh', 'rebuild', self.project)
        self.assertEqual(self.query('attacks')['results'][0]['id'], finding_id)
        export = self.directory / 'export.ndjson'
        self.run_cli(self.imports / 'process_burp.sh', 'export', self.project,
                     '--collection', 'exchanges', '--output', export)
        self.assertEqual(len(export.read_text().splitlines()), 1)
        self.assertNotEqual(self.run_cli(self.imports / 'process_burp.sh', 'export', self.project,
                                        '--collection', 'exchanges', '--output', export, check=False).returncode, 0)
        self.run_cli(self.imports / 'process_burp.sh', 'import', self.capture, self.project)
        self.assertEqual(self.query('attacks')['results'][0]['id'], finding_id)
        for mode in ('graph', 'embedding'):
            output = self.directory / (mode + '.html')
            self.run_cli(self.imports / 'visualize.sh', '--project-dir', self.project,
                         '--mode', mode, '--out', output)
            self.assertIn('<html', output.read_text().lower())

    def test_help_does_not_create_database(self):
        missing = self.directory / 'missing project'
        result = self.run_cli(self.queries / 'jeb-query.sh', 'map', '--project-dir', missing, '--help')
        self.assertIn('--project-dir', result.stdout)
        self.assertFalse(missing.exists())

    def test_upgrade_from_original_skills_main_preserves_sources_and_findings(self):
        # Pin the actual old skills source, not a hand-built approximation of its
        # schema. Never run historical code against a real engagement database.
        archive = subprocess.run(['git', 'archive', 'dbc5163', 'jeb-import/scripts', 'jeb-query/scripts'],
                                 cwd=ROOT, capture_output=True)
        if archive.returncode:
            self.skipTest('Historical main commit dbc5163 is unavailable in this checkout')
        legacy = self.directory / 'legacy source'
        legacy.mkdir()
        with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as source:
            for member in source.getmembers():
                if member.isfile():
                    path = legacy / member.name
                    if not path.resolve().is_relative_to(legacy.resolve()):
                        raise ValueError('Unsafe archive path')
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(source.extractfile(member).read())
        project = self.directory / 'legacy engagement'
        project.mkdir()

        def old_cli(script, *args):
            result = subprocess.run([sys.executable, str(ROOT / 'tests/offline_cli.py'), str(legacy / script),
                                     *map(str, args)], env=self.env, cwd=project,
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return result.stdout

        old_cli('jeb-import/scripts/import_project.py', 'import', self.capture, project)
        finding = json.loads(old_cli('jeb-query/scripts/agent_interface.py', 'record-attack',
                                     '--vuln-class', 'legacy-test', '--endpoint', 'https://app.example/api/orders/42',
                                     '--event-id', 'legacy-event', '--evidence', 'legacy evidence preserved'))
        before_file = self.directory / 'before-upgrade.ndjson'
        old_cli('jeb-import/scripts/import_project.py', 'export', project,
                '--collection', 'exchanges', '--output', before_file)
        before = json.loads(before_file.read_text())
        self.run_cli(self.imports / 'process_burp.sh', 'rebuild', project,
                     '--embedding-provider', 'litellm', '--embedding-preset', 'litellm-qwen3-embedding-8b',
                     '--embedding-revision', 'upgraded-revision', '--embedding-dimensions', '32')
        status = json.loads(self.run_cli(self.imports / 'process_burp.sh', 'status', project).stdout)
        self.assertEqual(status['project']['index_state'], 'complete')
        self.assertEqual(status['collections']['lookup']['exchanges'], 1)
        self.assertNotIn('structure', status['collections']['embedded'])
        after_file = self.directory / 'after-upgrade.ndjson'
        self.run_cli(self.imports / 'process_burp.sh', 'export', project,
                     '--collection', 'exchanges', '--output', after_file)
        after = json.loads(after_file.read_text())
        self.assertEqual(before['id'], after['id'])
        self.assertEqual(before['documents'], after['documents'])
        self.assertEqual(before['metadatas']['capture_id'], after['metadatas']['capture_id'])
        result = self.query('get', finding['recorded'], '--project-dir', project)
        self.assertIn('legacy evidence preserved', json.dumps(result))
        self.assertEqual(result['document']['id'], finding['recorded'])
        self.assertTrue(self.query('endpoint', '/api/orders/42', '--project-dir', project)['count'])


if __name__ == '__main__':
    unittest.main()
