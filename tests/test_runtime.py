"""CLI configuration, safe provider resolution, and executable hints (offline)."""
import contextlib
import io
import json
import os
from pathlib import Path
import shlex
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'jeb-import/scripts'))
sys.path.insert(0, str(ROOT / 'jeb-query/scripts'))
import runtime
import hints


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        for key in ('SELECTION', 'ORIGINAL', 'CONNECTION'):
            old = getattr(runtime, key)
            self.addCleanup(setattr, runtime, key, old)
        runtime.SELECTION = None
        runtime.ORIGINAL = None
        runtime.CONNECTION = None

    def selection(self, *args):
        return runtime.select(None, runtime.import_parser().parse_args([
            'import', 'capture.xml', '--embedding-provider', 'litellm',
            '--embedding-preset', 'litellm-qwen3-embedding-8b',
            '--embedding-revision', 'revision-1', *args]))

    def test_switches_inheritance_and_validation(self):
        selected = self.selection('--embedding-model', 'qwen/qwen3-embedding-8b', '--no-embedding-send-dimensions')
        self.assertEqual(selected['dimensions'], 4096)
        self.assertFalse(selected['send_dimensions'])
        self.assertEqual(runtime.select(selected), selected)
        with self.assertRaises(ValueError):
            self.selection('--embedding-dimensions', '4097')
        with self.assertRaises(ValueError):
            self.selection('--embedding-timeout', 'nan')
        with self.assertRaises(ValueError):
            runtime.select(None, runtime.import_parser().parse_args(['rebuild', '--embedding-preset', 'litellm-gemini-embedding-2']))
        self.assertEqual(runtime.select(None)['preset'], 'ollama-embeddinggemma2')

    def test_remaining_budgets_round_trip_through_switches(self):
        selected = self.selection('--embed-batch-docs', '8', '--embed-batch-chars', '16000',
                                  '--embed-workers', '1', '--candidate-ceiling', '400',
                                  '--max-distance-graph', 'none', '--max-distance-attacks', '0.6',
                                  '--depth-deep-candidate-k', '200', '--depth-normal-raw-chars', '500',
                                  '--embedding-base-url', 'https://override.example/v1/',
                                  '--opencode-server', 'http://127.0.0.1:4096')
        self.assertEqual(selected['batch_docs'], 8)
        self.assertEqual(selected['batch_chars'], 16000)
        self.assertEqual(selected['workers'], 1)
        self.assertEqual(selected['candidate_ceiling'], 400)
        self.assertIsNone(selected['max_distance_graph'])
        self.assertEqual(selected['max_distance_attacks'], .6)
        self.assertEqual(selected['depth']['deep']['candidate_k'], 200)
        self.assertEqual(selected['depth']['normal']['raw_chars'], 500)
        self.assertEqual(selected['base_url'], 'https://override.example/v1')
        args = runtime.import_parser().parse_args(['rebuild', *runtime.selection_argv(selected)])
        self.assertEqual(runtime.select(None, args), selected)
        for flag, value in [('--embed-workers', '0'), ('--embed-batch-chars', '-1'),
                            ('--depth-quick-n-results', '0')]:
            with self.assertRaises(ValueError):
                self.selection(flag, value)
        with contextlib.redirect_stdout(io.StringIO()) as out, self.assertRaises(SystemExit):
            self.selection('--max-distance-graph', 'nan')
        self.assertIn('cosine distance', json.loads(out.getvalue())['error'])

    def test_no_production_skill_reads_environment_configuration(self):
        import ast
        for skill in ('jeb-import', 'jeb-query'):
            for path in (ROOT / skill / 'scripts').glob('*.py'):
                tree = ast.parse(path.read_text())
                readers = [node for node in ast.walk(tree)
                           if (isinstance(node, ast.Attribute) and node.attr in ('environ', 'getenv'))
                           or (isinstance(node, ast.ImportFrom) and node.module == 'os'
                               and any(name.name in ('environ', 'getenv') for name in node.names))]
                self.assertEqual(readers, [], str(path))

    def test_legacy_envvars_cannot_change_backend_or_leak_credentials(self):
        with patch.dict(os.environ, {'JEB_EMBEDDING_PRESET': 'invalid',
                                    'JEB_EMBEDDING_BASE_URL': 'https://wrong.example/v1',
                                    'JEB_EMBEDDING_API_KEY': 'stale-secret',
                                    'JEB_EMBEDDING_HEADERS': '{"Authorization":"stale-secret"}',
                                    'JEB_OLLAMA_URL': 'https://wrong.example', 'JEB_DISTANCE_METRIC': 'invalid'}):
            runtime.SELECTION = runtime.select(None)
            self.assertEqual(runtime.SELECTION['preset'], 'ollama-embeddinggemma2')
            self.assertEqual(runtime.connection(), {'base_url': 'http://localhost:11434', 'api_key': '', 'headers': {}})

    def test_custom_header_and_keyless_providers(self):
        runtime.SELECTION = self.selection()
        for headers in ({'X-API-Key': 'private-header'}, {}):
            runtime.CONNECTION = None
            with patch.object(runtime, 'api', return_value={'settings': {'baseURL': 'https://gateway.example/v1'},
                                                           'headers': headers}) as api:
                connection = runtime.connection()
            self.assertEqual(connection['headers'], headers)
            self.assertEqual(connection['api_key'], '')
            api.assert_called_once()

    def test_ollama_url_normalization_and_keep_alive_switch(self):
        for suffix in ('/api/embed', '/api/embeddings', ''):
            args = runtime.import_parser().parse_args(['import', 'capture.xml', '--embedding-base-url',
                                                       'http://localhost:11434' + suffix, '--embedding-keep-alive', '5m'])
            runtime.SELECTION = runtime.select(None, args)
            runtime.CONNECTION = None
            self.assertEqual(runtime.connection()['base_url'], 'http://localhost:11434')
            self.assertEqual(runtime.get('keep_alive'), '5m')

    def test_explicit_server_switch_reaches_real_cli_arguments(self):
        import subprocess
        runtime.SELECTION = self.selection('--opencode-server', 'http://127.0.0.1:4096')
        result = subprocess.CompletedProcess([], 0, '{"data":{}}', '')
        with patch.object(runtime.subprocess, 'run', return_value=result) as run:
            runtime.api('/api/provider/litellm')
        self.assertEqual(run.call_args.args[0], ['opencode', 'api', '--server', 'http://127.0.0.1:4096',
                                               'get', '/api/provider/litellm'])

    def test_explicit_connection_reset_switches(self):
        selected = self.selection('--embedding-base-url', 'https://gateway.example/v1',
                                  '--opencode-server', 'http://127.0.0.1:4096')
        args = runtime.import_parser().parse_args(['rebuild', '--no-embedding-provider', '--no-opencode-server'])
        updated = runtime.select(selected, args)
        self.assertIsNone(updated['provider'])
        self.assertIsNone(updated['opencode_server'])
        args = runtime.import_parser().parse_args(['rebuild', '--no-embedding-base-url'])
        self.assertIsNone(runtime.select(selected, args)['base_url'])

    def test_runtime_budget_changes_do_not_mark_index_pending(self):
        import chromadb
        with tempfile.TemporaryDirectory() as project:
            client = chromadb.PersistentClient(path=project)
            current = self.selection()
            captures = client.create_collection('captures', embedding_function=None,
                                               metadata={'embedding_config': json.dumps(current), 'index_state': 'complete'})
            runtime.ORIGINAL = current
            runtime.SELECTION = {**current, 'batch_docs': 4, 'timeout': 20}
            runtime.persist(captures)
            self.assertEqual(captures.metadata['index_state'], 'complete')

    def test_current_index_stays_complete_when_saved_selection_is_stale(self):
        import chromadb
        with tempfile.TemporaryDirectory() as project:
            client = chromadb.PersistentClient(path=project)
            stale = {'preset': 'retired-preset'}
            captures = client.create_collection('captures', embedding_function=None,
                                               metadata={'embedding_config': json.dumps(stale), 'index_state': 'complete'})
            runtime.ORIGINAL = stale
            runtime.SELECTION = self.selection()
            runtime.persist(captures, indexed=True)
            self.assertEqual(captures.metadata['index_state'], 'complete')
            self.assertNotEqual(json.loads(captures.metadata['embedding_config']), stale)

    def test_test_runner_requires_explicit_live_switch(self):
        import subprocess
        with patch.dict(os.environ, {'JEB_TEST_LIVE': '1'}):
            result = subprocess.run([sys.executable, str(ROOT / 'tests/run.py'), '--tier', 'a',
                                     '--revision', 'not-authorized'], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertIn('require --live', result.stderr)
        result = subprocess.run([sys.executable, str(ROOT / 'tests/live_cli.py'), 'not-a-script.py'],
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Explicit --live', result.stderr)

    def test_switching_presets_resets_model_specific_defaults(self):
        saved = self.selection('--embedding-context-tokens', '20000')
        args = runtime.import_parser().parse_args(['rebuild', '--embedding-preset', 'litellm-gemini-embedding-2',
                                                  '--embedding-revision', 'gemini-revision'])
        selected = runtime.select(saved, args)
        self.assertEqual(selected['dimensions'], 3072)
        self.assertEqual(selected['context_tokens'], 8192)
        self.assertEqual(selected['provider'], 'litellm')
        args = runtime.import_parser().parse_args(['rebuild', '--embedding-preset', 'ollama-embeddinggemma2'])
        self.assertIsNone(runtime.select(saved, args)['provider'])

    def test_provider_settings_remain_in_memory_and_do_not_modify_environment(self):
        runtime.SELECTION = self.selection()
        before = dict(os.environ)
        with patch.object(runtime, 'api', return_value={'settings': {'baseURL': 'https://gateway.example/v1/', 'apiKey': 'secret'},
                                                       'headers': {'X-Test': 'header'}}) as api:
            with contextlib.redirect_stdout(io.StringIO()) as output:
                connection = runtime.connection()
                self.assertEqual(runtime.connection(), connection)
        self.assertEqual(connection['base_url'], 'https://gateway.example/v1')
        self.assertEqual(connection['api_key'], 'secret')
        self.assertEqual(output.getvalue(), '')
        self.assertEqual(dict(os.environ), before)
        api.assert_called_once_with('/api/provider/litellm')
        self.assertNotIn('secret', json.dumps(runtime.SELECTION))

    def test_active_api_key_only_and_ambiguous_credentials_rejected(self):
        runtime.SELECTION = self.selection()
        provider = {'integrationID': 'litellm', 'settings': {'baseURL': 'https://gateway.example/v1'}}
        integration = {'connections': [{'type': 'credential', 'id': 'key-1', 'method': 'key'}]}
        credential = {'id': 'key-1', 'integrationID': 'litellm', 'active': True,
                      'value': {'type': 'key', 'key': 'secret'}}
        with patch.object(runtime, 'api', side_effect=[provider, integration, [credential]]):
            self.assertEqual(runtime.connection()['api_key'], 'secret')
        runtime.CONNECTION = None
        with patch.object(runtime, 'api', side_effect=[provider, integration, [credential, credential]]):
            with self.assertRaisesRegex(ValueError, 'exactly one'):
                runtime.connection()
        integration['connections'][0]['method'] = 'oauth'
        with patch.object(runtime, 'api', side_effect=[provider, integration, [credential]]):
            with self.assertRaisesRegex(ValueError, 'OAuth'):
                runtime.connection()

    def test_api_errors_do_not_disclose_captured_secrets(self):
        import subprocess
        for result in (subprocess.CompletedProcess([], 1, 'SECRET', 'SECRET'),
                       subprocess.CompletedProcess([], 0, 'SECRET', '')):
            with patch.object(runtime.subprocess, 'run', return_value=result):
                with self.assertRaises(ValueError) as exc:
                    runtime.api('/api/credential')
                self.assertNotIn('SECRET', str(exc.exception))

    def test_malformed_endpoint_rejected_before_credentials_lookup(self):
        runtime.SELECTION = self.selection()
        with patch.object(runtime, 'api', return_value={'settings': {'baseURL': 'https://user:secret@gateway.example/v1'}}) as api:
            with self.assertRaises(ValueError):
                runtime.connection()
            self.assertEqual(api.call_count, 1)

    def test_configuration_persisted_without_secrets_and_concurrency_checked(self):
        import chromadb
        runtime.SELECTION = self.selection()
        with tempfile.TemporaryDirectory() as project:
            client = chromadb.PersistentClient(path=str(Path(project) / 'chroma_db'))
            captures = client.create_collection('captures', embedding_function=None)
            runtime.persist(captures)
            saved = runtime.load_selection(Path(project) / 'chroma_db')
            self.assertEqual(runtime.validate(saved), runtime.SELECTION)
            # Vector identity is pinned; untouched runtime defaults are not frozen in.
            for key in runtime.IDENTITY:
                self.assertIn(key, saved)
            self.assertNotIn('batch_docs', saved)
            self.assertNotIn('depth', saved)
            with self.assertRaisesRegex(ValueError, 'concurrently'):
                runtime.persist(captures)

    def test_hints_quote_paths_and_leading_dash_positionals(self):
        import agent_interface
        self.addCleanup(hints.set_location)
        hints.set_location()
        self.assertEqual(shlex.split(hints.query('map'))[1:], ['map'])
        hints.set_location(db_path='/tmp/project with spaces/chroma_db')
        hint = hints.query('get', target='-id with spaces')
        argv = shlex.split(hint)
        self.assertEqual(Path(os.path.expanduser(argv[0])).resolve(), (ROOT / 'jeb-query/jeb').resolve())
        args = agent_interface.build_parser().parse_args(argv[1:])
        self.assertEqual(args.target, '-id with spaces')
        self.assertEqual(args.db_path, '/tmp/project with spaces/chroma_db')
        hints.set_server('http://127.0.0.1:4096')
        argv = shlex.split(hints.query('search', text='orders'))
        self.assertEqual(agent_interface.build_parser().parse_args(argv[1:]).opencode_server, 'http://127.0.0.1:4096')
        importer = shlex.split(hints.importer('rebuild'))
        self.assertEqual(runtime.parse_import(importer[1:]).project_dir, '/tmp/project with spaces')
        hints.set_location(db_path='/tmp/elsewhere/custom_db')
        self.assertEqual(hints.importer('rebuild'), '')
        self.assertIn('Rebuild the project', hints.rebuild_note('Stale.'))
        hints.set_location(project_dir='/tmp/p')
        self.assertIn('--project-dir /tmp/p', hints.query('map'))
        with contextlib.redirect_stdout(io.StringIO()) as out, self.assertRaises(SystemExit):
            agent_interface.build_parser().parse_args(['map', '--db-path', 'one', '--project-dir', 'two'])
        self.assertEqual(json.loads(out.getvalue())['command'], 'map')

    def test_global_flags_may_precede_the_subcommand(self):
        self.assertEqual(runtime.hoist(['--project-dir', 'p', 'map', '--limit', '3'], ('map',)),
                         ['map', '--project-dir', 'p', '--limit', '3'])
        self.assertEqual(runtime.hoist(['--no-opencode-server', '--db-path=x', 'get', 'id'], ('get',)),
                         ['get', '--no-opencode-server', '--db-path=x', 'id'])
        args = runtime.parse_import(['--project-dir', '/tmp/p', 'status'])
        self.assertEqual((args.command, args.project_dir), ('status', '/tmp/p'))
        self.assertEqual(runtime.parse_import(['capture.xml', '/tmp/p']).project_dir, '/tmp/p')
        self.assertEqual(runtime.parse_import(['rebuild']).project_dir, '.')
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
            runtime.parse_import(['rebuild', '/tmp/a', '--project-dir', '/tmp/b'])
        self.assertEqual(runtime.leading_command(['--project-dir', 'p', 'map']), 'map')


if __name__ == '__main__':
    unittest.main()
