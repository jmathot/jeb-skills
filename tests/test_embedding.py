"""Contract tests: all transports are mocked; no model/server is contacted."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'jeb-import/scripts'))
import runtime


def load(preset='litellm-qwen3-embedding-8b', **options):
    selection = {'preset': preset, **options}
    if runtime.PROFILES[preset]['backend'] == 'litellm':
        selection.update(provider='mock', revision='mock-revision')
    with patch.object(runtime, 'SELECTION', runtime.validate(selection)):
        spec = importlib.util.spec_from_file_location('test_embedding_profile', ROOT / 'jeb-import/scripts/embedding.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


class EmbeddingTests(unittest.TestCase):
    def setUp(self):
        mode = patch.object(runtime, 'TEST_MODE', 'unit')
        mode.start()
        self.addCleanup(mode.stop)

    def test_shared_profiles_and_prompts(self):
        for preset in ('ollama-embeddinggemma2', 'litellm-gemini-embedding-2'):
            e = load(preset)
            self.assertEqual(e.doc_prefix('body', 'A | title'), 'title: A title | text: body')
            self.assertEqual(e.query_prefix_search('q'), 'task: search result | query: q')
            self.assertEqual(e.EMBEDDING_CONTEXT_TOKENS, 8192)
        e = load()
        self.assertEqual(e.doc_prefix('body'), 'body')
        self.assertEqual(e.doc_prefix('body', 'Title'), 'Title\nbody')
        self.assertEqual(e.query_prefix_search('q'), f'Instruct: {e.QUERY_INSTRUCTION}\nQuery:q')

    def test_litellm_batch_order_and_normalization(self):
        for preset in ('litellm-qwen3-embedding-8b', 'litellm-gemini-embedding-2'):
            e = load(preset)
            vector = [2.] * e.EMBEDDING_DIMENSIONS
            response = {'data': [{'index': 1, 'embedding': vector}, {'index': 0, 'embedding': [-v for v in vector]}]}
            with patch.object(e, '_request', return_value=response) as request:
                out = e.embed_documents(e.make_embedding_ef(), ['one', 'two'])
            self.assertLess(out[0][0], 0)
            self.assertGreater(out[1][0], 0)
            self.assertAlmostEqual(float(np.linalg.norm(out[0])), 1., places=5)
            path, body = request.call_args.args
            self.assertEqual(path, '/embeddings')
            self.assertEqual(body['dimensions'], e.EMBEDDING_DIMENSIONS)
            self.assertEqual(body['encoding_format'], 'float')
            self.assertNotIn('task_type', body)

    def test_ollama_contract(self):
        e = load('ollama-embeddinggemma2')
        ef = e.make_embedding_ef()
        with patch.object(e, '_request', side_effect=[{'models': [{'name': e.EMBEDDING_MODEL, 'digest': 'abc'}]},
                                                      {'embeddings': [[1.] * 768]}]) as request:
            e.embed_documents(ef, ['body'])
        self.assertEqual(ef.model_digest(), 'abc')
        path, body = request.call_args.args
        self.assertEqual(path, '/api/embed')
        self.assertFalse(body['truncate'])
        self.assertEqual(body['dimensions'], 768)

    def test_invalid_vectors_and_indices(self):
        e = load()
        for data in ([], [{'index': 0, 'embedding': [1.]}],
                     [{'index': 0, 'embedding': [float('nan')] * 4096}],
                     [{'index': 0, 'embedding': [0.] * 4096}],
                     [{'index': True, 'embedding': [1.] * 4096}],
                     [{'index': 1, 'embedding': [1.] * 4096}]):
            with self.subTest(data_length=len(data)), patch.object(e, '_request', return_value={'data': data}):
                with self.assertRaises(ValueError):
                    e.embed_query(e.make_embedding_ef(), 'graph', 'q')

    def test_no_silent_truncation_or_double_prefixing(self):
        e = load()
        with patch.object(e, '_request') as request:
            with self.assertRaises(ValueError):
                e.embed_query(e.make_embedding_ef(), 'graph', 'é' * 20000)
            request.assert_not_called()
        with self.assertRaises(ValueError):
            e.embed_documents(e.make_embedding_ef(), ['a'], ['t', 'extra'])

    def test_profile_changes_affect_cache_identity_not_credentials(self):
        e = load()
        ef = e.make_embedding_ef()
        profile = e.embedding_profile(ef)
        self.assertNotEqual(e.profile_fingerprint(profile), e.profile_fingerprint({**profile, 'embedding_dimensions': 768}))
        with patch.object(runtime, 'CONNECTION', {'api_key': 'do-not-store'}):
            self.assertEqual(profile, e.embedding_profile(ef))
            self.assertNotIn('do-not-store', json.dumps(ef.get_config()))
        ef.expected_digest = 'old'
        with patch.object(e, '_request') as request:
            with self.assertRaisesRegex(ValueError, 'revision'):
                e.embed_query(ef, 'graph', 'q')
            request.assert_not_called()

    def test_test_policy_blocks_before_network(self):
        for preset in ('ollama-embeddinggemma2', 'litellm-gemini-embedding-2', 'litellm-qwen3-embedding-8b'):
            e = load(preset)
            with patch.object(e, 'build_opener') as opener:
                with self.assertRaisesRegex(ValueError, 'Automated'):
                    e._request('/embeddings', {})
                opener.assert_not_called()
        with patch.object(runtime, 'TEST_MODE', 'live-qwen'):
            e = load('litellm-gemini-embedding-2')
            with self.assertRaises(ValueError):
                e.assert_test_policy()

    def test_native_qwen_dimensions_without_parameter(self):
        e = load(send_dimensions=False)
        with patch.object(e, '_request', return_value={'data': [{'index': 0, 'embedding': [1.] * 4096}]}) as request:
            e.embed_query(e.make_embedding_ef(), 'graph', 'q')
        self.assertNotIn('dimensions', request.call_args.args[1])

    def test_chroma_explicit_vectors_and_profile_rebuild(self):
        # Local Chroma round trip using mocked Qwen vectors, not a live model.
        import chromadb
        e = load()
        with tempfile.TemporaryDirectory() as directory:
            client = chromadb.PersistentClient(path=directory)
            ef = e.make_embedding_ef()
            col = client.create_collection('graph', embedding_function=ef, metadata=e.embedding_profile(ef))
            with patch.object(e, '_request', return_value={'data': [{'index': 0, 'embedding': [1.] * 4096}]}):
                col.upsert(ids=['one'], documents=['doc'], embeddings=e.embed_documents(ef, ['doc']))
                self.assertEqual(col.query(query_embeddings=[e.embed_query(ef, 'graph', 'q')], n_results=1)['ids'], [['one']])
            self.assertEqual(client.get_collection('graph', embedding_function=ef).count(), 1)


class PolicyTests(unittest.TestCase):
    def test_live_is_opt_in_and_non_qwen_is_rejected(self):
        import policy
        with patch.object(policy, 'SELECTION', None), self.assertRaises(SystemExit):
            policy.configure_live()
        with self.assertRaises(SystemExit):
            policy.authorize(provider='mock', model='gemini-embedding-2', revision='mock')


if __name__ == '__main__':
    unittest.main()
