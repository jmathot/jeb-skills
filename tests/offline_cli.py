"""Test-only Python wrapper: exercise installed CLIs with a mocked HTTP opener.

Never installed with the skills. Network transport is replaced before engine use.
"""
import hashlib
import json
from pathlib import Path
import runpy
import sys
from unittest.mock import patch

script = Path(sys.argv.pop(1)).resolve()
sys.path.insert(0, str(script.parent))
imports = script.parent if script.name != 'agent_interface.py' else script.parents[2] / 'jeb-import/scripts'
sys.path.insert(0, str(imports))
if not (imports / 'runtime.py').exists():
    # Original skills main (dbc5163) uses Ollama's client rather than urllib.
    # Replace both client-facing methods before executing that historical CLI.
    import embedding
    from chromadb.api.types import EmbeddingFunction
    class LegacyEF(EmbeddingFunction):
        def __call__(self, input):
            return [[(hashlib.sha256(text.encode()).digest()[i % 32] + 1) / 256
                     for i in range(768)] for text in input]

        def model_digest(self):
            return 'legacy-offline-digest'

        @staticmethod
        def name():
            return 'legacy-offline'

        def get_config(self):
            return {}

        @staticmethod
        def build_from_config(config):
            return LegacyEF()

    sys.argv[0] = str(script)
    with patch.object(embedding, 'make_ollama_ef', side_effect=LegacyEF):
        runpy.run_path(str(script), run_name='__main__')
    sys.exit(0)

import runtime
runtime.TEST_MODE = 'unit'

original = runpy.run_path


def mocked_run(path, **kwargs):
    import embedding

    class Response:
        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self):
            return json.dumps(self.body).encode()

    class Opener:
        def open(self, request, timeout=None):
            if request.full_url.endswith('/api/tags'):
                return Response({'models': [{'name': embedding.EMBEDDING_MODEL, 'digest': 'offline-model-digest'}]})
            body = json.loads(request.data)
            vectors = []
            for text in body['input']:
                digest = hashlib.sha256(text.encode()).digest()
                vectors.append([(digest[i % len(digest)] + 1) / 256 for i in range(embedding.EMBEDDING_DIMENSIONS)])
            if embedding.BACKEND == 'ollama':
                return Response({'embeddings': vectors})
            if runtime.SELECTION.get('provider') and request.get_header('Authorization') != 'Bearer offline-secret':
                raise ValueError('Mock gateway did not receive the expected private credential.')
            return Response({'model': embedding.EMBEDDING_MODEL,
                             'data': [{'index': i, 'embedding': v} for i, v in enumerate(vectors)]})

    # Only the transport policy check is bypassed: the opener itself cannot reach
    # any network. All formatting, request construction and validation still run.
    with patch.object(embedding, 'assert_test_policy'), patch.object(embedding, 'build_opener', return_value=Opener()):
        return original(path, **kwargs)


runtime.runpy.run_path = mocked_run
sys.argv[0] = str(script)
original(str(script), run_name='__main__')
