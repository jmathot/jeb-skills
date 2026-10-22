"""Explicit model profiles and two transports. No implicit embedding or fallback.

The same presets are consumed by the TypeScript plugin. All inputs are text;
multimodal embeddings are deliberately outside the capture pipeline's contract.
"""
import hashlib
import json
import math
import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler

import numpy as np
from chromadb.api.types import EmbeddingFunction

PROFILES = json.loads((Path(__file__).resolve().parents[2] / 'src' / 'embedding-profiles.json').read_text())
PRESET = os.environ.get('JEB_EMBEDDING_PRESET') or 'ollama-embeddinggemma2'
if PRESET not in PROFILES:
    raise ValueError(f'Unknown embedding preset: {PRESET}')
PROFILE = PROFILES[PRESET]
BACKEND = PROFILE['backend']
EMBEDDING_MODEL = os.environ.get('JEB_EMBEDDING_MODEL') or PROFILE['model']
EMBEDDING_SCHEME = PROFILE['scheme']
if os.environ.get('JEB_EMBEDDING_SCHEME') not in (None, '', EMBEDDING_SCHEME):
    raise ValueError('embeddingScheme is now selected by embedding.preset; remove the old override and rebuild.')
COLLECTION_SCHEMA = 'jeb-v7-graph'
DISTANCE_METRIC = os.environ.get('JEB_DISTANCE_METRIC') or 'cosine'
if DISTANCE_METRIC != 'cosine':
    raise ValueError('Only cosine distance is supported.')
EMBEDDING_DIMENSIONS = int(os.environ.get('JEB_EMBEDDING_DIMENSIONS') or PROFILE['dimensions'])
if not PROFILE['minDimensions'] <= EMBEDDING_DIMENSIONS <= PROFILE['dimensions'] or (
        PROFILE['allowedDimensions'] and EMBEDDING_DIMENSIONS not in PROFILE['allowedDimensions']):
    raise ValueError(f'Unsupported dimensions for {PRESET}: {EMBEDDING_DIMENSIONS}')
EMBEDDING_CONTEXT_TOKENS = int(os.environ.get('JEB_EMBEDDING_CONTEXT_TOKENS') or PROFILE['contextTokens'])
if not 1 <= EMBEDDING_CONTEXT_TOKENS <= PROFILE['contextTokens']:
    raise ValueError('Embedding contextTokens must be positive and no greater than the model limit.')
QUERY_INSTRUCTION = ('Given a query about captured HTTP traffic, retrieve relevant passages '
                     'describing observed routes, behavior, and evidence.')
BASE_URL = (os.environ.get('JEB_EMBEDDING_BASE_URL') or os.environ.get('JEB_OLLAMA_URL') or
            ('http://localhost:11434' if BACKEND == 'ollama' else '')).rstrip('/')
# Accept the old Ollama endpoint spelling as a connection setting only.
for suffix in ('/api/embeddings', '/api/embed'):
    if BACKEND == 'ollama' and BASE_URL.endswith(suffix):
        BASE_URL = BASE_URL[:-len(suffix)]
TIMEOUT = float(os.environ.get('JEB_EMBEDDING_TIMEOUT') or os.environ.get('JEB_OLLAMA_TIMEOUT') or 120)
if not math.isfinite(TIMEOUT) or TIMEOUT <= 0:
    raise ValueError('Embedding timeout must be a positive finite number.')
KEEP_ALIVE = os.environ.get('JEB_OLLAMA_KEEP_ALIVE') or '30m'
if os.environ.get('JEB_EMBEDDING_SEND_DIMENSIONS', 'true') not in ('true', 'false'):
    raise ValueError('JEB_EMBEDDING_SEND_DIMENSIONS must be true or false.')
SEND_DIMENSIONS = os.environ.get('JEB_EMBEDDING_SEND_DIMENSIONS', 'true') == 'true'
MODEL_REVISION = os.environ.get('JEB_EMBEDDING_REVISION') or ''
EMBEDDING_PROFILE_METADATA = {
    'embedding_preset': PRESET,
    'embedding_scheme': EMBEDDING_SCHEME,
    'collection_schema': COLLECTION_SCHEMA,
    'embedding_model': EMBEDDING_MODEL,
    'embedding_dimensions': EMBEDDING_DIMENSIONS,
    'embedding_context_tokens': EMBEDDING_CONTEXT_TOKENS,
    'embedding_truncate': False,
    'embedding_normalization': 'l2-v1',
    'hnsw:space': DISTANCE_METRIC,
}


def assert_test_policy():
    """Fail closed before any network access in automated tests."""
    mode = os.environ.get('JEB_TEST_MODE')
    if mode and (mode != 'live-qwen' or PRESET != 'litellm-qwen3-embedding-8b'
                 or EMBEDDING_MODEL.lower().split('/')[-1] != 'qwen3-embedding-8b'):
        raise ValueError('Automated network tests require LiteLLM qwen3-embedding-8b; other models are manual-only.')


class EmbeddingHTTPError(RuntimeError):
    def __init__(self, status_code):
        self.status_code = status_code
        # Never include upstream response bodies: they may echo inputs or secrets.
        super().__init__(f'Embedding endpoint returned HTTP {status_code}. Check model access, dimensions, and input limits.')


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Do not forward gateway credentials to a redirect destination.


def _request(path, body=None):
    assert_test_policy()
    parsed = urlsplit(BASE_URL)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password \
            or parsed.query or parsed.fragment:
        raise ValueError('Set a valid embedding baseURL without credentials, query, or fragment.')
    headers = json.loads(os.environ.get('JEB_EMBEDDING_HEADERS') or '{}')
    if not isinstance(headers, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in headers.items()):
        raise ValueError('Embedding headers must be a string-valued object.')
    key = os.environ.get('JEB_EMBEDDING_API_KEY') or ''
    if key:
        headers['Authorization'] = f'Bearer {key}'
    headers['Content-Type'] = 'application/json'
    request = Request(BASE_URL + path, headers=headers,
                      data=json.dumps(body).encode() if body is not None else None)
    try:
        with build_opener(NoRedirect).open(request, timeout=TIMEOUT) as response:
            result = json.load(response)
            if not isinstance(result, dict):
                raise ValueError('Expected an object response.')
            return result
    except HTTPError as exc:
        raise EmbeddingHTTPError(exc.code) from None
    except (URLError, TimeoutError, OSError):
        raise RuntimeError('Embedding endpoint unavailable or timed out; check the configured connection.') from None
    except (ValueError, UnicodeError):
        raise ValueError('Embedding endpoint returned invalid JSON.') from None


class ProfileEmbeddingFunction(EmbeddingFunction):
    """Chroma adapter; callers supply prepared text and explicit vectors."""
    def __init__(self):
        self._resolved_digest = None
        self.expected_digest = None

    @staticmethod
    def name():
        return 'jeb-explicit-profile'

    def default_space(self):
        return 'cosine'

    def supported_spaces(self):
        return ['cosine']

    def get_config(self):
        # Never persist credentials, headers, or endpoints into Chroma.
        return {'preset': PRESET, 'dimensions': EMBEDDING_DIMENSIONS}

    @staticmethod
    def build_from_config(config):
        if config != {'preset': PRESET, 'dimensions': EMBEDDING_DIMENSIONS}:
            raise ValueError('Embedding configuration differs; rebuild the project.')
        return ProfileEmbeddingFunction()

    def model_digest(self):
        if self._resolved_digest is None:
            if BACKEND == 'ollama':
                models = _request('/api/tags').get('models', [])
                wanted = EMBEDDING_MODEL if ':' in EMBEDDING_MODEL else EMBEDDING_MODEL + ':latest'
                self._resolved_digest = next((m.get('digest') for m in models
                                              if (m.get('model') or m.get('name')) == wanted), None)
                if not self._resolved_digest:
                    raise ValueError('Configured Ollama embedding model is not installed; pull it manually.')
            else:
                if not MODEL_REVISION:
                    raise ValueError('LiteLLM requires embedding.modelRevision (JEB_EMBEDDING_REVISION); '
                                     'pin the gateway deployment and disable cross-model fallback.')
                self._resolved_digest = MODEL_REVISION
        return self._resolved_digest

    def __call__(self, input):
        actual = self.model_digest()
        if self.expected_digest is not None and self.expected_digest != actual:
            raise ValueError('Embedding model revision differs from the collection; rebuild the project.')
        if not input:
            return []
        # A UTF-8 byte budget is deliberately conservative: char/4 is not a safe
        # token bound for captures. Count prefixes too. No provider may silently
        # truncate our inputs; reject before dispatch if we cannot prove they fit.
        if any(not isinstance(text, str) or not text.strip() or
               len(text.encode('utf-8')) + 16 > EMBEDDING_CONTEXT_TOKENS for text in input):
            raise ValueError('Embedding input exceeds the conservative token budget or is empty; '
                             'shorten the text (no silent truncation).')
        if BACKEND == 'ollama':
            result = _request('/api/embed', {'model': EMBEDDING_MODEL, 'input': list(input),
                               'dimensions': EMBEDDING_DIMENSIONS, 'truncate': False, 'keep_alive': KEEP_ALIVE})
            vectors = result.get('embeddings', [])
        else:
            body = {'model': EMBEDDING_MODEL, 'input': list(input), 'encoding_format': 'float'}
            if SEND_DIMENSIONS:
                body['dimensions'] = EMBEDDING_DIMENSIONS
            result = _request('/embeddings', body)
            data = result.get('data', [])
            if not isinstance(data, list) or len(data) != len(input) or any(
                    not isinstance(row, dict) or type(row.get('index')) is not int for row in data) or \
                    sorted(row['index'] for row in data) != list(range(len(input))):
                raise ValueError('Embedding response must contain exactly one indexed vector per input; no aggregation.')
            if os.environ.get('JEB_TEST_MODE') == 'live-qwen' and \
                    str(result.get('model', '')).lower().split('/')[-1] != 'qwen3-embedding-8b':
                raise ValueError('Test gateway response does not identify qwen3-embedding-8b.')
            vectors = [row.get('embedding') for row in sorted(data, key=lambda row: row['index'])]
        if len(vectors) != len(input):
            raise ValueError('Embedding count differs from input count; no aggregation is allowed.')
        out = []
        for vector in vectors:
            array = np.asarray(vector, dtype=np.float32)
            if array.shape != (EMBEDDING_DIMENSIONS,) or not np.isfinite(array).all():
                raise ValueError(f'Embedding must contain {EMBEDDING_DIMENSIONS} finite dimensions.')
            norm = float(np.linalg.norm(array.astype(np.float64)))
            if not math.isfinite(norm) or norm == 0:
                raise ValueError('Embedding has zero or invalid norm.')
            out.append(array / norm)
        return out


def embedding_profile(ef):
    return {**EMBEDDING_PROFILE_METADATA, 'embedding_model_digest': ef.model_digest()}


def profile_fingerprint(metadata):
    fields = {k: v for k, v in (metadata or {}).items()
              if k.startswith('embedding_') or k in ('collection_schema', 'hnsw:space')}
    return hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest()


def make_embedding_ef():
    return ProfileEmbeddingFunction()


def doc_prefix(text: str, title: str = '') -> str:
    title = ' '.join((title or '').replace('|', ' ').split())[:200]
    if PRESET == 'litellm-qwen3-embedding-8b':
        return f'{title}\n{text}' if title else text
    return f'title: {title or "none"} | text: {text}'


def query_prefix_search(text: str) -> str:
    if PRESET == 'litellm-qwen3-embedding-8b':
        return f'Instruct: {QUERY_INSTRUCTION}\nQuery:{text}'
    return f'task: search result | query: {text}'


def embed_documents(ef, texts, titles=None):
    titles = titles or [''] * len(texts)
    if len(titles) != len(texts):
        raise ValueError('document title count must match document text count')
    return ef([doc_prefix(text, title) for text, title in zip(texts, titles)])


def embed_query(ef, collection_name: str, text: str):
    return ef([query_prefix_search(text)])[0]
