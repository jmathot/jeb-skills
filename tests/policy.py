"""Cost policy: live automated embeddings are opt-in, Qwen3-Embedding-8B only."""
import os

PRESET = 'litellm-qwen3-embedding-8b'
MODEL = 'qwen3-embedding-8b'
BASELINE_NAME = 'qwen3-embedding-8b-4096'


def configure_live():
    if os.environ.get('JEB_TEST_LIVE') != '1':
        raise SystemExit('Live tests are opt-in: set JEB_TEST_LIVE=1 and the Qwen LiteLLM connection. '
                         'Use ./tests/run.sh --tier u for offline tests.')
    if os.environ.get('JEB_EMBEDDING_MODEL', MODEL).lower().split('/')[-1] != MODEL:
        raise SystemExit('Cost policy: only a Qwen3-Embedding-8B gateway alias is allowed.')
    os.environ.setdefault('JEB_EMBEDDING_MODEL', MODEL)
    for key, value in [('JEB_EMBEDDING_PRESET', PRESET),
                       ('JEB_EMBEDDING_DIMENSIONS', '4096')]:
        if os.environ.get(key, value) != value:
            raise SystemExit(f'Cost policy: {key} must be {value}; other models are manual-only.')
        os.environ[key] = value
    if not os.environ.get('JEB_EMBEDDING_BASE_URL') or not os.environ.get('JEB_EMBEDDING_REVISION'):
        raise SystemExit('Set JEB_EMBEDDING_BASE_URL and JEB_EMBEDDING_REVISION for the pinned Qwen gateway deployment.')
    # Remove legacy overrides that could select an incompatible prompt/endpoint.
    if os.environ.get('JEB_EMBEDDING_SCHEME', 'qwen3-embedding-8b-v1-instruct') != 'qwen3-embedding-8b-v1-instruct':
        raise SystemExit('Remove the incompatible JEB_EMBEDDING_SCHEME override before testing.')
    os.environ['JEB_EMBEDDING_SCHEME'] = 'qwen3-embedding-8b-v1-instruct'
    os.environ['JEB_TEST_MODE'] = 'live-qwen'
    os.environ['ANONYMIZED_TELEMETRY'] = 'False'
    os.environ.setdefault('JEB_EMBEDDING_API_KEY', os.environ.get('LITELLM_API_KEY', ''))
    # Keep paid test requests bounded; importing the fixture is explicitly cached.
    os.environ.setdefault('JEB_EMBEDDING_TIMEOUT', '120')
    os.environ.setdefault('JEB_EMBED_WORKERS', '1')
