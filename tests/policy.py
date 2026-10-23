"""Explicit switch-based cost policy: live automation is Qwen-only and opt-in."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'jeb-import/scripts'))
import runtime

PRESET = 'litellm-qwen3-embedding-8b'
MODEL = 'qwen3-embedding-8b'
BASELINE_NAME = 'qwen3-embedding-8b-4096'
SELECTION = None


def authorize(provider, model, revision, server=None):
    global SELECTION
    if model.lower().split('/')[-1] != MODEL:
        raise SystemExit('Cost policy: only a Qwen3-Embedding-8B gateway alias is allowed.')
    if not provider or not revision:
        raise SystemExit('Live tests require --provider and a pinned --revision.')
    SELECTION = runtime.validate({'preset': PRESET, 'model': model, 'provider': provider,
                                  'revision': revision, 'dimensions': 4096, 'workers': 1,
                                  'opencode_server': server})
    runtime.SELECTION = SELECTION
    runtime.CONNECTION = None
    runtime.TEST_MODE = 'live-qwen'
    return SELECTION


def configure_live():
    if SELECTION is None:
        raise SystemExit('Live tests require explicit --live, --provider and --revision switches via tests/run.sh.')
    return SELECTION
