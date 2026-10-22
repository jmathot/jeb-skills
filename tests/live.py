"""Run opt-in Qwen tests using a public OpenCode provider connection.

Never reads private credential files or writes credentials to disk. This helper
supports API keys in public provider settings; other connections can use the
documented explicit environment variables instead.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--provider', default='litellm')
parser.add_argument('--model', default='qwen/qwen3-embedding-8b')
parser.add_argument('--revision', required=True, help='Pinned Qwen deployment revision; never a secret')
parser.add_argument('args', nargs=argparse.REMAINDER, help='Arguments after -- are passed to tests/run.sh')
args = parser.parse_args()
if args.model.lower().split('/')[-1] != 'qwen3-embedding-8b':
    parser.error('Only Qwen3-Embedding-8B may be tested automatically')
if os.environ.get('JEB_TEST_LIVE') != '1':
    parser.error('Set JEB_TEST_LIVE=1 to opt in to live Qwen embedding costs')
proc = subprocess.run(['opencode', 'api', 'get', f'/api/provider/{args.provider}'], capture_output=True, text=True)
if proc.returncode:
    parser.error('Could not resolve OpenCode provider; check the connection using OpenCode')
provider = json.loads(proc.stdout)['data']
settings = provider.get('settings') or {}
if not settings.get('baseURL'):
    parser.error('Provider settings.baseURL is missing')
key = settings.get('apiKey') or os.environ.get('LITELLM_API_KEY', '')
env = {**os.environ, 'JEB_EMBEDDING_PRESET': 'litellm-qwen3-embedding-8b',
       'JEB_EMBEDDING_MODEL': args.model, 'JEB_EMBEDDING_DIMENSIONS': '4096',
       'JEB_EMBEDDING_REVISION': args.revision, 'JEB_EMBEDDING_BASE_URL': settings['baseURL'],
       'JEB_EMBEDDING_API_KEY': key, 'JEB_EMBEDDING_HEADERS': json.dumps(provider.get('headers') or {})}
argv = args.args[1:] if args.args[:1] == ['--'] else args.args
sys.exit(subprocess.call(['bash', str(Path(__file__).with_name('run.sh')), *argv], env=env))
