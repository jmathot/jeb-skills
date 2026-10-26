"""Switch/project configuration and private OpenCode connection resolution.

No JEB environment configuration is read or written. Only validated non-secret
selections are persisted in Chroma. Credentials stay in process memory.
"""
import argparse
import json
import math
from pathlib import Path
import runpy
import subprocess
import sys
import threading
from urllib.parse import quote, urlsplit

from storage import LOOKUP_COLLECTIONS

HERE = Path(__file__).resolve().parent
EXPORT_COLLECTIONS = ('graph', 'attacks') + LOOKUP_COLLECTIONS
IMPORT_COMMANDS = ('import', 'rebuild', 'status', 'abandon', 'export')
IMPORT_HELP = {'import': 'add a Burp XML capture to the project',
               'rebuild': 're-derive indexes from retained observations (no XML needed)',
               'status': 'capture parse state, project index state and loss ledger',
               'abandon': 'exclude a failed or interrupted capture, then rebuild',
               'export': 'write one collection as NDJSON'}
LAUNCHER_COMMANDS = {'setup': 'prepare the Python environment (--viz adds plotting)',
                     'viz': 'write an HTML site map or vector-space plot'}
# Commands that never embed: a stale saved selection must not block them.
READ_ONLY_COMMANDS = ('status', 'export', 'abandon')
# Accepted before or after the subcommand; (flag, takes a value).
GLOBAL_FLAGS = {'--project-dir': True, '--db-path': True, '--opencode-server': True,
                '--no-opencode-server': False}
PROFILES = json.loads((HERE / 'embedding-profiles.json').read_text())
ACTIVE = False
SELECTION = None
ORIGINAL = None
CONNECTION = None
TEST_MODE = None  # Test harnesses set this in memory; not a production setting.
CONNECTION_LOCK = threading.Lock()
CONFIG_KEY = 'embedding_config'
DEPTH_DEFAULTS = {
    'quick': dict(candidate_k=20, n_results=5, max_per_endpoint=1, snippet_len=120, raw_chars=0, neighbors=0),
    'normal': dict(candidate_k=40, n_results=8, max_per_endpoint=1, snippet_len=200, raw_chars=2000, neighbors=3),
    'deep': dict(candidate_k=120, n_results=25, max_per_endpoint=2, snippet_len=400, raw_chars=8000, neighbors=6),
}
DEFAULTS = {'timeout': 120, 'send_dimensions': True, 'revision': '', 'base_url': None,
            'provider': None, 'opencode_server': None, 'keep_alive': '30m',
            'batch_docs': 32, 'batch_chars': 48000, 'workers': 2, 'candidate_ceiling': 1000}
EMBEDDING_FLAGS = {
    'provider': '--embedding-provider', 'preset': '--embedding-preset',
    'model': '--embedding-model', 'revision': '--embedding-revision',
    'dimensions': '--embedding-dimensions', 'context_tokens': '--embedding-context-tokens',
    'timeout': '--embedding-timeout', 'base_url': '--embedding-base-url',
    'keep_alive': '--embedding-keep-alive', 'opencode_server': '--opencode-server',
    'batch_docs': '--embed-batch-docs', 'batch_chars': '--embed-batch-chars',
    'workers': '--embed-workers', 'candidate_ceiling': '--candidate-ceiling',
    'max_distance_graph': '--max-distance-graph', 'max_distance_attacks': '--max-distance-attacks',
}


class JsonArgumentParser(argparse.ArgumentParser):
    """Usage errors use the same JSON envelope as runtime errors."""

    def error(self, message):
        command = self.prog.split()[-1] if ' ' in self.prog else self.command_word()
        print(json.dumps({'command': command, 'error': message,
                          'help': f'jeb {command} -h' if command else 'jeb -h'}))
        sys.exit(2)

    def command_word(self):
        """The subcommand being parsed, for errors the top-level parser raises."""
        choices = [a.choices for a in self._actions if isinstance(a, argparse._SubParsersAction)]
        word = leading_command(sys.argv[1:]) or ''
        return word if not choices or word in choices[0] else ''


def hoist(argv, commands):
    """Move global flags written before the subcommand to just after it.

    Without a subcommand they are dropped, so the parser reports the missing
    command or prints help instead of misreading a flag value as the command.
    """
    argv, leading = list(argv), []
    while argv and argv[0] not in commands:
        flag = argv[0].split('=', 1)[0]
        if flag not in GLOBAL_FLAGS:
            break
        width = 2 if GLOBAL_FLAGS[flag] and '=' not in argv[0] else 1
        leading += argv[:width]
        del argv[:width]
    return argv[:1] + leading + argv[1:] if argv and argv[0] in commands else argv


def leading_command(argv):
    """The subcommand word, skipping global flags written before it."""
    i = 0
    while i < len(argv) and argv[i].split('=', 1)[0] in GLOBAL_FLAGS:
        i += 2 if GLOBAL_FLAGS[argv[i].split('=', 1)[0]] and '=' not in argv[i] else 1
    return argv[i] if i < len(argv) and not argv[i].startswith('-') else None


def get(name, default=None):
    """Typed process settings, initialized before importing engine modules."""
    return (SELECTION or {}).get(name, DEFAULTS.get(name, default))


def distance(value):
    if value.lower() == 'none':
        return None
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError('Use none or a finite cosine distance in [0, 2].') from None
    if not math.isfinite(number) or not 0 <= number <= 2:
        raise argparse.ArgumentTypeError('Use none or a finite cosine distance in [0, 2].')
    return number


def add_embedding_args(parser):
    for key, flag in EMBEDDING_FLAGS.items():
        if key == 'opencode_server':
            add_server_args(parser)
            continue
        if key in ('provider', 'base_url'):
            group = parser.add_mutually_exclusive_group()
            group.add_argument(flag, dest=key, default=argparse.SUPPRESS)
            group.add_argument('--no-embedding-' + key.replace('_', '-'), dest=key,
                               action='store_const', const=None, default=argparse.SUPPRESS)
            continue
        options = {'default': argparse.SUPPRESS, 'dest': key}
        if key == 'preset':
            options['choices'] = sorted(PROFILES)
        elif key in ('dimensions', 'context_tokens', 'batch_docs', 'batch_chars', 'workers', 'candidate_ceiling'):
            options['type'] = int
        elif key == 'timeout':
            options['type'] = float
        elif key.startswith('max_distance_'):
            options.update(type=distance, help='Cosine cutoff [0, 2], or none to disable')
        parser.add_argument(flag, **options)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--embedding-send-dimensions', dest='send_dimensions', action='store_true', default=argparse.SUPPRESS)
    group.add_argument('--no-embedding-send-dimensions', dest='send_dimensions', action='store_false', default=argparse.SUPPRESS)
    for depth, fields in DEPTH_DEFAULTS.items():
        for field in fields:
            parser.add_argument('--depth-' + depth + '-' + field.replace('_', '-'),
                                dest='depth_' + depth + '_' + field, type=int, default=argparse.SUPPRESS)


def add_server_args(parser):
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--opencode-server', default=argparse.SUPPRESS)
    group.add_argument('--no-opencode-server', dest='opencode_server', action='store_const',
                       const=None, default=argparse.SUPPRESS)


def import_parser():
    parser = JsonArgumentParser(prog='jeb', description='Import and maintain cumulative Burp XML captures in Chroma.',
                                epilog='Run "jeb <command> -h" for its options.',
                                allow_abbrev=False)
    subs = parser.add_subparsers(dest='command', required=True)
    for command in IMPORT_COMMANDS:
        p = subs.add_parser(command, allow_abbrev=False, help=IMPORT_HELP[command])
        if command == 'import':
            p.add_argument('xml_file')
        if command == 'abandon':
            p.add_argument('capture_id')
        p.add_argument('project_dir', nargs='?')
        p.add_argument('--project-dir', dest='project_dir_option', metavar='PROJECT_DIR',
                       help='Same as the positional project directory (default: .)')
        if command in ('import', 'rebuild'):
            add_embedding_args(p)
            p.add_argument('--auth-cookies', action='append', default=None)
            group = p.add_mutually_exclusive_group()
            group.add_argument('--auto-detect-auth-cookies', dest='auto_detect', action='store_true')
            group.add_argument('--no-auto-detect-auth-cookies', dest='auto_detect', action='store_false')
            p.set_defaults(auto_detect=None)
            p.add_argument('--rebuild', action='store_true')
        else:
            add_server_args(p)
        if command == 'export':
            p.add_argument('--collection', choices=EXPORT_COLLECTIONS, required=True)
            p.add_argument('--output', required=True)
    # Handled by the launcher itself; listed so help and typos show every command.
    for command, text in LAUNCHER_COMMANDS.items():
        subs.add_parser(command, help=text, add_help=False)
    return parser


def parse_import(argv):
    """Parse import arguments, resolving the positional/option project directory."""
    parser = import_parser()
    args = parser.parse_args(import_argv(argv))
    if args.command in LAUNCHER_COMMANDS:
        parser.error(f'Run "{args.command}" through the jeb launcher: <jeb-import skill dir>/jeb {args.command}')
    if args.project_dir and args.project_dir_option and \
            Path(args.project_dir).resolve() != Path(args.project_dir_option).resolve():
        parser.error('Give the project directory once: positional or --project-dir.')
    args.project_dir = args.project_dir_option or args.project_dir or '.'
    return args


def import_argv(argv):
    """Hoisted import arguments; a bare capture file means `import`."""
    argv = list(argv)
    word = leading_command(argv)
    if word is not None and word not in IMPORT_COMMANDS and \
            (word.lower().endswith('.xml') or Path(word).is_file()):
        argv.insert(0, 'import')
    return hoist(argv, IMPORT_COMMANDS)


def valid_url(value, label):
    if not isinstance(value, str):
        raise ValueError(label + ' must be an HTTP(S) URL.')
    try:
        parsed = urlsplit(value)
        valid = (parsed.scheme in ('http', 'https') and parsed.hostname and not parsed.username
                 and not parsed.password and not parsed.query and not parsed.fragment)
        parsed.port
    except ValueError:
        valid = False
    if not valid or any(ord(c) <= 32 for c in value):
        raise ValueError(label + ' must be an HTTP(S) URL without credentials, whitespace, query, or fragment.')
    return value.rstrip('/')


def validate(selection):
    allowed = set(EMBEDDING_FLAGS) | {'send_dimensions', 'depth'}
    if not isinstance(selection, dict) or set(selection) - allowed:
        raise ValueError('Unsupported saved embedding selections; preserve the database.')
    preset = selection.get('preset', 'ollama-embeddinggemma2')
    if not isinstance(preset, str) or preset not in PROFILES:
        raise ValueError('Unknown embedding preset.')
    p = PROFILES[preset]
    result = {**DEFAULTS, 'preset': preset, 'model': p['model'], 'dimensions': p['dimensions'],
              'context_tokens': p['contextTokens'], **selection}
    if not isinstance(result['model'], str) or not result['model'].strip():
        raise ValueError('Embedding model must be non-empty.')
    n = result['dimensions']
    if type(n) is not int or not p['minDimensions'] <= n <= p['dimensions'] or (
            p['allowedDimensions'] and n not in p['allowedDimensions']):
        raise ValueError('Unsupported embedding dimensions for selected preset.')
    n = result['context_tokens']
    if type(n) is not int or not 1 <= n <= p['contextTokens']:
        raise ValueError('Embedding context limit exceeds the preset budget or is invalid.')
    timeout = result['timeout']
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError('Embedding timeout must be positive and finite.')
    if type(result['send_dimensions']) is not bool:
        raise ValueError('Embedding send-dimensions must be boolean.')
    provider = result['provider']
    if provider is not None and (not isinstance(provider, str) or not provider.strip()):
        raise ValueError('Embedding provider ID must be non-empty.')
    if p['backend'] == 'litellm':
        if not isinstance(result['revision'], str) or not result['revision'].strip():
            raise ValueError('LiteLLM requires --embedding-revision; pin the gateway deployment.')
        if not provider and not result['base_url']:
            raise ValueError('LiteLLM needs --embedding-provider or --embedding-base-url (keyless endpoint).')
    if p['backend'] == 'ollama' and (provider or result['revision']):
        raise ValueError('Ollama uses its local model digest, not an OpenCode provider or revision.')
    for key in ('base_url', 'opencode_server'):
        if result[key] is not None:
            result[key] = valid_url(result[key], key.replace('_', ' '))
    if not isinstance(result['keep_alive'], str) or not result['keep_alive'].strip():
        raise ValueError('Embedding keep-alive must be non-empty.')
    for key in ('batch_docs', 'batch_chars', 'workers', 'candidate_ceiling'):
        if type(result[key]) is not int or result[key] < 1:
            raise ValueError(key.replace('_', ' ') + ' must be a positive integer.')
    for key in ('max_distance_graph', 'max_distance_attacks'):
        if key in result:
            value = result[key]
            if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float))
                                      or not math.isfinite(value) or not 0 <= value <= 2):
                raise ValueError('Cosine distance must be none or a finite number in [0, 2].')
    depth = result.get('depth', {})
    if not isinstance(depth, dict) or set(depth) - set(DEPTH_DEFAULTS):
        raise ValueError('Invalid depth settings.')
    result['depth'] = {}
    for name, defaults in DEPTH_DEFAULTS.items():
        overrides = depth.get(name, {})
        if not isinstance(overrides, dict) or set(overrides) - set(defaults):
            raise ValueError('Invalid depth fields.')
        fields = {**defaults, **overrides}
        for field, value in fields.items():
            minimum = 0 if field in ('snippet_len', 'raw_chars', 'neighbors') else 1
            if type(value) is not int or value < minimum:
                raise ValueError('Depth ' + field + ' must be an integer >= ' + str(minimum) + '.')
        result['depth'][name] = fields
    return result


def load_selection(db_path):
    if not (Path(db_path) / 'chroma.sqlite3').is_file():
        return None
    import chromadb
    client = chromadb.PersistentClient(path=str(Path(db_path).resolve()))
    if 'captures' not in {c.name for c in client.list_collections()}:
        return None
    meta = client.get_collection('captures', embedding_function=None).metadata or {}
    saved = meta.get(CONFIG_KEY)
    return json.loads(saved) if saved else None


def select(saved, args=None):
    result = dict(saved or {})
    if args is not None:
        supplied = {key: value for key, value in vars(args).items()
                    if key in EMBEDDING_FLAGS or key == 'send_dimensions'}
        preset = supplied.get('preset')
        if preset and preset != result.get('preset', 'ollama-embeddinggemma2'):
            for key in ('model', 'dimensions', 'context_tokens', 'revision', 'max_distance_graph', 'max_distance_attacks'):
                result.pop(key, None)
            # Never accidentally carry a remote connection across backend types.
            old_backend = PROFILES.get(result.get('preset', 'ollama-embeddinggemma2'), {}).get('backend')
            if old_backend != PROFILES[preset]['backend']:
                result.pop('base_url', None)
                if PROFILES[preset]['backend'] == 'ollama':
                    result.pop('provider', None)
        result.update(supplied)
        depth = {name: dict(fields) for name, fields in result.get('depth', {}).items()}
        for name, fields in DEPTH_DEFAULTS.items():
            for field in fields:
                key = 'depth_' + name + '_' + field
                if hasattr(args, key):
                    depth.setdefault(name, {})[field] = getattr(args, key)
        result['depth'] = depth
    return validate(result)


def selection_argv(selection):
    """Serialize non-secret settings for CLI harnesses; never transports keys."""
    args = []
    for key, flag in EMBEDDING_FLAGS.items():
        if key in selection and selection[key] is not None:
            args += [flag, str(selection[key])]
        elif key.startswith('max_distance_') and key in selection:
            args += [flag, 'none']
        elif key in ('provider', 'base_url', 'opencode_server') and key in selection:
            args.append('--no-opencode-server' if key == 'opencode_server' else '--no-embedding-' + key.replace('_', '-'))
    args.append('--embedding-send-dimensions' if selection.get('send_dimensions', True) else '--no-embedding-send-dimensions')
    for name, fields in selection.get('depth', {}).items():
        for field, value in fields.items():
            args += ['--depth-' + name + '-' + field.replace('_', '-'), str(value)]
    return args


IDENTITY = ('preset', 'model', 'dimensions', 'context_tokens', 'revision')


def stored(selection):
    """The persisted form: vector identity stays pinned, while runtime defaults are
    left out so later default changes still reach existing projects."""
    result = {}
    for key, value in selection.items():
        if key == 'depth':
            depth = {name: {field: v for field, v in fields.items() if DEPTH_DEFAULTS[name][field] != v}
                     for name, fields in value.items()}
            depth = {name: fields for name, fields in depth.items() if fields}
            if depth:
                result['depth'] = depth
        elif key in IDENTITY or key not in DEFAULTS or value != DEFAULTS[key]:
            result[key] = value
    return result


def persist(captures, indexed=False):
    """Called under the import writer lock once the command is committed to the
    selection (see rebuild_project). Runtime-only changes do not reindex.
    `indexed` means the stored vectors already match this selection."""
    if SELECTION is None:
        return
    meta = dict(captures.metadata or {})
    current = json.loads(meta[CONFIG_KEY]) if meta.get(CONFIG_KEY) else None
    if current != ORIGINAL:
        raise ValueError('Project embedding selections changed concurrently; retry the command.')
    saved = stored(SELECTION)
    if current != saved:
        meta[CONFIG_KEY] = json.dumps(saved, sort_keys=True)
        try:
            previous = validate(current) if current is not None else None
        except ValueError:
            previous = None
        if not indexed and (previous is None or any(previous.get(k) != SELECTION.get(k) for k in IDENTITY)):
            meta['index_state'] = 'pending'
        captures.modify(metadata=meta)


def api(path):
    try:
        command = ['opencode', 'api']
        if get('opencode_server'):
            command += ['--server', get('opencode_server')]
        # Inherit the OpenCode CLI's authentication context, never dump responses.
        proc = subprocess.run([*command, 'get', path], capture_output=True, text=True, timeout=30)
        if proc.returncode:
            raise ValueError('OpenCode lookup failed.')
        return json.loads(proc.stdout)['data']
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError):
        raise ValueError('Could not resolve OpenCode embedding connection; check the selected provider/server in OpenCode.') from None


def _provider_connection():
    provider_id = get('provider')
    if not provider_id:
        return {'base_url': get('base_url') or 'http://localhost:11434', 'api_key': '', 'headers': {}}
    provider = api('/api/provider/' + quote(provider_id, safe=''))
    if not isinstance(provider, dict) or (provider.get('settings') is not None and not isinstance(provider['settings'], dict)):
        raise ValueError('OpenCode provider response has no endpoint settings.')
    if provider.get('activation') == 'disabled':
        raise ValueError('Selected OpenCode embedding provider is disabled.')
    settings = provider.get('settings') or {}
    base_url = valid_url(get('base_url') or settings.get('baseURL'), 'Selected provider baseURL')
    headers = provider.get('headers') or {}
    if not isinstance(headers, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in headers.items()):
        raise ValueError('Selected provider headers must be strings.')
    key = settings.get('apiKey')
    if key is not None and not isinstance(key, str):
        raise ValueError('Selected provider API key is invalid.')
    # Provider-configured headers may implement non-bearer authentication. Without
    # an integration, settings/headers (or an intentionally keyless gateway) suffice.
    integration_id = provider.get('integrationID')
    header_auth = any(k.lower() in ('authorization', 'x-api-key', 'api-key') for k in headers)
    if not key and not header_auth and integration_id:
        if not isinstance(integration_id, str):
            raise ValueError('Invalid OpenCode integration ID.')
        integration = api('/api/integration/' + quote(integration_id, safe=''))
        if not isinstance(integration, dict) or not isinstance(integration.get('connections'), list):
            raise ValueError('OpenCode integration response has no connections.')
        connections = [c for c in integration['connections'] if isinstance(c, dict) and c.get('type') == 'credential']
        if connections:
            credentials = api('/api/credential')  # Broad public API; keep response private.
            if not isinstance(credentials, list):
                raise ValueError('Unexpected OpenCode credential response.')
            active = [c for c in credentials if isinstance(c, dict) and c.get('integrationID') == integration_id and c.get('active') is True]
            if len(active) != 1:
                raise ValueError('Selected integration needs exactly one active API-key credential.')
            selected = active[0]
            if not selected.get('id') or not any(c.get('id') == selected['id'] and c.get('method') == 'key' and not c.get('status') for c in connections):
                raise ValueError('Only ready API-key connections can be reused; OAuth/external connections are not forwarded.')
            credential = selected.get('value') or {}
            if not isinstance(credential, dict) or credential.get('type') != 'key' or not isinstance(credential.get('key'), str) or not credential['key']:
                raise ValueError('Selected integration does not expose an API-key credential.')
            key = credential['key']
    return {'base_url': base_url, 'api_key': key or '', 'headers': dict(headers)}


def connection():
    global CONNECTION
    with CONNECTION_LOCK:
        if CONNECTION is None:
            result = _provider_connection()
            base = valid_url(result['base_url'], 'Embedding base URL')
            preset = get('preset', 'ollama-embeddinggemma2')
            if PROFILES[preset]['backend'] == 'ollama':
                for suffix in ('/api/embeddings', '/api/embed'):
                    if base.endswith(suffix):
                        base = base[:-len(suffix)]
            CONNECTION = {**result, 'base_url': base}
        return CONNECTION


def run(mode, argv=None):
    global ACTIVE, SELECTION, ORIGINAL, CONNECTION
    argv = list(sys.argv[1:] if argv is None else argv)
    scripts = {'import': HERE / 'import_project.py',
               'query': HERE.parents[1] / 'jeb-query/scripts/agent_interface.py',
               'visualize': HERE / 'visualize.py',
               'store': HERE / 'vector_store.py'}
    command = 'viz' if mode == 'visualize' else leading_command(argv) or mode
    try:
        if mode == 'import':
            argv = import_argv(argv)
            args = parse_import(argv)
            command = args.command
            db_path = Path(args.project_dir).resolve() / 'chroma_db'
            read_only = command in READ_ONLY_COMMANDS
        else:
            parser = JsonArgumentParser(prog='jeb', add_help=False, allow_abbrev=False)
            group = parser.add_mutually_exclusive_group()
            group.add_argument('--project-dir')
            group.add_argument('--db-path')
            add_server_args(parser)
            args, _ = parser.parse_known_args(argv)
            db_path = (Path(args.project_dir) / 'chroma_db' if args.project_dir else Path(args.db_path or './chroma_db')).resolve()
            read_only = mode == 'visualize'
        options = argv[:argv.index('--')] if '--' in argv else argv
        if '-h' not in options and '--help' not in options:
            ORIGINAL = load_selection(db_path)
            try:
                SELECTION = select(ORIGINAL, args)
            except ValueError:
                if not read_only:
                    raise
                SELECTION = None  # Never embeds; defaults suffice to inspect a stale project.
        CONNECTION = None
        ACTIVE = True
        sys.argv = [str(scripts[mode]), *argv]
        runpy.run_path(str(scripts[mode]), run_name='__main__')
        return 0
    except (ValueError, OSError) as exc:
        print(json.dumps({'command': command, 'error': str(exc)}))
        return 1


if __name__ == '__main__':
    mode = sys.argv.pop(1)
    sys.modules['runtime'] = sys.modules[__name__]
    sys.exit(run(mode))
