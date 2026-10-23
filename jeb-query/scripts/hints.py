"""Executable, quoted follow-up commands retaining the selected database."""
from pathlib import Path
import shlex

DATABASE = None
SERVER_ARGS = []
HERE = Path(__file__).resolve().parent
QUERY = HERE / 'jeb-query.sh'
IMPORT = HERE.parents[1] / 'jeb-import/scripts/process_burp.sh'
POSITIONALS = {'endpoint': 'target', 'get': 'target', 'similar': 'target',
               'identifier': 'target', 'evidence': 'target', 'graph': 'target', 'search': 'text'}


def set_database(path):
    global DATABASE, SERVER_ARGS
    DATABASE = str(Path(path).resolve())
    SERVER_ARGS = []


def set_server(server):
    global SERVER_ARGS
    SERVER_ARGS = ['--opencode-server', server] if server is not None else ['--no-opencode-server']


def query(command, **args):
    parts = ['bash', str(QUERY), command]
    parts += SERVER_ARGS
    if DATABASE:
        parts += ['--db-path', DATABASE]
    positional = POSITIONALS.get(command)
    for key, value in args.items():
        if key == positional or value is None or value == '':
            continue
        flag = '--in' if key == 'collection' else '--' + key.replace('_', '-')
        if isinstance(value, bool):
            if value:
                parts.append(flag)
        else:
            parts += [flag, str(value)]
    if positional and args.get(positional) not in (None, ''):
        parts += ['--', str(args[positional])]
    return shlex.join(parts)


def importer(command, **args):
    parts = ['bash', str(IMPORT), command]
    parts += SERVER_ARGS
    for key, value in args.items():
        if value is not None and value != '':
            parts += ['--' + key.replace('_', '-'), str(value)]
    # An explicit database may have a nonstandard basename. Its parent alone
    # would select another store; never emit a misleading rebuild command.
    if DATABASE and Path(DATABASE).name != 'chroma_db':
        return ''
    parts += ['--', str(Path(DATABASE).parent) if DATABASE else '.']
    return shlex.join(parts)
