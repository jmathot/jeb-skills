"""Executable, quoted follow-up commands that keep the caller's project selection."""
from pathlib import Path
import shlex

LOCATION = []
SERVER_ARGS = []
DATABASE = None
HERE = Path(__file__).resolve().parent
QUERY = HERE.parent / 'jeb'
IMPORT = HERE.parents[1] / 'jeb-import/jeb'
POSITIONALS = {'endpoint': 'target', 'get': 'target', 'similar': 'target',
               'identifier': 'target', 'evidence': 'target', 'graph': 'target', 'search': 'text'}


def launcher(path):
    """The launcher path, written as ~/... under the home directory."""
    try:
        return '~/' + shlex.quote(str(path.relative_to(Path.home())))
    except (ValueError, RuntimeError):
        return shlex.quote(str(path))


def set_location(project_dir=None, db_path=None):
    """Echo the selection the caller gave; omitted means ./chroma_db in the cwd."""
    global LOCATION, DATABASE, SERVER_ARGS
    SERVER_ARGS = []
    if project_dir:
        LOCATION = ['--project-dir', str(Path(project_dir).resolve())]
        DATABASE = Path(project_dir).resolve() / 'chroma_db'
    elif db_path:
        LOCATION = ['--db-path', str(Path(db_path).resolve())]
        DATABASE = Path(db_path).resolve()
    else:
        LOCATION, DATABASE = [], None


def set_server(server):
    global SERVER_ARGS
    SERVER_ARGS = ['--opencode-server', server] if server is not None else ['--no-opencode-server']


def query(command, **args):
    parts = [command, *LOCATION, *SERVER_ARGS]
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
        value = str(args[positional])
        # `--` only where the value could be read as an option.
        parts += ['--', value] if value.startswith('-') else [value]
    return launcher(QUERY) + ' ' + shlex.join(parts)


def importer(command, **args):
    # An explicit database may have a nonstandard basename. Its parent alone
    # would select another store; never emit a misleading rebuild command.
    if DATABASE is not None and DATABASE.name != 'chroma_db':
        return ''
    parts = [command]
    if DATABASE is not None:
        parts += ['--project-dir', str(DATABASE.parent)]
    parts += SERVER_ARGS
    for key, value in args.items():
        if value is not None and value != '':
            parts += ['--' + key.replace('_', '-'), str(value)]
    return launcher(IMPORT) + ' ' + shlex.join(parts)


def rebuild_note(reason):
    """A rebuild instruction carrying a runnable command when one can be built."""
    command = importer('rebuild')
    return reason + (' Run: ' + command if command else ' Rebuild the project with jeb-import.') + \
        ' Retain all original captures and the database.'


def import_note(reason):
    """An import instruction for a project with no finished capture."""
    command = importer('import')
    return reason + ' No capture has finished importing. ' + \
        ('Run: ' + command + ' CAPTURE.xml' if command else 'Import a capture with jeb-import.')
