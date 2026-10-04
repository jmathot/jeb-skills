"""Follow-up hints emitted in every response's `next` field.

One formatter so the eight call sites cannot drift apart again (they previously
emitted `jeb-query.sh ...` shell syntax for wrappers that no longer exist). The
rendered form mirrors how the plugin exposes the engine as tools:

    jeb query command=get target=abc123
    jeb import command=rebuild

Keep entries pure invocations. Explanatory text belongs in `notes`, not appended
to the command, so a hint stays mechanically mappable to a tool call.
"""


def _render(tool, command, args):
    parts = [tool, f'command={command}']
    for key, value in args.items():
        if value is None or value == '':
            continue
        parts.append(f'{key}={value}')
    return ' '.join(parts)


def query(command, **args):
    """A `jeb_query` follow-up, e.g. query('get', target=doc_id)."""
    return _render('jeb query', command, args)


def importer(command, **args):
    """A `jeb_import` follow-up, e.g. importer('rebuild')."""
    return _render('jeb import', command, args)
