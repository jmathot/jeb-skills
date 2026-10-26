"""User-facing text names only commands that exist."""
import ast
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'jeb-import/scripts'))
import runtime

# Removed scripts; only the migration notes and changelog may still name them.
REMOVED = ('process_burp.sh', 'jeb-query.sh', 'setup.sh', 'visualize.sh')
HISTORY = {ROOT / 'docs/migration.md', ROOT / 'CHANGELOG.md'}
IMPORT_COMMANDS = {*runtime.IMPORT_COMMANDS, 'setup', 'viz'}
QUERY_COMMANDS = {'endpoint', 'map', 'search', 'get', 'similar', 'identifier', 'evidence',
                  'graph', 'attacks', 'record-attack', 'status'}


def documents():
    yield from (ROOT / name for name in ('README.md', 'examples/README.md', 'docs/testing.md',
                                         'agent/J.E.B.E.D.I.A.H..md'))
    for skill in ('jeb-import', 'jeb-query'):
        yield ROOT / skill / 'SKILL.md'
        yield ROOT / skill / 'jeb'
        yield from sorted((ROOT / skill / 'references').glob('*.md'))


def string_literals(path):
    """Non-docstring string constants: what a script can print or run."""
    tree = ast.parse(path.read_text())
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            first = node.body[0] if node.body else None
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                docstrings.add(id(first.value))
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
            yield node.lineno, node.value


class DocsTests(unittest.TestCase):
    def test_no_removed_script_names(self):
        found = []
        for path in documents():
            for number, line in enumerate(path.read_text().splitlines(), 1):
                found += [f'{path.relative_to(ROOT)}:{number}:{name}' for name in REMOVED if name in line]
        for path in sorted(ROOT.glob('jeb-*/scripts/*.py')):
            for number, text in string_literals(path):
                found += [f'{path.relative_to(ROOT)}:{number}:{name}' for name in REMOVED if name in text]
        self.assertEqual(found, [])
        for path in HISTORY:
            self.assertTrue(path.is_file(), path)

    def test_documented_commands_exist(self):
        # `jeb <word>` in the skill docs must be a command of that skill's launcher.
        for skill, commands in (('jeb-import', IMPORT_COMMANDS), ('jeb-query', QUERY_COMMANDS)):
            for path in (ROOT / skill / 'SKILL.md', *sorted((ROOT / skill / 'references').glob('*.md'))):
                for word in re.findall(r'(?<![\w/-])jeb ([a-z][a-z-]*)', path.read_text()):
                    self.assertIn(word, commands, f'{path.relative_to(ROOT)}: jeb {word}')


if __name__ == '__main__':
    unittest.main()
