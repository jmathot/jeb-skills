"""Installer tests use an isolated configuration and never pull/call a model."""
import os
from pathlib import Path
import subprocess
import shutil
import json
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='jeb-install-', dir='/tmp/opencode')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.config = self.directory / 'config with spaces'
        self.config.mkdir()
        self.bin = self.directory / 'bin'
        self.bin.mkdir()
        # Fail if the installer ever tries to call Ollama (including downloads).
        for name, body in [('opencode', '#!/bin/sh\necho "opencode v2.1.3"\n'),
                           ('ollama', '#!/bin/sh\necho forbidden > "$OPENCODE_CONFIG_DIR/forbidden"\nexit 99\n')]:
            script = self.bin / name
            script.write_text(body)
            script.chmod(0o755)
        self.env = {**os.environ, 'OPENCODE_CONFIG_DIR': str(self.config),
                    'PATH': str(self.bin) + os.pathsep + os.environ['PATH']}

    def install(self, *args):
        return subprocess.run(['bash', str(ROOT / 'install.sh'), '--skip-deps', *args], env=self.env,
                              cwd=ROOT, text=True, capture_output=True)

    def test_symlink_idempotence_and_jsonc_preservation(self):
        config = self.config / 'opencode.jsonc'
        config.write_text('{\n  // keep this comment\n  "model": "unchanged/model",\n}\n')
        for _ in range(2):
            result = self.install('--preset', 'litellm-qwen3-embedding-8b', '--model-revision', 'test-r1')
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.config / 'packages/jebediah').is_symlink())
        text = config.read_text()
        self.assertIn('// keep this comment', text)
        self.assertIn('unchanged/model', text)
        self.assertEqual(text.count('"package"'), 1)
        self.assertFalse((self.config / 'forbidden').exists())

    def test_conflict_is_preflighted_before_any_target_changes(self):
        agents = self.config / 'agents'
        agents.mkdir()
        (agents / 'jebediah.md').write_text('user work')
        self.assertNotEqual(self.install().returncode, 0)
        self.assertEqual((agents / 'jebediah.md').read_text(), 'user work')
        self.assertFalse((self.config / 'packages/jebediah').exists())

    def test_copy_and_force_preserve_existing_entries_as_backups(self):
        target = self.config / 'packages/jebediah'
        target.mkdir(parents=True)
        (target / 'user.txt').write_text('keep')
        result = self.install('--copy', '--force')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((target / 'src/index.ts').is_file())
        backups = list(target.parent.glob('jebediah.backup.*'))
        self.assertEqual(len(backups), 1)
        self.assertEqual((backups[0] / 'user.txt').read_text(), 'keep')
        self.assertFalse((target / 'engine/.venv').exists())

    def test_bad_configuration_does_not_install(self):
        (self.config / 'opencode.jsonc').write_text('{invalid')
        self.assertNotEqual(self.install().returncode, 0)
        self.assertFalse((self.config / 'packages/jebediah').exists())

    def test_litellm_revision_is_required(self):
        self.assertNotEqual(self.install('--preset', 'litellm-gemini-embedding-2').returncode, 0)
        self.assertFalse((self.config / 'packages/jebediah').exists())

    def test_switching_install_modes_updates_one_registration(self):
        self.assertEqual(self.install().returncode, 0)
        copied = self.install('--copy', '--force')
        self.assertEqual(copied.returncode, 0, copied.stderr)
        config = json.loads((self.config / 'opencode.jsonc').read_text())
        self.assertEqual(len(config['plugins']), 1)
        self.assertEqual(config['plugins'][0]['package'], str(self.config / 'packages/jebediah'))

    def test_failed_config_write_rolls_back_replacements(self):
        target = self.config / 'packages/jebediah'
        target.mkdir(parents=True)
        (target / 'user.txt').write_text('keep')
        node = self.bin / 'node'
        node.write_text('#!/bin/sh\ncase "$1" in *install-config.mjs) [ "$2" != write ] || exit 42 ;; esac\nexec "$JEB_REAL_NODE" "$@"\n')
        node.chmod(0o755)
        self.env['JEB_REAL_NODE'] = shutil.which('node')
        result = self.install('--force')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((target / 'user.txt').read_text(), 'keep')
        self.assertFalse((self.config / 'agents/jebediah.md').exists())
        self.assertFalse((self.config / 'opencode.jsonc').exists())
        self.assertFalse((self.config / '.jeb-install.lock').exists())


if __name__ == '__main__':
    unittest.main()
