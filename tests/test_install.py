"""Standalone installation tests, always using disposable config directories."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='jeb-skills-')
        self.addCleanup(self.temp.cleanup)
        self.config = Path(self.temp.name) / 'config with spaces'
        self.env = {**os.environ, 'OPENCODE_CONFIG_DIR': str(self.config)}

    def install(self, *args):
        return subprocess.run(['bash', str(ROOT / 'install-skills.sh'), *args],
                              env=self.env, capture_output=True, text=True)

    def test_clean_repeat_install_preserves_configuration_and_environment(self):
        self.config.mkdir()
        document = '{ // preserve comments\n "plugins": ["other-plugin"]\n}\n'
        (self.config / 'opencode.jsonc').write_text(document)
        for _ in range(2):
            result = self.install()
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.config / 'opencode.jsonc').read_text(), document)
        self.assertTrue((self.config / 'skills/jeb-import/scripts/embedding-profiles.json').is_file())
        self.assertTrue((self.config / 'skills/jeb-query/SKILL.md').is_file())
        self.assertTrue((self.config / 'agents/J.E.B.E.D.I.A.H..md').is_file())
        for skill in ('jeb-import', 'jeb-query'):
            launcher = self.config / 'skills' / skill / 'jeb'
            self.assertTrue(os.access(launcher, os.X_OK), launcher)
            self.assertTrue(list((self.config / 'skills' / skill / 'references').glob('*.md')))
        # Everything stays inside the OpenCode configuration directory.
        self.assertEqual({p.name for p in self.config.iterdir()}, {'opencode.jsonc', 'skills', 'agents'})
        venv = self.config / 'skills/jeb-import/scripts/venv/local'
        venv.parent.mkdir()
        venv.write_text('keep')
        self.assertEqual(self.install().returncode, 0)
        self.assertEqual(venv.read_text(), 'keep')
        self.assertFalse((self.config / 'plugins').exists())
        self.assertFalse((self.config / 'packages').exists())

    def test_conflicts_are_preflighted_and_forced_replacements_backed_up(self):
        target = self.config / 'skills/jeb-query/SKILL.md'
        target.parent.mkdir(parents=True)
        target.write_text('local work')
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.config / 'skills/jeb-import/SKILL.md').exists())
        self.assertEqual(target.read_text(), 'local work')
        self.assertEqual(self.install('--force').returncode, 0)
        backups = list(target.parent.glob('SKILL.md.backup-*'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(), 'local work')

    def test_modified_managed_file_is_not_silently_overwritten(self):
        self.assertEqual(self.install().returncode, 0)
        target = self.config / 'skills/jeb-import/scripts/runtime.py'
        target.write_text('my changes')
        self.assertNotEqual(self.install().returncode, 0)
        self.assertEqual(target.read_text(), 'my changes')

    def test_legacy_agent_requires_force_and_is_backed_up(self):
        legacy = self.config / 'agents/jebediah.md'
        legacy.parent.mkdir(parents=True)
        legacy.write_text('legacy agent')
        self.assertNotEqual(self.install().returncode, 0)
        self.assertEqual(self.install('--force').returncode, 0)
        self.assertFalse(legacy.exists())
        self.assertEqual(next(legacy.parent.glob('jebediah.md.backup-*')).read_text(), 'legacy agent')

    def test_symlink_destination_is_not_followed(self):
        outside = Path(self.temp.name) / 'outside'
        outside.mkdir()
        self.config.mkdir()
        (self.config / 'skills').symlink_to(outside, target_is_directory=True)
        self.assertNotEqual(self.install('--force').returncode, 0)
        self.assertEqual(list(outside.iterdir()), [])

    def test_rollback_restores_files_if_atomic_replace_fails(self):
        spec = importlib.util.spec_from_file_location('installer', ROOT / 'scripts/install_skills.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        target = self.config / 'skills/jeb-query/SKILL.md'
        target.parent.mkdir(parents=True)
        target.write_text('local work')
        with patch.object(module.os, 'replace', side_effect=OSError('test failure')):
            with self.assertRaises(OSError):
                module.install(self.config, force=True)
        self.assertEqual(target.read_text(), 'local work')
        self.assertFalse((self.config / 'skills/jeb-import/SKILL.md').exists())


if __name__ == '__main__':
    unittest.main()
