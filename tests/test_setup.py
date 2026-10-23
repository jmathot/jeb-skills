"""Environment preparation contracts; subprocesses are mocked, never pip/network."""
import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='jeb-setup-')
        self.addCleanup(self.temp.cleanup)
        self.here = Path(self.temp.name)
        (self.here / 'requirements.txt').write_text('core')
        (self.here / 'requirements-viz.txt').write_text('viz')
        spec = importlib.util.spec_from_file_location('setup_environment', ROOT / 'jeb-import/scripts/setup_environment.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.module.__file__ = str(self.here / 'setup_environment.py')

    def run_setup(self, *args, fail=False):
        def command(argv, **kwargs):
            if 'venv' in argv:
                python = self.here / 'venv/bin/python'
                python.parent.mkdir(parents=True, exist_ok=True)
                python.touch()
            elif fail:
                raise subprocess.CalledProcessError(1, ['mock-pip'])
        with patch.object(sys, 'argv', ['setup_environment.py', *args]), \
                patch.object(self.module.subprocess, 'run', side_effect=command) as run, \
                contextlib.redirect_stdout(io.StringIO()):
            self.module.main()
        return run.call_count

    def test_readiness_stamp_and_dependency_change(self):
        self.assertEqual(self.run_setup(), 2)
        self.assertEqual(self.run_setup(), 0)
        (self.here / 'requirements.txt').write_text('changed-core')
        self.assertEqual(self.run_setup(), 1)
        self.assertEqual(self.run_setup('--viz'), 1)
        self.assertEqual(self.run_setup('--viz'), 0)

    def test_failure_is_retryable_without_a_readiness_stamp(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_setup(fail=True)
        self.assertFalse((self.here / 'venv/.jeb-requirements').exists())
        self.assertEqual(self.run_setup(), 1)


if __name__ == '__main__':
    unittest.main()
