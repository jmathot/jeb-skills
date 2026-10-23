"""Offline unittest entrypoint: set the network guard in process, not via envvars."""
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'jeb-import/scripts'))
import runtime
runtime.TEST_MODE = 'unit'
suite = unittest.defaultTestLoader.discover(str(HERE), pattern='test_*.py')
result = unittest.TextTestRunner().run(suite)
sys.exit(0 if result.wasSuccessful() else 1)
