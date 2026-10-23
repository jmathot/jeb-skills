"""Run ground-truth fact/CLI checks using deterministic fake embeddings.

This is NOT a retrieval-quality benchmark or a source of live-model baselines.
Every engine subprocess goes through offline_cli.py's mocked HTTP opener.
"""
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

import fixture
import bench_correctness
import runtime


def main():
    with tempfile.TemporaryDirectory(prefix='jeb-offline-facts-', dir='/tmp/opencode') as work, \
            patch.object(fixture, 'WORK', work), \
            patch.object(fixture, 'configure_live', return_value=runtime.validate({})), \
            patch.object(fixture, 'CLI_PREFIX', [str(Path(__file__).with_name('offline_cli.py'))]):
        bench_correctness.main()


if __name__ == '__main__':
    main()
