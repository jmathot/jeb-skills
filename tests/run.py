"""Run offline contracts or explicitly authorized Qwen benchmarks, without JEB envvars."""
import argparse
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tier', action='append', choices=('u', 'a', 'b', 'c'))
    parser.add_argument('--live', action='store_true', help='Explicit opt-in to paid Qwen embedding requests')
    parser.add_argument('--provider', default='litellm')
    parser.add_argument('--model', default='qwen/qwen3-embedding-8b')
    parser.add_argument('--revision')
    parser.add_argument('--opencode-server')
    for flag in ('fresh', 'verbose', 'update-baseline', 'skip-import'):
        parser.add_argument('--' + flag, action='store_true')
    args = parser.parse_args()
    tiers = args.tier or (['u', 'a', 'b', 'c'] if args.live else ['u'])
    if any(t != 'u' for t in tiers) and not args.live:
        parser.error('Benchmark tiers require --live and a pinned --revision; use --tier u for offline checks.')
    if args.live and not args.revision:
        parser.error('--live requires a pinned --revision')
    if not (HERE / 'capture.xml').exists() or not (HERE / 'ground_truth.json').exists():
        subprocess.run([sys.executable, str(HERE / 'make_capture.py')], check=True)
    status = 0
    if 'u' in tiers:
        for command in ([sys.executable, str(HERE / 'test_units.py')],
                        [sys.executable, str(HERE / 'unit_suite.py')]):
            if subprocess.run(command).returncode:
                status = 1
    if any(t != 'u' for t in tiers):
        import policy
        policy.authorize(args.provider, args.model, args.revision, args.opencode_server)
        import fixture
        fixture.ensure(fresh=args.fresh)
        for tier in tiers:
            if tier == 'u':
                continue
            import importlib
            module = importlib.import_module({'a': 'bench_correctness', 'b': 'bench_retrieval', 'c': 'bench_perf'}[tier])
            flags = []
            if args.verbose and tier in ('a', 'b'):
                flags.append('--verbose')
            if args.update_baseline and tier in ('b', 'c'):
                flags.append('--update-baseline')
            if args.skip_import and tier == 'c':
                flags.append('--skip-import')
            sys.argv = [str(HERE / (module.__name__ + '.py')), *flags]
            try:
                module.main()
            except SystemExit as exc:
                if exc.code not in (None, 0):
                    status = 1
    print('suite: ' + ('FAILURES above' if status else 'all selected tiers passed'))
    return status


if __name__ == '__main__':
    sys.exit(main())
