"""Install managed skill files without overwriting unrecognized local changes."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def install(config, force=False):
    config = config.expanduser().absolute()
    manifest_path = config / 'skills/.jeb-install.json'
    if manifest_path.is_symlink():
        raise ValueError('Refusing a symlink installation manifest.')
    old = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    if not isinstance(old, dict):
        raise ValueError('Installation manifest must be an object; preserve it for review.')
    sources = {}
    for skill in ('jeb-import', 'jeb-query'):
        source = ROOT / skill
        sources[f'skills/{skill}/SKILL.md'] = source / 'SKILL.md'
        sources[f'skills/{skill}/jeb'] = source / 'jeb'
        for folder in ('scripts', 'references'):
            if not (source / folder).is_dir():
                continue
            for path in sorted((source / folder).iterdir()):
                if path.is_file() and not path.name.startswith('.'):
                    sources[f'skills/{skill}/{folder}/{path.name}'] = path
    sources['agents/J.E.B.E.D.I.A.H..md'] = ROOT / 'agent/J.E.B.E.D.I.A.H..md'
    operations, conflicts = [], []
    for name, source in sources.items():
        target = config / name
        # Do not follow directory symlinks into another checkout or installation.
        if any(parent.is_symlink() for parent in (target, *target.parents)):
            raise ValueError(f'Refusing symlink installation path: {target}')
        if target.exists() and not target.is_file():
            raise ValueError(f'Expected a file: {target}')
        if target.exists() and digest(target) == digest(source):
            continue
        if target.exists() and old.get(name) != digest(target):
            conflicts.append(target)
        operations.append((source, target))
    legacy = config / 'agents/jebediah.md'
    if legacy.is_dir() and not legacy.is_symlink():
        raise ValueError(f'Expected an agent file, not a directory: {legacy}')
    if legacy.exists() or legacy.is_symlink():
        conflicts.append(legacy)
    if conflicts and not force:
        raise ValueError('Conflicting files (use --force to back up): ' + ', '.join(map(str, conflicts)))
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    backups, installed = {}, []
    try:
        for target in conflicts:
            backup = target.with_name(target.name + '.backup-' + stamp)
            if backup.exists():
                raise ValueError(f'Backup already exists: {backup}')
            target.rename(backup)
            backups[target] = backup
        for source, target in operations:
            target.parent.mkdir(parents=True, exist_ok=True)
            previous = target.read_bytes() if target.exists() else None
            previous_mode = target.stat().st_mode if target.exists() else None
            installed.append((target, previous, previous_mode))
            with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as handle:
                staging = Path(handle.name)
            try:
                shutil.copy2(source, staging)
                os.replace(staging, target)
            finally:
                staging.unlink(missing_ok=True)
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode='w', dir=manifest_path.parent, delete=False) as handle:
            staging = Path(handle.name)
            json.dump({name: digest(path) for name, path in sources.items()}, handle, indent=2)
        try:
            os.replace(staging, manifest_path)
        finally:
            staging.unlink(missing_ok=True)
    except Exception:
        for target, previous, mode in reversed(installed):
            if previous is None:
                target.unlink(missing_ok=True)
            else:
                target.write_bytes(previous)
                target.chmod(mode)
        for target, backup in backups.items():
            backup.rename(target)
        raise
    print(f'Installed jeb-import, jeb-query and the primary agent into {config}')
    print('No OpenCode configuration or plugin registration was changed.')
    for backup in backups.values():
        print(f'Backup: {backup}')
    print(f'Next: "{config}/skills/jeb-import/jeb" setup [--viz]')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--force', action='store_true', help='Back up conflicting files before replacement')
    args = parser.parse_args()
    config = Path(os.environ.get('OPENCODE_CONFIG_DIR') or
                  str(Path(os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config') / 'opencode'))
    try:
        install(config, args.force)
    except (ValueError, OSError) as exc:
        parser.exit(1, f'Installation failed: {exc}\n')


if __name__ == '__main__':
    main()
