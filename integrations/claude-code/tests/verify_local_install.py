#!/usr/bin/env python3
"""Observe a disposable local plugin lifecycle; never certify hosted cache or sessions."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

FILES = ('.claude-plugin/plugin.json', 'scripts/vettalon_plugin.py',
         'scripts/runtime/process_capture_v2.py', 'scripts/runtime/process_supervisor.py',
         'skills/doctor/SKILL.md', 'skills/scan/SKILL.md', 'skills/report/SKILL.md')
FILE_CAP = 1024 * 1024
TOTAL_CAP = 4 * 1024 * 1024
INVENTORY_CAP = 1024 * 1024
VERSION = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?\Z')


class LifecycleError(Exception):
    pass


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result: raise LifecycleError('Duplicate inventory JSON key; observation unknown.')
        result[key] = value
    return result


def _json(text):
    def constant(_value): raise LifecycleError('Nonfinite inventory JSON; observation unknown.')
    try:
        if type(text) is not str or len(text.encode('utf-8')) > INVENTORY_CAP:
            raise LifecycleError('Inventory text is missing or exceeds its observation cap.')
        def floating(value):
            number = float(value)
            if not math.isfinite(number): raise LifecycleError('Nonfinite inventory JSON; observation unknown.')
            return number
        return json.loads(text, object_pairs_hook=_pairs, parse_constant=constant, parse_float=floating)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise LifecycleError('Inventory JSON could not be verified.') from error


def next_version(current):
    if type(current) is not str or len(current) > 128 or (match := VERSION.fullmatch(current)) is None:
        raise LifecycleError('Actual plugin manifest needs an explicit semver version.')
    major, minor, patch, prerelease = match.groups()
    if prerelease:
        parts = prerelease.split('.')
        if parts[-1].isdigit(): parts[-1] = str(int(parts[-1]) + 1)
        else: parts += ['lifecycle', '1']
        return f'{major}.{minor}.{patch}-' + '.'.join(parts)
    return f'{major}.{minor}.{int(patch) + 1}-lifecycle.1'


def _regular_bytes(path, cap):
    """No symlink component or special-file content read, including FIFO."""
    path = Path(path).absolute()
    directory = None; leaf = None
    try:
        directory = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for part in path.parts[1:-1]:
            if part == '..': raise LifecycleError('Parent traversal is not an owned observation.')
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory); directory = following
        leaf = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        metadata = os.fstat(leaf)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > cap:
            raise LifecycleError('Owned artifact is not an ordinary bounded file.')
        with os.fdopen(leaf, 'rb') as handle:
            leaf = None; data = handle.read(cap + 1)
        if len(data) > cap: raise LifecycleError('Owned artifact exceeds its byte cap.')
        return data
    except OSError as error:
        raise LifecycleError('Owned artifact is missing, unreadable or a symlink.') from error
    finally:
        if leaf is not None: os.close(leaf)
        if directory is not None: os.close(directory)


def _snapshot(plugin):
    files = {}; total = 0; manifest = None
    for relative in FILES:
        data = _regular_bytes(plugin / relative, min(FILE_CAP, TOTAL_CAP - total))
        total += len(data)
        files[relative] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
        if relative == FILES[0]: manifest = _json(data.decode('utf-8', 'strict'))
    if type(manifest) is not dict or manifest.get('name') != 'vettalon':
        raise LifecycleError('Owned plugin manifest identity is unknown.')
    version = manifest.get('version')
    next_version(version)  # Validate, without replacing the actual declared version.
    return version, files


def _owned_directory(value, owned):
    if type(value) is not str or not value or '\x00' in value:
        raise LifecycleError('Observed installation path is missing.')
    path = Path(value)
    if not path.is_absolute() or '..' in path.parts:
        raise LifecycleError('Observed installation path is not an owned absolute path.')
    try: relative = path.relative_to(owned)
    except ValueError as error: raise LifecycleError('Observed installation is outside the owned temporary root.') from error
    current = owned
    for component in relative.parts:
        current /= component
        try: info = current.lstat()
        except OSError as error: raise LifecycleError('Observed owned directory is missing.') from error
        if stat.S_ISLNK(info.st_mode): raise LifecycleError('Observed owned directory contains a symlink.')
        if not stat.S_ISDIR(info.st_mode): raise LifecycleError('Observed owned directory is not ordinary.')
    return path


def observe_inventory(text, owned, source, expected_version, expected_files):
    """Known list-JSON projection, from statically reviewed CLI source, not registry guesses."""
    rows = _json(text)
    if type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict:
        raise LifecycleError('Installed inventory shape or unique plugin entry is unknown.')
    row = rows[0]
    if (row.get('id') != 'vettalon@vettalon-local' or row.get('scope') != 'user'
            or row.get('enabled') is not True
            or ('errors' in row and (type(row['errors']) is not list or row['errors']))):
        raise LifecycleError('Installed plugin identity, scope, enabled state or load errors are unknown.')
    recorded = row.get('version')
    if type(recorded) is not str or len(recorded) > 128:
        raise LifecycleError('Recorded installed version is unknown.')
    next_version(recorded)  # Validate shape only; local folder version may legitimately be newer.
    installed = _owned_directory(row.get('installPath'), owned)
    if 'readFromFolder' in row:
        selected = _owned_directory(row['readFromFolder'], owned)
        if selected != source:
            raise LifecycleError('Relative-path inventory does not identify the exact owned source.')
        version = row.get('folderVersion'); kind = 'local-relative-source'
    else:
        if 'folderVersion' in row: raise LifecycleError('Folder version has no observed folder path.')
        selected = installed; version = recorded; kind = 'owned-cache-copy-from-local-source'
    if version != expected_version:
        raise LifecycleError('Observed installed/source version is stale or unknown; partial retained.')
    actual_version, actual_files = _snapshot(selected)
    if actual_version != expected_version or actual_files != expected_files:
        raise LifecycleError('Observed installed artifact bytes do not match the owned expected source.')
    # Reopen the exact seven files; a source mutation during observation cannot pass.
    if _snapshot(source) != (expected_version, expected_files) or _snapshot(selected) != (actual_version, actual_files):
        raise LifecycleError('Owned source or installed bytes changed during observation.')
    return {'event': 'installation-observed', 'observation_kind': kind,
            'expected_version': expected_version, 'observed_version': version,
            'recorded_registry_version': recorded,
            'observed_path': selected.relative_to(owned).as_posix(),
            'install_path': installed.relative_to(owned).as_posix(),
            'files': actual_files, 'files_match_owned_source': True,
            'hosted_cache_verified': False, 'session_loaded_or_executed': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path, help='New JSONL log path; existing files are refused before CLI lookup.')
    args = parser.parse_args(argv)
    try: log = args.output.open('x')
    except OSError:
        print('Output must be a new writable log file in an existing directory; no CLI action performed.', file=sys.stderr)
        return 2
    root = Path(__file__).resolve().parents[3]
    original_plugin = root / 'integrations/claude-code/plugins/vettalon'
    before = None; status = 'partial'; exit_code = 2; observations = 0
    with log:
        def record(event):
            log.write(json.dumps(event) + '\n'); log.flush()
        try:
            before = _snapshot(original_plugin)
            claude = shutil.which('claude')
            if not claude: raise LifecycleError('Claude CLI not found on PATH; install it separately before lifecycle verification.')
            with tempfile.TemporaryDirectory(prefix='vettalon-isolated-plugin-') as directory:
                temp = Path(directory).resolve()
                for name in ('home', 'config', 'tmp'): (temp / name).mkdir()
                marketplace = temp / 'marketplace'
                shutil.copytree(root / 'integrations/claude-code', marketplace,
                                ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '*.pyo'))
                source = marketplace / 'plugins/vettalon'
                expected_version, expected_files = _snapshot(source)
                env = {'HOME': str(temp / 'home'), 'CLAUDE_CONFIG_DIR': str(temp / 'config'),
                       'TMPDIR': str(temp / 'tmp'), 'PATH': str(Path(claude).absolute().parent) + os.pathsep + os.defpath,
                       'LANG': 'C', 'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC': '1', 'DISABLE_AUTOUPDATER': '1'}

                def call(*command):
                    try:
                        result = subprocess.run([claude, *command], cwd=temp, env=env,
                                                capture_output=True, text=True, timeout=40)
                    except subprocess.TimeoutExpired:
                        record({'args': command, 'timed_out': True})
                        raise LifecycleError('Isolated Claude CLI step timed out; partial evidence retained.') from None
                    event = {'args': command, 'exit': result.returncode,
                             'stdout_sha256': hashlib.sha256(result.stdout.encode()).hexdigest(),
                             'stderr_sha256': hashlib.sha256(result.stderr.encode()).hexdigest()}
                    if command == ('--version',):
                        match = re.fullmatch(r'(\d+\.\d+\.\d+) \(Claude Code\)\s*', result.stdout)
                        if match: event['claude_version'] = match.group(1)
                    if command[:2] == ('plugin', 'details'):
                        event['inventory_counts'] = {key: int(match.group(1)) for key in [
                            'Skills', 'Agents', 'Hooks', 'MCP servers', 'LSP servers',
                        ] if (match := re.search(r'^\s*' + re.escape(key) + r' \((\d+)\)', result.stdout, re.MULTILINE))}
                    record(event)
                    if result.returncode: raise LifecycleError('Isolated Claude CLI step failed; partial evidence retained without raw output.')
                    if command[:2] == ('plugin', 'details') and event.get('inventory_counts') != {
                            'Skills': 3, 'Agents': 0, 'Hooks': 0, 'MCP servers': 0, 'LSP servers': 0}:
                        raise LifecycleError('Plugin service inventory is unknown or differs from the owned source.')
                    if command == ('--version',) and 'claude_version' not in event:
                        raise LifecycleError('Claude CLI version response is unknown; partial retained.')
                    return result.stdout

                call('--version')
                call('plugin', 'validate', str(marketplace), '--strict')
                call('plugin', 'marketplace', 'add', str(marketplace))
                call('plugin', 'install', 'vettalon@vettalon-local', '--scope', 'user')
                observed = observe_inventory(call('plugin', 'list', '--json'), temp, source, expected_version, expected_files)
                record(dict(observed, phase='installed')); observations += 1
                call('plugin', 'details', 'vettalon')
                manifest = source / '.claude-plugin/plugin.json'
                data = _json(_regular_bytes(manifest, FILE_CAP).decode('utf-8', 'strict'))
                data['version'] = next_version(expected_version)
                manifest.write_text(json.dumps(data))
                updated_version, updated_files = _snapshot(source)
                if updated_version == expected_version: raise LifecycleError('Temporary source version did not advance.')
                call('plugin', 'marketplace', 'update', 'vettalon-local')
                call('plugin', 'update', 'vettalon@vettalon-local')
                observed = observe_inventory(call('plugin', 'list', '--json'), temp, source, updated_version, updated_files)
                record(dict(observed, phase='updated')); observations += 1
                call('plugin', 'details', 'vettalon')
                call('plugin', 'marketplace', 'remove', 'vettalon-local')
            status = 'complete'; exit_code = 0
        except LifecycleError as error:
            print(str(error), file=sys.stderr); record({'error': str(error)})
        except Exception as error:
            record({'error_type': type(error).__name__})
            print('Lifecycle verification failed; inspect the partial log. Raw error details were not recorded.', file=sys.stderr)
        finally:
            try: unchanged = before is not None and before == _snapshot(original_plugin)
            except (OSError, LifecycleError, UnicodeError): unchanged = False
            if not unchanged: status = 'partial'; exit_code = 2
            record({'status': status, 'observed_phases': observations,
                    'repository_selected_plugin_files_unchanged': unchanged,
                    'real_user_config_hashes_unchanged': None, 'profile_fingerprint_verified': False,
                    'hosted_cache_verified': False, 'session_loaded_or_executed': False,
                    'isolation': 'Clean allowlist environment; owned HOME/config/cwd/tmp. No model session or login; environment alone is not an OS credential/network boundary.'})
    return exit_code


if __name__ == '__main__': sys.exit(main())
