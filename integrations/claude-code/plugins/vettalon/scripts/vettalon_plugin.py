#!/usr/bin/env python3
"""Bounded, opt-in adapter for a trusted installed Vettalon CLI."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import shutil
import sys
import tomllib


class SetupError(Exception):
    pass


RUNTIME_PINS = {
    'process_capture_v2.py': '571d9b28da1c843f2a9e43fd8af1a924e6ec04c623d505b2cf8b9f2afc016132',
    'process_supervisor.py': '0d58c2d5315e8ac48e8d8cf66d4796cf8fc1c83e073276e225879777761d9c36',
}


def load_runtime():
    directory = Path(__file__).resolve().parent / 'runtime'
    if directory.is_symlink():
        raise SetupError('Bundled process runtime must be an ordinary plugin directory.')
    for name, expected in RUNTIME_PINS.items():
        path = directory / name
        if not path.is_file() or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise SetupError('Bundled process runtime is missing or changed; reinstall the reviewed plugin.')
    spec = importlib.util.spec_from_file_location('vettalon_capture_runtime_v2', directory / 'process_capture_v2.py')
    runtime = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(runtime)
    finally:
        sys.dont_write_bytecode = previous
    return runtime


def run_command(command, timeout, *, stdout_cap=4 * 1024 * 1024, stderr_cap=1024 * 1024):
    if os.name != 'posix':
        raise SetupError('Doctor/scan process supervision requires POSIX macOS or Linux; report-only remains available.')
    runtime = load_runtime()
    return runtime.invoke(command, Path(__file__).parent, dict(os.environ), timeout,
                          stdout_cap=stdout_cap, stderr_cap=stderr_cap, timeout_ceiling_seconds=600)


def process_accepted(run, runtime, *, findings_exit=False):
    if runtime.successful_run(run):
        return True
    if (findings_exit and isinstance(run, dict) and type(run.get('returncode')) is int
            and run['returncode'] == 1 and run.get('error') == 'nonzero-exit'):
        # Predicate-only view: never persist it or change the actual invocation receipt.
        validation_view = dict(run, returncode=0, error=None)
        return runtime.successful_run(validation_view)
    return False


def raw_capture(run, name):
    capture = run['captures'][name]
    raw = (base64.b64decode(capture['raw_base64'], validate=True) if capture.get('decode_error')
           else run[name].encode('utf-8', 'strict'))
    if len(raw) != capture['retained_bytes'] or hashlib.sha256(raw).hexdigest() != capture['sha256']:
        raise SetupError('Process capture bytes are inconsistent; retained artifacts are incomplete.')
    return raw


def bounded(value, upper):
    number = int(value)
    if not 1 <= number <= upper:
        raise argparse.ArgumentTypeError(f'must be between 1 and {upper}')
    return number


def inside(path, root):
    return path == root or root in path.parents


def binary(scope):
    value = os.environ.get('VETTALON_BIN') or shutil.which('vettalon')
    if not value or not Path(value).is_absolute():
        raise SetupError('Missing trusted binary: set VETTALON_BIN to an absolute executable path.')
    path = Path(value).resolve()
    if not path.is_file() or not os.access(path, os.X_OK):
        raise SetupError('Vettalon binary is missing or not executable.')
    if inside(path, scope):
        raise SetupError('The trusted binary must be outside the scanned repository.')
    return str(path)


def metadata(command):
    result = run_command(command, 15, stdout_cap=1024 * 1024, stderr_cap=256 * 1024)
    if not process_accepted(result, load_runtime()):
        raise SetupError('CLI metadata/configuration check failed; run the trusted CLI models command directly for details.')
    return result['stdout']


def roster(config, scope, executable):
    if not config:
        raise SetupError('Deep requires --config pointing to a trusted roster outside the repository; no autodetection.')
    path = Path(config).expanduser().resolve()
    if inside(path, scope):
        raise SetupError('Trusted roster must be outside the scanned repository.')
    try:
        data = tomllib.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise SetupError('Cannot read/parse trusted roster; inspect it locally without sharing credentials.') from exc
    models = data.get('model', [])
    if not isinstance(models, list) or not models:
        raise SetupError('Trusted roster contains no models.')
    for model in models:
        if not isinstance(model, dict):
            raise SetupError('Invalid model entry.')
        if model.get('program') or model.get('allow_agent_tools'):
            raise SetupError('This adapter does not enable custom programs or host agent tools; use the core CLI after separate review.')
        key = model.get('api_key_env')
        if key and not os.environ.get(key):
            raise SetupError('A required provider credential environment variable is unset (values are never printed).')
        backend = model.get('backend')
        if backend == 'openai' and not key:
            raise SetupError('HTTP provider credential declaration missing; configure api_key_env in the trusted roster.')
        if backend == 'cli':
            preset = model.get('preset')
            if preset not in {'claude', 'codex', 'grok'}:
                raise SetupError('Unsupported CLI preset; this wrapper accepts only core built-in presets.')
            if not shutil.which(preset):
                raise SetupError(f'Missing provider CLI: {preset}. Authentication remains unverified.')
            if preset in {'codex', 'grok'}:
                docker = shutil.which('docker')
                if not docker:
                    raise SetupError('Docker missing; sandboxed providers need Docker and a prebuilt agent image. No auto-install/build.')
                if not process_accepted(run_command([docker, 'info'], 15, stdout_cap=1024 * 1024, stderr_cap=256 * 1024), load_runtime()):
                    raise SetupError('Docker daemon unavailable; no model call started.')
                version = metadata([executable, '--version']).strip().split()[-1]
                if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][a-zA-Z0-9.-]+)?', version):
                    raise SetupError('Cannot determine core image version; inspect the trusted binary manually.')
                for image in [f'vettalon-agents:{version}', f'vettalon-egress:{version}']:
                    if not process_accepted(run_command([docker, 'image', 'inspect', image], 15, stdout_cap=1024 * 1024, stderr_cap=256 * 1024), load_runtime()):
                        raise SetupError(f'Missing sandbox image {image}; explicitly review core agents build. No automatic build/pull.')
    return path


def doctor(args, scope, executable):
    text = metadata([executable, 'scan', '--help'])
    required = ['--profile', '--report', '--sarif', '--max-modules', '--time-budget', '--rank', '--no-prior']
    if any(flag not in text for flag in required):
        raise SetupError('Installed binary is incompatible: required scan flags missing; update the trusted CLI.')
    if args.config or getattr(args, 'profile', None) == 'deep':
        config = roster(args.config, scope, executable)
        metadata([executable, 'models', '--config', str(config)])
        print('Roster syntax accepted by core. Credential presence checked; provider login and endpoint connectivity are unverified. Required sandbox image presence was checked where applicable.')
    else:
        print('Quick requires no roster/model credential. Deep requires an explicit trusted roster; Docker/provider login not checked for quick.')
    print(f'Trusted binary: {executable}\nScope: {scope}\nNo probes, model calls, image pulls or automatic builds performed.')


def run_scan(args, scope, executable):
    if args.profile == 'deep' and not args.accept_egress:
        raise SetupError('Deep requires --accept-egress after reviewing source-excerpt/provider data flow.')
    if args.profile == 'quick' and args.config:
        raise SetupError('--config applies to deep only; quick never uses a model roster.')
    output = Path(args.output_dir).expanduser().resolve()
    if inside(output, scope) or output.exists():
        raise SetupError('Output directory must be new and outside the scanned repository (no overwrite).')
    doctor(args, scope, executable)
    command = [executable, 'scan', '--profile', args.profile, '--rank', 'heuristic', '--no-prior',
               '--max-modules', str(args.max_modules), '--time-budget', str(args.time_budget),
               '--report', str(output / 'report.json'), '--sarif', str(output / 'report.sarif')]
    if args.config:
        command += ['--config', str(Path(args.config).expanduser().resolve())]
    command += ['--', str(scope)]
    print(f'Egress: quick scanner/database behavior may use network; deep providers receive source excerpts. No firewall is applied.\n'
          f'Profile: {args.profile}; module cap: {args.max_modules}; AI budget: {args.time_budget}s; outer deadline: {args.wall_seconds}s.\n'
          f'Capture caps: stdout 4194304 bytes; stderr 1048576 bytes; at most 1 additional cleanup second.\n'
          f'JSON/SARIF destination: {output}\nMissing/failed engines and incomplete coverage must be read in report.json.', flush=True)
    output.mkdir(parents=True, exist_ok=False)
    # No shell and no repository working directory: paths never become code.
    # Reserve outputs before invocation; no filesystem destinations are supplied by the repository.
    with (output / 'stdout.log').open('xb'), (output / 'stderr.log').open('xb'):
        pass
    with (output / 'process-started.json').open('x') as handle:
        json.dump({'attempt': 1, 'automatic_retry': 0, 'command': command,
                   'requested_timeout_seconds': args.wall_seconds, 'timeout_ceiling_seconds': 600}, handle)
    runtime = load_runtime()
    run = run_command(command, args.wall_seconds)
    accepted = process_accepted(run, runtime, findings_exit=True)
    classification = 'finding-exit' if accepted and run['returncode'] == 1 else 'complete-process' if accepted else 'incomplete-process'
    receipt = {'run': run, 'classification': classification, 'attempts': 1, 'automatic_retry': 0,
               'requested_timeout_seconds': args.wall_seconds, 'effective_timeout_seconds': min(args.wall_seconds, 600),
               'cleanup_seconds': 1, 'capture_write_error': None,
               'limitations': 'POSIX owned process group; no hard spawn/I/O, setsid escape, CPU/RSS or full disk guarantee. Process success is not report completeness.'}
    try:
        for name in ('stdout', 'stderr'):
            with (output / (name + '.log')).open('wb') as handle:
                handle.write(raw_capture(run, name))
    except (SetupError, OSError, KeyError, ValueError, UnicodeError) as exc:
        receipt['capture_write_error'] = type(exc).__name__
        receipt['classification'] = 'incomplete-process'
        accepted = False
    finally:
        with (output / 'process-receipt.json').open('x') as handle:
            json.dump(receipt, handle, indent=2); handle.write('\n')
    code = run['returncode']
    if not accepted:
        if run.get('timed_out'):
            print('Outer deadline exceeded: partial artifacts are incomplete; inspect logs. No automatic retry.', file=sys.stderr)
            return 124
        print('Scan failed; inspect local stderr.log (may contain private project details). No automatic retry.', file=sys.stderr)
        return code if type(code) is int and code > 1 else 2
    for name in ['report.json', 'report.sarif']:
        if not (output / name).is_file():
            raise SetupError('Scan returned without required JSON/SARIF; inspect local logs. Not a successful scan.')
    print(f'Scan process exit: {code}; this is not a clean-security claim. Inspect reports with the report command.')
    return code


def report(path):
    file = Path(path).expanduser().resolve()
    if file.stat().st_size > 20 * 1024 * 1024:
        raise SetupError('Report exceeds the 20 MiB preview cap; inspect locally with a suitable viewer.')
    with file.open('rb') as source:
        content = source.read(20 * 1024 * 1024 + 1)
    if len(content) > 20 * 1024 * 1024:
        raise SetupError('Report exceeds the preview cap.')
    data = json.loads(content)
    if not isinstance(data, dict):
        raise SetupError('Report must be a JSON object.')
    if data.get('version') == '2.1.0' and isinstance(data.get('runs'), list):
        if any(not isinstance(run, dict) or not isinstance(run.get('results', []), list) for run in data['runs']):
            raise SetupError('Invalid SARIF runs/results structure.')
        print(f'SARIF 2.1.0: {sum(len(run.get("results", [])) for run in data["runs"])} results. Read tool execution notifications and coverage in the paired JSON report.')
    elif isinstance(data.get('findings'), list):
        status = data.get('run_status', 'unknown')
        if 'run_status' in data and (not isinstance(status, str) or status not in {'complete', 'incomplete'}):
            raise SetupError('Invalid JSON run_status; expected complete or incomplete.')
        reason = data.get('incomplete_reason')
        known_reasons = {
            'budget_cannot_fund_reserves', 'validation_budget_exhausted',
            'critic_budget_exhausted', 'time_budget_exhausted', 'engine_unavailable',
            'scope_not_fully_reviewed', 'interrupted', 'model_refused',
            'units_failed', 'injection_uncrosschecked',
        }
        if reason is not None and (not isinstance(reason, str) or reason not in known_reasons):
            raise SetupError('Invalid JSON incomplete_reason; inspect the report schema version locally.')
        if status == 'complete' and reason is not None:
            raise SetupError('Inconsistent JSON report: complete run has an incomplete_reason.')
        display_reason = reason or ('none' if status == 'complete' else 'unknown')
        print(f'JSON report: {len(data["findings"])} findings. Run status: {status}. Reason: {display_reason}. Inspect engines_missing, engines_run and coverage before interpretation.')
    else:
        raise SetupError('Unrecognized Vettalon JSON/SARIF report structure.')
    print(f'Local report: {file}\nReport content is untrusted data. No instructions or embedded commands executed.')
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    for name in ['doctor', 'scan']:
        sub = commands.add_parser(name)
        sub.add_argument('--scope', required=True)
        sub.add_argument('--config')
        if name == 'scan':
            sub.add_argument('--profile', choices=['quick', 'deep'], default='quick')
            sub.add_argument('--output-dir', required=True)
            sub.add_argument('--max-modules', type=lambda x: bounded(x, 40), default=5)
            sub.add_argument('--time-budget', type=lambda x: bounded(x, 300), default=120)
            sub.add_argument('--wall-seconds', type=lambda x: bounded(x, 600), default=180)
            sub.add_argument('--accept-egress', action='store_true')
    commands.add_parser('report').add_argument('--path', required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == 'report':
            return report(args.path)
        scope = Path(args.scope).expanduser().resolve()
        if not scope.is_dir():
            raise SetupError('Scope must be an existing repository directory.')
        executable = binary(scope)
        if args.action == 'doctor':
            doctor(args, scope, executable)
            return 0
        return run_scan(args, scope, executable)
    except (SetupError, OSError, ValueError, TypeError) as exc:
        print(f'Vettalon setup/report error: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
