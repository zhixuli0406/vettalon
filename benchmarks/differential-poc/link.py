"""Fresh, bounded synthetic runner-to-finding linkage; never a verdict authority."""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'blind-twins'))
from protocol import digest, generate, harness, sandbox_flags

SCHEMA = 'vettalon-synthetic-link-v1'
MAX_BYTES = 4 * 1024 * 1024
COMMAND_BYTES = 256 * 1024
TOTAL_SECONDS = 300
HEX = re.compile(r'[0-9a-f]{64}\Z')
PROCESS_CONTRACT = 'vettalon-link-process-v2'
RUNTIME_DIRECTORY = Path(__file__).resolve().parents[2] / 'scripts/runtime'
RUNTIME_PINS = {
    'process_capture_v2.py': '571d9b28da1c843f2a9e43fd8af1a924e6ec04c623d505b2cf8b9f2afc016132',
    'process_supervisor.py': '0d58c2d5315e8ac48e8d8cf66d4796cf8fc1c83e073276e225879777761d9c36',
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def safe_path(path):
    """Reject symlinks in every existing component, including output parents."""
    path = Path(os.path.abspath(path))
    for component in [*reversed(path.parents), path]:
        if component.is_symlink():
            raise ValueError('Symlink path refused')
    return path



@contextmanager
def parent_fd(path):
    """Walk parent directories without following a concurrently swapped symlink."""
    path = safe_path(path)
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd, path.name
    finally:
        os.close(fd)


def mkdir_new(path):
    with parent_fd(path) as (directory, name):
        os.mkdir(name, mode=0o700, dir_fd=directory)


def read_file(path, cap=MAX_BYTES):
    with parent_fd(path) as (directory, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_size <= cap, 'Input must be a bounded regular file')
        data = bytearray()
        while len(data) <= cap:
            chunk = os.read(fd, min(65536, cap + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        require(len(data) <= cap, 'Input byte limit exceeded')
        return bytes(data)
    finally:
        os.close(fd)


def json_data(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate JSON key')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))


def write_new(path, data):
    path = safe_path(path)
    if not isinstance(data, bytes):
        data = (json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode()
    require(0 < len(data) <= MAX_BYTES, 'Artifact byte limit exceeded')
    with parent_fd(path) as (directory, name):
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)
    return data


def bind_pairs(report, bindings):
    require(isinstance(report, dict) and type(report.get('schema_version')) is int and report['schema_version'] == 2,
            'Only current product report schema 2 is supported')
    require(isinstance(bindings, dict) and set(bindings) == {'schema', 'items'} and bindings['schema'] == SCHEMA,
            'Unsupported synthetic bindings schema')
    items = bindings['items']
    require(isinstance(items, list) and 1 <= len(items) <= 5, 'One to five fixed synthetic pairs required')
    findings = report.get('findings')
    require(isinstance(findings, list) and len(findings) <= 1024 and all(isinstance(f, dict) and isinstance(f.get('id'), str) for f in findings),
            'Invalid report findings')
    by_id = {f['id']: f for f in findings}
    require(len(by_id) == len(findings), 'Duplicate finding IDs')
    payloads, labels = generate()
    pairs = []
    seen_findings, seen_pairs = set(), set()
    for item in items:
        require(isinstance(item, dict) and set(item) == {'finding_id', 'pair_id', 'case_id'}, 'Invalid binding shape')
        require(all(isinstance(v, str) and 0 < len(v) <= 128 and v.isascii() and v.isprintable() for v in item.values()), 'Invalid binding identity')
        require(item['finding_id'] not in seen_findings and item['pair_id'] not in seen_pairs, 'Duplicate finding or pair')
        selected = [x for x in labels if x['pair_id'] == item['pair_id'] and x['variant'] == 0]
        require(len(selected) == 2, 'Unknown fixed synthetic pair')
        vulnerable = next(x for x in selected if x['vulnerable'])
        require(item['case_id'] == vulnerable['id'], 'Binding must select the vulnerable canonical specimen')
        finding = by_id.get(item['finding_id'])
        require(finding is not None, 'Finding not in report')
        source = next(x for x in payloads if x['id'] == vulnerable['id'])
        require(finding.get('status') in ['candidate', 'needs_human'] and finding.get('file') == 'synthetic/' + source['id'] + '.py', 'Only explicitly named synthetic candidate findings can be linked')
        require(finding.get('file_hash') == source['source_sha256'], 'Finding requires the exact scanned source hash; missing hashes cannot be inferred')
        pairs.append({'binding': item, 'finding_status': finding['status'], 'labels': selected,
                      'payloads': [next(x for x in payloads if x['id'] == label['id']) for label in selected]})
        seen_findings.add(item['finding_id']); seen_pairs.add(item['pair_id'])
    return pairs


class CommandFailure(RuntimeError):
    def __init__(self, receipt):
        super().__init__('Command process control or bounded capture is incomplete')
        self.receipt = receipt


def load_runtime():
    """Load only the reviewed canonical bytes; no lookup or download fallback."""
    require(not RUNTIME_DIRECTORY.is_symlink(), 'Process runtime must be an ordinary directory')
    for name, expected in RUNTIME_PINS.items():
        path = RUNTIME_DIRECTORY / name
        require(path.is_file() and not path.is_symlink() and sha(read_file(path)) == expected,
                'Process runtime is missing or changed')
    spec = importlib.util.spec_from_file_location('link_capture_runtime_v2', RUNTIME_DIRECTORY / 'process_capture_v2.py')
    runtime = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(runtime)
    finally:
        sys.dont_write_bytecode = previous
    return runtime


def process_complete(run, runtime):
    """Observe nonzero exits without rewriting the actual invocation receipt."""
    if (isinstance(run, dict) and type(run.get('returncode')) is int
            and -255 <= run['returncode'] <= 255 and run['returncode'] != 0
            and run.get('error') == 'nonzero-exit'):
        return runtime.successful_run(dict(run, returncode=0, error=None))
    return runtime.successful_run(run)


def command(argv, timeout, byte_cap=COMMAND_BYTES):
    """Bound each captured stream; enforce the combined acceptance cap afterwards."""
    require(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= TOTAL_SECONDS,
            'Invalid command timeout')
    require(type(byte_cap) is int and 0 < byte_cap <= COMMAND_BYTES, 'Invalid command byte cap')
    require(os.name == 'posix', 'Process supervision requires POSIX')
    runtime = load_runtime()
    environment = {k: os.environ[k] for k in ('HOME', 'PATH', 'TMPDIR', 'LANG', 'LC_ALL') if k in os.environ}
    run = runtime.invoke(argv, Path(__file__).resolve().parent, environment, timeout,
                         stdout_cap=byte_cap, stderr_cap=byte_cap, timeout_ceiling_seconds=TOTAL_SECONDS)
    observed = sum(c.get('observed_bytes', 0) for c in run['captures'].values())
    limited = (run.get('error') == 'output-limit' or observed > byte_cap
               or any(c.get('truncated') is True for c in run['captures'].values()))
    receipt = {'argv': argv, 'timed_out': run['timed_out'], 'output_limited': limited,
               'returncode': run['returncode'], 'stdout': run['stdout'], 'stderr': run['stderr'],
               'wall_seconds': run['seconds'], 'process_contract': PROCESS_CONTRACT, 'process': run,
               'combined_acceptance_cap': byte_cap, 'per_stream_capture_cap': byte_cap}
    if limited or not process_complete(run, runtime):
        raise CommandFailure(receipt)
    return receipt


def container_name(payload, identity):
    return 'vettalon-link-' + identity[:32] + '-' + payload['id']


def create_argv(payload, label, identity, image, docker=('docker',)):
    return [*docker, 'create', '--name', container_name(payload, identity), '--pull', 'never', *sandbox_flags(), '--label', 'vettalon.link-run=' + identity,
            '--label', 'vettalon.link-case=' + payload['id'], image, 'python', '-I', '-B', '-c', harness(payload, label, identity)]


def validate_receipt(receipt, argv):
    require(isinstance(receipt, dict) and receipt.get('argv') == argv and receipt.get('timed_out') is False
            and receipt.get('output_limited') is False and type(receipt.get('returncode')) is int
            and receipt['returncode'] == 0, 'Command failed, timed out, overflowed, or argv mismatched')
    require(isinstance(receipt.get('stdout'), str) and isinstance(receipt.get('stderr'), str)
            and len((receipt['stdout'] + receipt['stderr']).encode()) <= COMMAND_BYTES, 'Invalid bounded raw output')
    wall = receipt.get('wall_seconds')
    require(type(wall) in [int, float] and math.isfinite(wall) and 0 <= wall <= 22, 'Invalid command timing')
    require(receipt.get('process_contract') == PROCESS_CONTRACT, 'Missing current process control contract')
    cap = receipt.get('combined_acceptance_cap')
    require(type(cap) is int and 0 < cap <= COMMAND_BYTES
            and type(receipt.get('per_stream_capture_cap')) is int
            and receipt['per_stream_capture_cap'] == cap, 'Invalid declared capture caps')
    run = receipt.get('process')
    require(load_runtime().successful_run(run), 'Incomplete process control or capture evidence')
    require(run['command'] == argv and type(run['returncode']) is type(receipt['returncode'])
            and run['returncode'] == receipt['returncode'] and run['stdout'] == receipt['stdout']
            and run['stderr'] == receipt['stderr'] and type(run['seconds']) is type(wall)
            and run['seconds'] == wall and len((run['stdout'] + run['stderr']).encode()) <= cap
            and all(c['cap_bytes'] == cap for c in run['captures'].values()),
            'Process receipt contradicts projected output, timing, command or caps')


def inspect_contract(info, payload, label, identity, image, cid, state):
    require(isinstance(info, dict) and info.get('Id') == cid and info.get('Image') == image
            and info.get('Name') == '/' + container_name(payload, identity), 'Container/image identity mismatch')
    config, host, observed = info.get('Config'), info.get('HostConfig'), info.get('State')
    require(all(isinstance(value, dict) for value in [config, host, observed])
            and isinstance(config.get('Labels'), dict), 'Malformed container inspect objects')
    require(config.get('Cmd') == ['python', '-I', '-B', '-c', harness(payload, label, identity)]
            and config.get('Labels', {}).get('vettalon.link-run') == identity
            and config.get('Labels', {}).get('vettalon.link-case') == payload['id']
            and config.get('Entrypoint') in [None, []], 'Executed harness or nonce mismatch')
    require(observed.get('Status') == state and observed.get('Running') is False
            and type(observed.get('ExitCode')) is int and observed['ExitCode'] == 0
            and observed.get('OOMKilled') is False and not observed.get('Error'), 'Container state/exit failure')
    require(host.get('NetworkMode') == 'none' and host.get('ReadonlyRootfs') is True
            and host.get('CapDrop') == ['ALL'] and host.get('Privileged') is False
            and config.get('User') == '65534:65534' and info.get('Mounts') == []
            and host.get('Binds') in [None, []] and host.get('Devices') in [None, []]
            and host.get('Memory') == 134217728 and host.get('NanoCpus') == 500000000
            and host.get('PidsLimit') == 32 and host.get('SecurityOpt') == ['no-new-privileges']
            and host.get('Tmpfs') == {'/tmp': 'rw,noexec,nosuid,nodev,size=8m,mode=1777'}, 'Sandbox contract mismatch')


def validate_execution(row, payload, label, identity, image, seen, docker=('docker',)):
    require(isinstance(identity, str) and HEX.fullmatch(identity) and row.get('run_identity') == identity, 'Fresh launch nonce mismatch')
    require(row.get('case_id') == payload['id'] and row.get('source_sha256') == payload['source_sha256']
            and row.get('harness_sha256') == digest(harness(payload, label, identity)), 'Source/harness mismatch')
    cid = row.get('container_id')
    require(isinstance(cid, str) and HEX.fullmatch(cid) and cid not in seen, 'Invalid or reused container')
    require(re.fullmatch(r'sha256:[0-9a-f]{64}', image) is not None, 'Invalid pinned image')
    commands = row.get('commands', {})
    expected = {'create': create_argv(payload, label, identity, image, docker), 'created_inspect': [*docker, 'inspect', cid],
                'start': [*docker, 'start', '-a', cid], 'inspect': [*docker, 'inspect', cid], 'cleanup': [*docker, 'rm', '-f', cid]}
    require(set(commands) == set(expected), 'Missing execution/control/cleanup receipts')
    for phase, argv in expected.items():
        validate_receipt(commands[phase], argv)
    require(commands['create']['stdout'].strip() == cid and commands['cleanup']['stdout'].strip() == cid, 'Creation/cleanup identity mismatch')
    for phase, state in [('created_inspect', 'created'), ('inspect', 'exited')]:
        raw = json_data(commands[phase]['stdout'])
        require(isinstance(raw, list) and len(raw) == 1 and raw[0] == row.get(phase), 'Raw inspect contradicts summary')
        inspect_contract(raw[0], payload, label, identity, image, cid, state)
    observed = json_data(commands['start']['stdout'])
    require(observed == row.get('observed') and isinstance(observed, dict), 'Raw stdout contradicts observed summary')
    require(observed.get('run_identity') == identity and observed.get('case_id') == payload['id']
            and observed.get('source_sha256') == payload['source_sha256'] and type(observed.get('uid')) is int and observed['uid'] == 65534
            and observed.get('normal_control') is True and type(observed.get('security_effect')) is bool
            and observed['security_effect'] is label['vulnerable']
            and observed.get('state') == 'synthetic-only' and observed.get('principal') == 'alice-or-viewer'
            and observed.get('object') == 'dummy-record' and observed.get('operation') == 'read-or-write', 'Synthetic effect/control/nonce mismatch')
    seen.add(cid)


def execute(payload, label, identity, image, deadline, docker=('docker',)):
    row = {'case_id': payload['id'], 'source_sha256': payload['source_sha256'], 'harness_sha256': digest(harness(payload, label, identity)),
           'run_identity': identity, 'commands': {}}
    cid = None
    def invoke(phase, argv, seconds):
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'Run deadline exhausted')
        try:
            result = command(argv, min(seconds, remaining))
        except CommandFailure as exc:
            row['commands'][phase] = exc.receipt
            raise
        except OSError as exc:
            row['commands'][phase] = {'argv': argv, 'launch_error': str(exc)[:512]}
            raise
        row['commands'][phase] = result
        require(result['returncode'] == 0, 'Docker command failed: ' + phase)
        return result
    try:
        raw = invoke('create', create_argv(payload, label, identity, image, docker), 15)
        cid = raw['stdout'].strip()
        require(HEX.fullmatch(cid), 'Invalid created container ID')
        row['container_id'] = cid
        row['created_inspect'] = json_data(invoke('created_inspect', [*docker, 'inspect', cid], 10)['stdout'])[0]
        inspect_contract(row['created_inspect'], payload, label, identity, image, cid, 'created')
        started = invoke('start', [*docker, 'start', '-a', cid], 20)
        row['observed'] = json_data(started['stdout'])
        row['inspect'] = json_data(invoke('inspect', [*docker, 'inspect', cid], 10)['stdout'])[0]
    except (OSError, ValueError, KeyError, IndexError, TypeError, RuntimeError) as exc:
        row['execution_error'] = type(exc).__name__ + ': ' + str(exc)[:512]
    finally:
        if row['commands']:
            cleanup_target = cid if cid and HEX.fullmatch(cid) else container_name(payload, identity)
            try:
                # Cleanup receives its own bounded allowance even if the run deadline expired.
                row['commands']['cleanup'] = command([*docker, 'rm', '-f', cleanup_target], 15)
            except CommandFailure as exc:
                row['commands']['cleanup'] = exc.receipt
            except (OSError, ValueError) as exc:
                row['cleanup_error'] = type(exc).__name__ + ': ' + str(exc)[:512]
    return row


def write_bundle(output, pair, rows, identity, raw_hash):
    binding = pair['binding']
    folder = output / binding['case_id']
    mkdir_new(folder)
    artifacts = []
    for label, payload in zip(pair['labels'], pair['payloads']):
        prefix = 'vulnerable' if label['vulnerable'] else 'patched'
        row = next(r for r in rows if r['case_id'] == label['id'])
        for role, data in [(prefix + '_source', payload['source'].encode()), (prefix + '_execution', row)]:
            name = role + ('.py' if role.endswith('source') else '.json')
            content = write_new(folder / name, data)
            artifacts.append({'role': role, 'path': name, 'sha256': sha(content), 'bytes': len(content)})
    control = {'schema': SCHEMA, 'kind': 'synthetic-normal-control', 'run_identity': identity, 'pair_id': binding['pair_id'],
               'finding_id': binding['finding_id'], 'raw_batch_sha256': raw_hash,
               'specimens': [{'case_id': r['case_id'], 'container_id': r['container_id'], 'normal_control': r['observed']['normal_control']} for r in rows]}
    data = write_new(folder / 'normal_control.json', control)
    artifacts.append({'role': 'normal_control', 'path': 'normal_control.json', 'sha256': sha(data), 'bytes': len(data)})
    manifest = {'schema': 'vettalon-evidence-v1', 'finding_id': binding['finding_id'], 'level': 'differential_oracle',
                'run_id': identity, 'pair_id': binding['pair_id'], 'artifacts': artifacts, 'human_decision': None}
    write_new(folder / 'manifest.json', manifest)
    return manifest



def local_docker(socket_path):
    # Socket symlinks are explicitly selected and resolved, unlike source/artifact inputs.
    requested = Path(os.path.abspath(socket_path))
    canonical = requested.resolve(strict=True)
    info = canonical.stat()
    requested_info = requested.lstat()
    require(stat.S_ISSOCK(info.st_mode), 'Docker endpoint must be an existing local Unix socket')
    require(info.st_uid in [0, os.getuid()], 'Docker socket owner must be this user or root')
    return ['docker', '--host', 'unix://' + str(canonical)], {
        'requested': str(requested), 'canonical': str(canonical), 'device': info.st_dev,
        'inode': info.st_ino, 'uid': info.st_uid, 'mode': info.st_mode,
        'requested_entry': {'device': requested_info.st_dev, 'inode': requested_info.st_ino,
                            'mode': requested_info.st_mode, 'mtime_ns': requested_info.st_mtime_ns,
                            'ctime_ns': requested_info.st_ctime_ns},
        'requested_link_target': os.readlink(requested) if requested.is_symlink() else None}


def launch(report_path, bindings_path, output, validator, docker_socket, image='python:3.12-slim'):
    docker, socket_identity = local_docker(docker_socket)
    report_data, bindings_data = read_file(report_path), read_file(bindings_path, 32768)
    report = json_data(report_data)
    pairs = bind_pairs(report, json_data(bindings_data))
    require(isinstance(report.get('repo'), str) and Path(report['repo']).is_absolute(), 'Synthetic report repo must be absolute')
    source_root = safe_path(report['repo'])
    sources = {}
    for pair in pairs:
        payload = next(p for p, label in zip(pair['payloads'], pair['labels']) if label['vulnerable'])
        source_path = source_root / ('synthetic/' + payload['id'] + '.py')
        content = read_file(source_path, 4096)
        require(content == payload['source'].encode() and sha(content) == payload['source_sha256'], 'Current synthetic source differs from scanned file hash')
        sources[str(source_path)] = sha(content)
    output = safe_path(output)
    require(output.parent.is_dir(), 'Output parent must already exist')
    mkdir_new(output)  # Never reuse even an empty directory.
    identity = secrets.token_hex(32)
    deadline = time.monotonic() + TOTAL_SECONDS
    load_runtime()  # Reject changed helper bytes before any validator or Docker child.
    implementation = {str(path.relative_to(Path(__file__).resolve().parents[2])): sha(read_file(path))
                      for path in [Path(__file__).resolve(), Path(__file__).resolve().parents[1] / 'blind-twins/protocol.py',
                                   *(RUNTIME_DIRECTORY / name for name in RUNTIME_PINS)]}
    context = {'schema': SCHEMA, 'run_identity': identity, 'report_sha256': sha(report_data), 'bindings_sha256': sha(bindings_data),
               'implementation_sha256': implementation, 'source_sha256': sources, 'planned_containers': 2 * len(pairs), 'maximum_containers': 10,
               'real_model_calls': 0, 'container_network': 'none', 'host_control_plane': 'explicit_local_unix_socket',
               'host_os_deny_egress': 'not_established', 'docker_socket': socket_identity, 'image_requested': image, 'total_seconds_limit': TOTAL_SECONDS,
               'process_capture_contract': PROCESS_CONTRACT, 'process_cleanup_extra_seconds': 1,
               'combined_output_acceptance_bytes': COMMAND_BYTES, 'per_stream_capture_bytes': COMMAND_BYTES}
    write_new(output / 'launch.json', context)
    rows, manifests = [], []
    result = {'schema': SCHEMA, 'run_identity': identity, 'status': 'incomplete', 'finding_status_changed': False,
              'origin': 'operator_supplied', 'human_decision': None, 'manifests': manifests,
              'limitations': 'Self-owned fixed synthetic contract only; local unsigned operator-supplied receipts. No trusted attestation, arbitrary-target semantics, scanner discovery, model PoC, or human confirmation.'}
    preflight_phase = 'report-validation'
    try:
        validator = safe_path(validator)
        require(validator.is_file() and os.access(validator, os.X_OK), 'Validator must be an explicit local executable')
        write_new(output / 'report-input.json', report_data)
        validation = command([str(validator), 'validate', str(output / 'report-input.json')], 15)
        write_new(output / 'report-validation.json', validation)
        validate_receipt(validation, [str(validator), 'validate', str(output / 'report-input.json')])
        require(isinstance(image, str) and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._:/@-]{0,191}', image), 'Invalid local image reference')
        preflight_phase = 'image-inspect'
        image_receipt = command([*docker, 'image', 'inspect', image], 10)
        write_new(output / 'image-inspect.json', image_receipt)
        validate_receipt(image_receipt, [*docker, 'image', 'inspect', image])
        images = json_data(image_receipt['stdout'])
        require(isinstance(images, list) and len(images) == 1, 'Image inspect shape mismatch')
        require(isinstance(images[0], dict), 'Malformed image inspect object')
        image_id = images[0].get('Id')
        require(isinstance(image_id, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', image_id), 'Missing pinned local image')
        seen = set()
        for pair in pairs:
            for payload, label in zip(pair['payloads'], pair['labels']):
                row = execute(payload, label, identity, image_id, deadline, docker)
                rows.append(row)
                write_new(output / ('raw-' + payload['id'] + '.json'), row)
                validate_execution(row, payload, label, identity, image_id, seen, docker)
        raw = write_new(output / 'batch.json', {'schema': SCHEMA, 'run_identity': identity, 'image_id': image_id, 'rows': rows})
        require(read_file(report_path) == report_data and read_file(bindings_path, 32768) == bindings_data, 'Input changed during execution')
        require(local_docker(docker_socket) == (docker, socket_identity), 'Docker socket identity changed')
        for source_path, expected in sources.items():
            require(sha(read_file(Path(source_path), 4096)) == expected, 'Synthetic source changed during execution')
        require(read_file(output / 'report-input.json') == report_data, 'Validated input snapshot changed')
        for relative, expected in implementation.items():
            require(sha(read_file(Path(__file__).resolve().parents[2] / relative)) == expected, 'Runner implementation changed during execution')
        for row in rows:
            require(json_data(read_file(output / ('raw-' + row['case_id'] + '.json'))) == row, 'Persisted raw execution changed')
        for pair in pairs:
            pair_rows = [r for r in rows if r['case_id'] in {p['id'] for p in pair['payloads']}]
            write_bundle(output, pair, pair_rows, identity, sha(raw))
            manifests.append({'finding_id': pair['binding']['finding_id'], 'path': pair['binding']['case_id'] + '/manifest.json',
                              'artifact_root': pair['binding']['case_id'], 'finding_status': pair['finding_status']})
        result.update(status='synthetic_contract_matched', image_id=image_id, containers=len(rows), batch_sha256=sha(raw))
    except (OSError, ValueError, KeyError, IndexError, TypeError, RuntimeError) as exc:
        if isinstance(exc, CommandFailure):
            write_new(output / (preflight_phase + '-failure.json'), exc.receipt)
        result['error'] = type(exc).__name__ + ': ' + str(exc)[:1024]
        result['containers_attempted'] = len(rows)
    write_new(output / 'checks.json', result)
    return result


def make_fixture(output):
    """Construct declared synthetic candidates, never pretend they were scanned."""
    output = safe_path(output)
    require(output.parent.is_dir(), 'Fixture parent must exist')
    mkdir_new(output)
    mkdir_new(output / 'synthetic')
    payloads, labels = generate()
    findings, bindings = [], []
    for label in labels:
        if label['variant'] != 0 or not label['vulnerable']:
            continue
        payload = next(p for p in payloads if p['id'] == label['id'])
        file = 'synthetic/' + payload['id'] + '.py'
        rule = 'synthetic/' + label['family']
        snippet = payload['source'][:1000]
        finding_id = 'synthetic_fixture-' + sha(('synthetic_fixture\0' + rule + '\0' + file + '\0' + '1' + '\0' + snippet).encode())[:16]
        findings.append({'id': finding_id, 'source_engine': 'synthetic_fixture', 'kind': 'static_analysis',
                         'severity': 'high', 'title': 'Synthetic fixture only: ' + label['family'], 'file': file,
                         'line': 1, 'snippet': snippet, 'rule_id': rule, 'evidence': [], 'proof_evidence': [],
                         'status': 'candidate', 'root_fingerprint': 'synthetic-fixture@' + payload['source_sha256'][:16],
                         'file_hash': payload['source_sha256'], 'severity_basis': 'scanner_rule'})
        bindings.append({'finding_id': finding_id, 'pair_id': label['pair_id'], 'case_id': label['id']})
        write_new(output / file, payload['source'].encode())
    report = {'schema_version': 2, 'repo': str(output), 'started_at': '2026-10-16T00:00:00Z',
              'profile': {'mode': 'quick'}, 'engines_run': [], 'engines_missing': [], 'findings': findings,
              'summary': {'total_findings': 5, 'by_severity': {'critical': 0, 'high': 5, 'medium': 0, 'low': 0, 'info': 0},
                          'engines_run_count': 0, 'engines_missing_count': 0},
              'run_status': 'incomplete', 'incomplete_reason': 'scope_not_fully_reviewed'}
    write_new(output / 'report.json', report)
    write_new(output / 'bindings.json', {'schema': SCHEMA, 'items': bindings})
    write_new(output / 'fixture-notice.json', {'schema': SCHEMA, 'synthetic': True, 'real_scanner_runs': 0,
                                             'real_model_calls': 0, 'purpose': 'Declared candidates for runner linkage; not discovered vulnerabilities'})
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest='action', required=True)
    fixture = subs.add_parser('fixture', help='Create explicitly synthetic report, sources and bindings')
    fixture.add_argument('--output', type=Path, required=True)
    run = subs.add_parser('run', help='Fresh synthetic execution; cannot import historical receipts')
    run.add_argument('--report', type=Path, required=True)
    run.add_argument('--bindings', type=Path, required=True)
    run.add_argument('--output', type=Path, required=True)
    run.add_argument('--vettalon', type=Path, required=True, help='Explicit trusted local product validator executable')
    run.add_argument('--docker-socket', type=Path, required=True, help='Explicit existing local Unix socket; remote contexts refused')
    run.add_argument('--image', default='python:3.12-slim')
    args = parser.parse_args()
    if args.action == 'fixture':
        make_fixture(args.output)
        print(json.dumps({'synthetic': True, 'findings': 5, 'real_model_calls': 0}))
        return 0
    result = launch(args.report, args.bindings, args.output, args.vettalon, args.docker_socket, args.image)
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result['status'] == 'synthetic_contract_matched' else 1


if __name__ == '__main__':
    sys.exit(main())
