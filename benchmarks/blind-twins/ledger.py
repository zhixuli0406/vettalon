"""Pure D01 schedule and read-only reconciliation; never dispatches a provider."""
import hashlib
import importlib.util
import json
import math
import os
import re
import stat
from pathlib import Path

from protocol import digest, fixed_subset, generate, select_scope

ARMS = ('finder-only', 'samefamily', 'crossfamily')
REPEATS = range(5)
OUTPUT_TOKENS = 1024
MAX_CALLS = 250
MAX_RESERVED_TOKENS = 256000
IDENTITY_SOURCE_FILE_CAP = 64 * 1024
RUN_ROOT = Path(__file__).resolve().parents[2] / 'reports/evidence-acceptance/formal-runs-v1'


def _canonical_budget_path(plan):
    """Ask the actual formal writer for its single ledger identity."""
    source = Path(__file__).resolve().parent.parent / 'formal-transport/transport_v1.py'
    spec = importlib.util.spec_from_file_location('twins_canonical_formal_transport', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.canonical_budget_path(plan)


def _open_directory(path):
    path = Path(path)
    if not path.is_absolute() or any(part in ('.', '..') for part in path.parts):
        raise ValueError('Absolute ordinary path without traversal required')
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            next_descriptor = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                      dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError as error:
        os.close(descriptor)
        raise ValueError('Cannot open directory without following symlinks') from error


def read_regular(path, cap):
    """Read bounded bytes through nofollow descriptors for every path component."""
    path = Path(path)
    if not path.is_absolute() or any(part in ('.', '..') for part in path.parts) or path.name in ('', '/'):
        raise ValueError('Absolute ordinary file path without traversal required')
    descriptor = _open_directory(path.parent)
    try:
        file_descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                  dir_fd=descriptor)
        try:
            before = os.fstat(file_descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size > cap:
                raise ValueError('Bounded regular file required')
            chunks = []
            remaining = cap + 1
            while remaining:
                part = os.read(file_descriptor, min(65536, remaining))
                if not part: break
                chunks.append(part); remaining -= len(part)
            data = b''.join(chunks)
            after = os.fstat(file_descriptor)
            if (len(data) > cap or before.st_ino != after.st_ino
                    or before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns):
                raise ValueError('File changed or exceeded byte cap while reading')
            return data
        finally:
            os.close(file_descriptor)
    except OSError as error:
        raise ValueError('Cannot read ordinary file without following symlinks') from error
    finally:
        os.close(descriptor)


def _json_file(path, cap):
    return json.loads(read_regular(path, cap))


def schedule(scope=None, identity_view='anonymous'):
    """Materialize the one authorized anonymous five-pair, three-arm roster."""
    if identity_view != 'anonymous':
        raise ValueError('The D01 budget does not authorize a second identity view')
    frozen = fixed_subset()
    if scope is None:
        scope = frozen
    if scope != frozen:
        raise ValueError('Formal D01 must use the exact frozen five-pair scope')
    payloads, labels = select_scope(*generate(), scope)
    pairs = {label['pair_id'] for label in labels}
    if (len(payloads) != 10 or len(pairs) != 5
            or any(sum(label['pair_id'] == pair for label in labels) != 2 for pair in pairs)
            or sum(label['vulnerable'] for label in labels) != 5):
        raise ValueError('The fixed five-pair denominator is incomplete')
    slots = []
    for arm in ARMS:
        for repeat in REPEATS:
            for payload in payloads:
                for stage in (('finder',) if arm == 'finder-only' else ('finder', 'verifier')):
                    role = 'finder' if stage == 'finder' else arm + '_verifier'
                    slots.append({'arm': arm, 'repeat': repeat, 'case_id': payload['id'],
                                  'source_sha256': payload['source_sha256'], 'stage': stage,
                                  'role': role, 'attempt_key': f"{arm}|{repeat}|{payload['id']}|{stage}"})
    if len(slots) != MAX_CALLS or len({x['attempt_key'] for x in slots}) != MAX_CALLS:
        raise ValueError('Formal schedule does not fit the fixed call budget')
    return {'schema': 'twins-formal-schedule-v1', 'scope_sha256': digest(scope),
            'identity_view': identity_view, 'rows_per_run': len(payloads),
            'runs': len(ARMS) * len(REPEATS), 'calls_by_arm': {
                arm: sum(x['arm'] == arm for x in slots) for arm in ARMS},
            'requested_calls': len(slots), 'requested_output_tokens_per_call': OUTPUT_TOKENS,
            'reserved_output_tokens_ceiling': len(slots) * OUTPUT_TOKENS,
            'inflight': 1, 'automatic_retries': 0, 'slots': slots}


def validate_plan(plan, planned):
    """Refuse a plan that would silently enlarge or fork the shared D01 budget."""
    expected = {'max_calls': MAX_CALLS, 'max_output_tokens': OUTPUT_TOKENS,
                'max_total_output_tokens': MAX_RESERVED_TOKENS,
                'inflight': 1, 'automatic_retries': 0,
                'purpose': 'd01-anonymous-fixed-five-pair-v1',
                'experiment': 'twins', 'scope_sha256': planned['scope_sha256']}
    if type(plan) is not dict or any(plan.get(key) != value for key, value in expected.items()):
        raise ValueError('Plan differs from the fixed shared D01 ceiling and scope')
    if planned['requested_calls'] != MAX_CALLS or planned['reserved_output_tokens_ceiling'] != MAX_RESERVED_TOKENS:
        raise ValueError('Schedule exceeds the fixed D01 ceiling')
    return True


def reconcile_debits(plan, planned, ledger_path, attempts, *, run_root=RUN_ROOT):
    """Bind started, request, dispatch-entry, and attempt artifact bytes to one D01 plan."""
    validate_plan(plan, planned)
    path = Path(ledger_path)
    run_root = Path(run_root)
    if not path.is_absolute() or not run_root.is_absolute():
        raise ValueError('Absolute ledger and run roots required')
    canonical = _canonical_budget_path(plan)
    if path != canonical:
        raise ValueError('Ledger path is not the formal writer canonical budget path')
    for directory in (path, path / 'debits'):
        descriptor = _open_directory(directory)
        os.close(descriptor)
    if _json_file(path / 'batch.json', 65536) != plan:
        raise ValueError('Persisted canonical batch differs from the requested plan')
    expected_slots = {slot['attempt_key']: slot for slot in planned['slots']}
    case_indexes = {case_id: number for number, case_id in enumerate(fixed_subset()['case_ids'])}
    descriptor = _open_directory(path / 'debits')
    try:
        names = set()
        with os.scandir(descriptor) as entries:
            for entry in entries:
                names.add(entry.name)
                if len(names) > 2 * MAX_CALLS:
                    raise ValueError('Debit directory entry count exceeds the fixed ceiling')
    finally:
        os.close(descriptor)
    started_names = sorted(name for name in names if re.fullmatch(r'[0-9]{4}\.started\.json', name))
    entry_names = {name for name in names if re.fullmatch(r'[0-9]{4}\.dispatch-entry\.json', name)}
    if names != set(started_names) | entry_names or len(started_names) > MAX_CALLS:
        raise ValueError('Unknown, malformed, or excessive debit directory entries')
    if started_names:
        descriptor = _open_directory(run_root)
        os.close(descriptor)
    plan_sha = hashlib.sha256(json.dumps(plan, sort_keys=True, ensure_ascii=False,
                                         separators=(',', ':'), allow_nan=False).encode()).hexdigest()
    by_key = {}
    for number, name in enumerate(started_names, 1):
        if name != f'{number:04d}.started.json':
            raise ValueError('Debit slots must be contiguous and numbered')
        data = read_regular(path / 'debits' / name, 65536)
        record = json.loads(data)
        if type(record) is not dict:
            raise ValueError('Debit entry must be an object')
        key = record.get('attempt_key')
        detail = record.get('detail')
        if (set(record) != {'schema', 'slot', 'attempt_key', 'purpose', 'plan_sha256',
                           'reserved_output_tokens', 'detail'}
                or record['schema'] != 'formal-debit-v1' or type(record['slot']) is not int
                or record['slot'] != number or key not in expected_slots or key in by_key
                or record['purpose'] != plan['purpose'] or record['plan_sha256'] != plan_sha
                or type(record['reserved_output_tokens']) is not int
                or record['reserved_output_tokens'] != OUTPUT_TOKENS):
            raise ValueError('Debit record disagrees with the fixed schedule')
        slot = expected_slots[key]
        if (type(detail) is not dict or set(detail) != {
                'prompt_sha256', 'parent_sha256', 'role', 'request_sha256',
                'attempt_dir', 'timeout_seconds', 'deadline_monotonic'}
                or detail['role'] != slot['role']
                or not all(type(detail[field]) is str and re.fullmatch(r'[0-9a-f]{64}', detail[field])
                           for field in ('prompt_sha256', 'request_sha256'))
                or (detail['parent_sha256'] is not None
                    and (type(detail['parent_sha256']) is not str
                         or not re.fullmatch(r'[0-9a-f]{64}', detail['parent_sha256'])))
                or type(detail['attempt_dir']) is not str
                or type(detail['timeout_seconds']) not in (int, float)
                or not math.isfinite(detail['timeout_seconds'])
                or not 0 < detail['timeout_seconds'] <= plan['per_call_seconds']
                or type(detail['deadline_monotonic']) not in (int, float)
                or not math.isfinite(detail['deadline_monotonic'])):
            raise ValueError('Started debit has malformed or wrong-role request binding')
        attempt_dir = Path(detail['attempt_dir'])
        expected_name = f"{case_indexes[slot['case_id']]:03d}-{slot['stage']}"
        if (not attempt_dir.is_absolute() or attempt_dir.name != expected_name
                or attempt_dir.parent.parent != run_root
                or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', attempt_dir.parent.name)):
            raise ValueError('Attempt directory is outside the fixed formal run layout')
        request_bytes = read_regular(attempt_dir / 'request.json', 1024 * 1024)
        if hashlib.sha256(request_bytes).hexdigest() != detail['request_sha256']:
            raise ValueError('Started debit does not bind actual request bytes')
        request = json.loads(request_bytes)
        if (type(request) is not dict
                or set(request) != {'model', 'prompt', 'timeout_seconds', 'max_output_tokens'}
                or request['model'] != plan['models'][slot['role']]['name']
                or type(request['prompt']) is not str or not request['prompt']
                or hashlib.sha256(request['prompt'].encode()).hexdigest() != detail['prompt_sha256']
                or type(request['max_output_tokens']) is not int or request['max_output_tokens'] != OUTPUT_TOKENS
                or type(request['timeout_seconds']) not in (int, float)
                or request['timeout_seconds'] != detail['timeout_seconds']):
            raise ValueError('Request model, prompt, and cap do not match the durable debit')
        started_sha = hashlib.sha256(data).hexdigest()
        entry_name = f'{number:04d}.dispatch-entry.json'
        dispatch_entered = entry_name in entry_names
        if dispatch_entered:
            entry = _json_file(path / 'debits' / entry_name, 65536)
            if (type(entry) is not dict or set(entry) != {
                    'started_sha256', 'request_sha256', 'request_receipt_semantics'}
                    or entry['started_sha256'] != started_sha
                    or entry['request_sha256'] != detail['request_sha256']
                    or entry['request_receipt_semantics'] != 'single-use admission; bytes received by server unknown'):
                raise ValueError('Dispatch-entry is not bound to the same started request')
        by_key[key] = {'started_sha256': started_sha, 'detail': detail,
                       'attempt_dir': attempt_dir, 'request': request,
                       'dispatch_entered': dispatch_entered}
    if len(entry_names) != sum(row['dispatch_entered'] for row in by_key.values()):
        raise ValueError('Orphan dispatch-entry without a started slot')
    seen = set()
    for attempt in attempts:
        if type(attempt) is not dict:
            raise ValueError('Raw attempt object required')
        key = attempt.get('attempt_key')
        binding = by_key.get(key)
        if (key in seen or binding is None
                or attempt.get('started_sha256') != binding['started_sha256']
                or attempt.get('prompt_sha256') != binding['detail']['prompt_sha256']
                or attempt.get('parent_sha256') != binding['detail']['parent_sha256']
                or attempt.get('prompt') != binding['request']['prompt']
                or attempt.get('model') != binding['request']['model']):
            raise ValueError('Raw attempt is missing, duplicated, or unbound from its durable request')
        reference = attempt.get('attempt_artifact')
        artifact_path = binding['attempt_dir'] / 'attempt.json'
        if (type(reference) is not dict or set(reference) != {'path', 'sha256'}
                or reference['path'] != str(artifact_path)
                or type(reference['sha256']) is not str
                or not re.fullmatch(r'[0-9a-f]{64}', reference['sha256'])):
            raise ValueError('Raw attempt artifact was moved outside its debited request directory')
        artifact_bytes = read_regular(artifact_path, 4 * 1024 * 1024)
        if hashlib.sha256(artifact_bytes).hexdigest() != reference['sha256']:
            raise ValueError('Raw attempt artifact bytes changed')
        if attempt.get('client_request_entries') == 1 and not binding['dispatch_entered']:
            raise ValueError('Observed client request entry lacks its durable dispatch-entry')
        seen.add(key)
    unreported = sorted(set(by_key) - seen)
    return {'schema': 'twins-formal-ledger-audit-v1', 'requested_calls': MAX_CALLS,
            'recorded_debits': len(by_key), 'recorded_dispatch_entries': len(entry_names),
            'recorded_reserved_output_tokens': len(by_key) * OUTPUT_TOKENS,
            'raw_attempts_bound': len(seen), 'debits_without_raw_attempt': len(unreported),
            'unreported_attempt_keys': unreported, 'reconciled': not unreported}
