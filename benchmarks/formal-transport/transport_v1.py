"""Opt-in client admission and accounting. No production backend is armed."""
import base64
import hashlib
import http.client
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import sys
import time

REPO = Path(__file__).resolve().parents[2]
BUDGET_ROOT = REPO / 'reports/evidence-acceptance/formal-budget-ledger-v1'
RUN_ROOT = REPO / 'reports/evidence-acceptance/formal-runs-v1'
RUNTIME = REPO / 'scripts/runtime/process_capture_v2.py'
RUNTIME_SHA256 = '571d9b28da1c843f2a9e43fd8af1a924e6ec04c623d505b2cf8b9f2afc016132'
SUPERVISOR_SHA256 = '0d58c2d5315e8ac48e8d8cf66d4796cf8fc1c83e073276e225879777761d9c36'
RESPONSE_CAP = 1024 * 1024
PLAN_KEYS = {'schema', 'purpose', 'experiment', 'backend', 'models', 'scope_sha256', 'task_sha256',
             'source_bindings', 'max_calls', 'max_output_tokens', 'max_total_output_tokens',
             'per_call_seconds', 'per_run_seconds', 'input_token_cap', 'inflight', 'automatic_retries'}


class CapabilityError(ValueError):
    pass


class BudgetError(ValueError):
    pass


def digest(value):
    data = value if isinstance(value, bytes) else value.encode('utf-8') if isinstance(value, str) else json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def _hash(value):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def validate_plan(plan):
    if type(plan) is not dict or set(plan) != PLAN_KEYS or plan['schema'] != 'formal-budget-v1':
        raise ValueError('Exact formal budget fields required')
    if (plan['experiment'] not in ('twins', 'context', 'rag')
            or plan['backend'] not in ('local-ollama-http-v1', 'grok-cli')
            or type(plan['purpose']) is not str or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,95}', plan['purpose'])
            or not _hash(plan['scope_sha256']) or not _hash(plan['task_sha256'])
            or type(plan['source_bindings']) is not dict or not plan['source_bindings']
            or not all(type(k) is str and _hash(v) for k, v in plan['source_bindings'].items())):
        raise ValueError('Invalid scope, purpose, backend, or implementation binding')
    for key, maximum in [('max_calls', 250), ('max_total_output_tokens', 256000)]:
        if type(plan[key]) is not int or not 1 <= plan[key] <= maximum:
            raise ValueError('Budget outside fixed ceilings')
    for key, maximum in [('per_call_seconds', 90), ('per_run_seconds', 1200)]:
        if type(plan[key]) not in (int, float) or not math.isfinite(plan[key]) or not 0 < plan[key] <= maximum:
            raise ValueError('Invalid execution limit')
    if (type(plan['max_output_tokens']) is not int or plan['max_output_tokens'] != 1024
            or type(plan['inflight']) is not int or plan['inflight'] != 1
            or type(plan['automatic_retries']) is not int or plan['automatic_retries'] != 0):
        raise ValueError('Exactly 1024 reserved tokens, one worker, and zero retries required')
    cap = plan['input_token_cap']
    if cap is not None and (type(cap) is not int or not 0 < cap <= 1048576):
        raise ValueError('Invalid input token cap')
    models = plan['models']
    if type(models) is not dict or not models or set(models) - {'finder', 'samefamily_verifier', 'crossfamily_verifier'} or 'finder' not in models:
        raise ValueError('Explicit finder model required')
    for model in models.values():
        if (type(model) is not dict or set(model) != {'name', 'digest', 'family'}
                or type(model['name']) is not str or not model['name'].strip() or len(model['name']) > 256
                or not _hash(model['digest']) or type(model['family']) is not str or not model['family'].strip()):
            raise ValueError('Explicit declared model, digest and family required')
    return True


def _validated_controls(backend, model_name):
    # No reviewed exact installed provider/model control binding exists yet.
    # Official API docs and requested flags must not arm this registry.
    return None


def _count_input_tokens(model, prompt):
    # No verified matching local tokenizer is bundled or acquired.
    return None


def ensure_ready(plan, prompt, role):
    validate_plan(plan)
    if type(prompt) is not str or not prompt or role not in plan['models']:
        raise ValueError('Explicit nonempty prompt and declared role required')
    model = plan['models'][role]
    controls = _validated_controls(plan['backend'], model['name'])
    if (plan['backend'] != 'local-ollama-http-v1' or type(controls) is not dict
            or type(controls.get('effective_output_tokens')) is not int or controls['effective_output_tokens'] != 1024
            or type(controls.get('client_visible_requests_per_worker')) is not int or controls['client_visible_requests_per_worker'] != 1
            or type(controls.get('automatic_retries')) is not int or controls['automatic_retries'] != 0
            or controls.get('model_name') != model['name'] or controls.get('model_digest') != model['digest']
            or not isinstance(controls.get('evidence'), str) or not controls['evidence']):
        raise CapabilityError('Exact provider controls unknown; formal dispatch disabled')
    tokens = None
    if plan['experiment'] != 'twins' or plan['input_token_cap'] is not None:
        tokens = _count_input_tokens(plan['models'][role], prompt)
        if type(tokens) is not int or tokens < 0 or plan['input_token_cap'] is None:
            raise CapabilityError('Input-token control unavailable; bytes are not tokens')
        if tokens > plan['input_token_cap']:
            raise BudgetError('Input token cap exceeded before dispatch')
    return {'provider_controls': controls, 'input_tokens_preflight': tokens}


def _fsync_directory(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def mkdir_durable(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('Symlink directory refused')
    if path.exists():
        if not path.is_dir(): raise ValueError('Directory required')
        return
    if not path.parent.exists(): mkdir_durable(path.parent)
    path.mkdir()
    _fsync_directory(path)
    _fsync_directory(path.parent)


def write_new(path, value):
    data = value if isinstance(value, bytes) else (json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False) + '\n').encode()
    with Path(path).open('xb') as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    _fsync_directory(Path(path).parent)
    return digest(data)


def read_bytes(path, cap=4 * 1024 * 1024):
    path = Path(path)
    if path.is_symlink() or not path.is_file(): raise ValueError('Regular owned JSON file required')
    with path.open('rb') as handle: data = handle.read(cap + 1)
    if len(data) > cap: raise ValueError('JSON file byte cap exceeded')
    return data


def read_json(path, cap=4 * 1024 * 1024):
    return json.loads(read_bytes(path, cap).decode('utf-8', 'strict'))


def canonical_budget_path(plan):
    validate_plan(plan)
    return BUDGET_ROOT / plan['purpose']


class Ledger:
    """Cooperative single-writer bookkeeping, not rollback-resistant attestation."""
    def __init__(self, path, plan):
        validate_plan(plan)
        self.path = Path(path).resolve()
        self.plan = json.loads(json.dumps(plan)); self.plan_sha256 = digest(plan)
        self.halted = False
        mkdir_durable(self.path)
        write_new(self.path / '.owner', {'pid': os.getpid(), 'plan_sha256': self.plan_sha256})
        if (self.path / 'halted.json').exists(): raise BudgetError('Ledger halted; no automatic recovery')
        batch = self.path / 'batch.json'
        if batch.exists():
            if read_json(batch) != self.plan: raise ValueError('Existing canonical budget plan changed')
        else:
            if set(p.name for p in self.path.iterdir()) != {'.owner'}:
                raise ValueError('Partial ledger requires root inspection, not reset')
            mkdir_durable(self.path / 'debits')
            write_new(batch, self.plan)
        self.records()

    def records(self):
        if read_json(self.path / 'batch.json') != self.plan:
            raise ValueError('Canonical budget mutated')
        rows = [read_json(path) for path in sorted((self.path / 'debits').glob('*.started.json'))]
        if (len(rows) > self.plan['max_calls'] or len(rows) * 1024 > self.plan['max_total_output_tokens']
                or len({r.get('attempt_key') for r in rows}) != len(rows)
                or any(r.get('plan_sha256') != self.plan_sha256 or type(r.get('reserved_output_tokens')) is not int
                       or r['reserved_output_tokens'] != 1024 for r in rows)):
            raise ValueError('Malformed existing debit records')
        return rows

    def totals(self):
        rows = self.records()
        return {'debits': len(rows), 'reserved_output_tokens': sum(r['reserved_output_tokens'] for r in rows)}

    def reserve(self, key, detail):
        if self.halted or (self.path / 'halted.json').exists(): raise BudgetError('Halted ledger cannot dispatch')
        if type(key) is not str or not key or len(key) > 512: raise ValueError('Bounded attempt key required')
        rows = self.records()
        if any(r['attempt_key'] == key for r in rows): raise ValueError('Attempt already debited; no replacement')
        if len(rows) >= self.plan['max_calls'] or (len(rows) + 1) * 1024 > self.plan['max_total_output_tokens']:
            raise BudgetError('Canonical call or permanent token reservation exhausted')
        slot = len(rows) + 1
        record = {'schema': 'formal-debit-v1', 'slot': slot, 'attempt_key': key, 'purpose': self.plan['purpose'],
                  'plan_sha256': self.plan_sha256, 'reserved_output_tokens': 1024, 'detail': detail}
        path = self.path / 'debits' / f'{slot:04d}.started.json'
        started_sha = write_new(path, record)
        return path, started_sha

    def halt(self, reason):
        self.halted = True
        if not (self.path / 'halted.json').exists():
            write_new(self.path / 'halted.json', {'reason': reason, 'no_automatic_resume': True})

    def close(self):
        if not self.halted:
            (self.path / '.owner').unlink()
            _fsync_directory(self.path)


def normalize_usage(raw):
    result = {'input_tokens': raw.get('prompt_eval_count'), 'output_tokens': raw.get('eval_count'),
              'source': 'provider-reported-response-not-independent-billing'}
    for name in ('input_tokens', 'output_tokens'):
        if result[name] is not None and (type(result[name]) is not int or result[name] < 0):
            raise ValueError('Malformed observed provider token count')
    if result['output_tokens'] is not None and result['output_tokens'] > 1024:
        raise ValueError('Observed output token cap violation')
    return result


def summarize_usage(usages):
    result = {'usd': None, 'human_minutes': None, 'billing_verified': False}
    for name in ('input', 'output'):
        key = name + '_tokens'
        values = [u.get(key) for u in usages]
        if any(v is not None and (type(v) is not int or v < 0) for v in values):
            raise ValueError('Invalid usage record')
        unknown = sum(v is None for v in values)
        result['known_' + key] = sum(v for v in values if v is not None)
        result['unknown_' + name + '_attempts'] = unknown
        result[key] = result['known_' + key] if values and not unknown else None
    return result


def _validate_request(spec):
    if (type(spec) is not dict or set(spec) != {'model', 'prompt', 'timeout_seconds', 'max_output_tokens'}
            or type(spec['model']) is not str or not spec['model'].strip() or len(spec['model']) > 256
            or type(spec['prompt']) is not str or not spec['prompt']
            or type(spec['max_output_tokens']) is not int or spec['max_output_tokens'] != 1024
            or type(spec['timeout_seconds']) not in (int, float) or not math.isfinite(spec['timeout_seconds'])
            or not 0 < spec['timeout_seconds'] <= 90):
        raise ValueError('Fixed request fields and caps required')


def request_ollama_once(spec):
    """One fixed HTTP request. Called by the gated, single-use worker only."""
    _validate_request(spec)
    body = {'model': spec['model'], 'stream': False, 'format': 'json',
            'messages': [{'role': 'user', 'content': spec['prompt']}],
            'options': {'num_predict': 1024, 'temperature': 0, 'num_ctx': 4096}, 'keep_alive': '0s'}
    encoded = json.dumps(body, separators=(',', ':'), ensure_ascii=False).encode()
    result = {'schema': 'formal-http-v1', 'status': 'transport-error', 'request_body_sha256': digest(encoded),
              'requested': {'max_output_tokens': 1024, 'num_ctx': 4096, 'automatic_retry': 0},
              'client_request_entries': 0, 'provider_requests_received': None,
              'usage': {'input_tokens': None, 'output_tokens': None}, 'text': None,
              'response_raw_base64': None, 'response_sha256': None, 'response_bytes': None}
    connection = None
    try:
        connection = http.client.HTTPConnection('127.0.0.1', 11434, timeout=spec['timeout_seconds'])
        result['client_request_entries'] = 1
        connection.request('POST', '/api/chat', body=encoded,
                           headers={'Content-Type': 'application/json', 'Content-Length': str(len(encoded)), 'Connection': 'close'})
        response = connection.getresponse()
        raw = response.read(RESPONSE_CAP + 1)
        result.update(http_status=response.status, response_raw_base64=base64.b64encode(raw).decode('ascii'),
                      response_sha256=digest(raw), response_bytes=len(raw))
        if len(raw) > RESPONSE_CAP:
            result['status'] = 'response-byte-limit'
        elif not 200 <= response.status < 300:
            result['status'] = 'http-error'
        else:
            value = json.loads(raw.decode('utf-8', 'strict'))
            if (type(value) is not dict or value.get('model') != spec['model'] or value.get('done') is not True
                    or type(value.get('message')) is not dict or type(value['message'].get('content')) is not str):
                raise ValueError('Incomplete or mismatched provider response')
            result['text'] = value['message']['content']
            result['usage'] = normalize_usage(value)
            result['status'] = 'complete' if all(result['usage'][k] is not None for k in ('input_tokens', 'output_tokens')) else 'usage-unknown'
    except (OSError, http.client.HTTPException) as error:
        result.update(status='transport-error', error=type(error).__name__)
    except (ValueError, UnicodeError, TypeError, KeyError) as error:
        result.update(status='response-parse-failure', error=type(error).__name__)
    finally:
        if connection is not None: connection.close()
    return result


def http_worker(packet_path):
    packet_path = Path(packet_path).resolve()
    if packet_path.name != 'worker-dispatch.json' or RUN_ROOT.resolve() not in packet_path.parents:
        raise ValueError('Worker packet must be in the fixed owned run tree')
    packet = read_json(packet_path)
    if set(packet) != {'ledger_path', 'started_path', 'started_sha256', 'request_path', 'request_sha256', 'role'}:
        raise ValueError('Exact worker binding required')
    ledger_path = Path(packet['ledger_path']).resolve()
    plan = read_json(ledger_path / 'batch.json')
    validate_plan(plan)
    if ledger_path != canonical_budget_path(plan).resolve(): raise ValueError('Noncanonical budget path')
    if ((ledger_path / 'halted.json').exists() or read_json(ledger_path / '.owner').get('plan_sha256') != digest(plan)):
        raise BudgetError('Worker requires the active, non-halted writer')
    started_path = Path(packet['started_path']).resolve()
    request_path = Path(packet['request_path']).resolve()
    if (started_path.parent != ledger_path / 'debits' or not re.fullmatch(r'[0-9]{4}\.started\.json', started_path.name)
            or request_path != packet_path.parent / 'request.json'):
        raise ValueError('Worker paths do not bind the owned slot')
    started = read_json(started_path)
    if digest(read_bytes(started_path)) != packet['started_sha256'] or digest(read_bytes(request_path)) != packet['request_sha256']:
        raise ValueError('Worker source binding changed')
    spec = read_json(request_path)
    _validate_request(spec)
    detail = started.get('detail', {})
    if (started.get('purpose') != plan['purpose'] or started.get('plan_sha256') != digest(plan)
            or started.get('reserved_output_tokens') != 1024
            or detail.get('request_sha256') != packet['request_sha256'] or detail.get('role') != packet['role']
            or detail.get('attempt_dir') != str(packet_path.parent)
            or packet['role'] not in plan['models'] or spec.get('model') != plan['models'][packet['role']]['name']
            or spec['timeout_seconds'] > plan['per_call_seconds'] or spec['timeout_seconds'] != detail.get('timeout_seconds')
            or detail.get('prompt_sha256') != digest(spec.get('prompt', ''))):
        raise ValueError('Worker plan, model, prompt or debit mismatch')
    deadline = detail.get('deadline_monotonic')
    if type(deadline) not in (int, float) or not math.isfinite(deadline) or time.monotonic() >= deadline:
        raise BudgetError('Worker admission deadline expired')
    ensure_ready(plan, spec['prompt'], packet['role'])
    entry = started_path.with_name(started_path.name.replace('.started.json', '.dispatch-entry.json'))
    write_new(entry, {'started_sha256': packet['started_sha256'], 'request_sha256': packet['request_sha256'],
                      'request_receipt_semantics': 'single-use admission; bytes received by server unknown'})
    # The socket timeout is local; the unchanged outer supervisor owns cleanup.
    spec['timeout_seconds'] = min(spec['timeout_seconds'], deadline - time.monotonic())
    if spec['timeout_seconds'] <= 0: raise BudgetError('Deadline expired before HTTP entry')
    return request_ollama_once(spec)


def load_runtime():
    if digest(RUNTIME.read_bytes()) != RUNTIME_SHA256 or digest(RUNTIME.with_name('process_supervisor.py').read_bytes()) != SUPERVISOR_SHA256:
        raise ValueError('Pinned process helper changed')
    spec = importlib.util.spec_from_file_location('formal_pinned_process_capture', RUNTIME)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def _invoke_worker(packet_path, directory, timeout):
    runtime = load_runtime()
    for name in ('home', 'tmp'): mkdir_durable(directory / name)
    return runtime.invoke([sys.executable, '-B', '-I', '-S', str(Path(__file__).resolve()), '--http-worker', str(packet_path)],
        directory, {'HOME': str(directory / 'home'), 'TMPDIR': str(directory / 'tmp'), 'PATH': os.defpath,
                    'LANG': 'C', 'PYTHONDONTWRITEBYTECODE': '1'}, timeout,
        stdout_cap=4 * 1024 * 1024, stderr_cap=128 * 1024)


def dispatch_one(ledger, key, prompt, role, directory, timeout, parent_sha256=None):
    readiness = ensure_ready(ledger.plan, prompt, role)
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= ledger.plan['per_call_seconds']:
        raise BudgetError('Run deadline exhausted or call timeout invalid')
    directory = Path(directory).resolve()
    if directory.exists(): raise FileExistsError('Attempt directory must be new')
    mkdir_durable(directory)
    request = {'model': ledger.plan['models'][role]['name'], 'prompt': prompt,
               'max_output_tokens': 1024, 'timeout_seconds': timeout}
    request_sha = write_new(directory / 'request.json', request)
    detail = {'prompt_sha256': digest(prompt), 'parent_sha256': parent_sha256, 'role': role,
              'request_sha256': request_sha, 'attempt_dir': str(directory),
              'timeout_seconds': timeout, 'deadline_monotonic': time.monotonic() + timeout}
    started, started_sha = ledger.reserve(key, detail)
    packet = {'ledger_path': str(ledger.path), 'started_path': str(started), 'started_sha256': started_sha,
              'request_path': str(directory / 'request.json'), 'request_sha256': request_sha, 'role': role}
    result = {'attempt_key': key, 'status': 'process-unknown', 'debit': 1, 'reserved_output_tokens': 1024,
              'prompt': prompt, 'prompt_sha256': digest(prompt), 'parent_sha256': parent_sha256,
              'model': request['model'], 'readiness': readiness, 'worker_invocations': 0,
              'client_request_entries': None, 'provider_requests_received': None,
              'usage': {'input_tokens': None, 'output_tokens': None}, 'text': None,
              'started_sha256': started_sha, 'process_receipt': None}
    try:
        packet_path = directory / 'worker-dispatch.json'; write_new(packet_path, packet)
        remaining = detail['deadline_monotonic'] - time.monotonic()
        if remaining <= 0: raise BudgetError('Deadline expired after pre-debit; no refund')
        result['worker_invocations'] = 1
        receipt = _invoke_worker(packet_path, directory, min(timeout, remaining))
        result['process_receipt'] = receipt
        write_new(directory / 'process-receipt.json', receipt)
        for name in ('stdout', 'stderr'):
            capture = receipt.get('captures', {}).get(name, {})
            if 'raw_base64' in capture:
                raw = base64.b64decode(capture['raw_base64'], validate=True)
            else:
                raw = receipt.get(name, '').encode('utf-8', 'strict')
            write_new(directory / (name + '.raw'), raw)
        if not load_runtime().successful_run(receipt):
            result['status'] = 'process-control-failure'
        else:
            value = json.loads(receipt['stdout'])
            if (type(value) is not dict or value.get('schema') != 'formal-http-v1'
                    or type(value.get('client_request_entries')) is not int or not 0 <= value['client_request_entries'] <= 1):
                raise ValueError('Invalid fixed HTTP worker observation')
            result.update({k: value.get(k) for k in ('status', 'text', 'usage', 'client_request_entries', 'provider_requests_received')})
            result['http_observation'] = value
    except BaseException as error:
        result.update(status='process-or-artifact-failure', error=type(error).__name__)
        ledger.halt(result['status'])
        artifact_sha = write_new(directory / 'attempt.json', result)
        result['attempt_artifact'] = {'path': str(directory / 'attempt.json'), 'sha256': artifact_sha}
        if not isinstance(error, Exception): raise
        return result
    if result['status'] != 'complete': ledger.halt(result['status'])
    artifact_sha = write_new(directory / 'attempt.json', result)
    result['attempt_artifact'] = {'path': str(directory / 'attempt.json'), 'sha256': artifact_sha}
    return result


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--http-worker':
        try:
            print(json.dumps(http_worker(Path(sys.argv[2])), ensure_ascii=False))
        except Exception:
            print('Fixed HTTP worker rejected request', file=sys.stderr)
            raise SystemExit(1)
    else:
        raise SystemExit('Use the explicit run_v1.py prepare/execute entry')
