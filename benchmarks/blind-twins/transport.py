"""Read-only twins adapter for the existing formal-transport implementation."""
import hashlib
import importlib.util
import json
from pathlib import Path
from ledger import read_regular

HERE = Path(__file__).resolve().parent
FORMAL = HERE.parent / 'formal-transport'


def _load(name):
    path = FORMAL / name
    spec = importlib.util.spec_from_file_location('twins_formal_' + name[:-3], path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def preflight_capabilities(prepared, plan, formal_runner=None):
    """Check all three roles without constructing a ledger or opening a socket."""
    runner = formal_runner or _load('run_v1.py')
    runner.validate_prepared(prepared)
    expected = runner.budget_plan(prepared, plan['models'], plan['backend'], plan['input_token_cap'])
    if expected != plan:
        raise ValueError('Formal plan does not bind the prepared source')
    roles = ('finder', 'samefamily_verifier', 'crossfamily_verifier')
    if set(plan['models']) != set(roles):
        raise ValueError('All three fixed roles must be checked before a D01 batch')
    prompt = prepared['task'] + json.dumps(prepared['rows'][0]['payload'])
    blockers = {}
    for role in roles:
        try:
            runner.transport.ensure_ready(plan, prompt, role)
        except runner.transport.CapabilityError as error:
            blockers[role] = str(error)
    return {'schema': 'twins-formal-capability-preflight-v1', 'ready': not blockers,
            'requested': {'calls': plan['max_calls'], 'output_tokens_per_call': plan['max_output_tokens'],
                          'total_output_reservation': plan['max_total_output_tokens'],
                          'automatic_retries': plan['automatic_retries'], 'inflight': plan['inflight']},
            'enforced': {'provider_output_cap_verified': None if blockers else 'registry-accepted',
                         'provider_retry_control_verified': None if blockers else 'registry-accepted',
                         'provider_attempts_verified': None},
            'observed': {'provider_attempts': None, 'input_tokens': None,
                         'output_tokens': None, 'usd': None},
            'blockers': blockers,
            'scope': 'pre-dispatch capability check only; no model or HTTP request'}


def project_formal_report(raw_path, denominator_path=None, *, formal_report=None):
    """Add explicit request/control/observation boundaries to a validated formal raw."""
    reader = formal_report or _load('report_v1.py')
    report = reader.read_report(Path(raw_path), denominator_path)
    if report.get('kind') != 'formal-v1-readonly-recomputed':
        raise ValueError('A formal-v1 report is required')
    data = read_regular(Path(raw_path).absolute(), 16 * 1024 * 1024)
    if hashlib.sha256(data).hexdigest() != report['raw_sha256']:
        raise ValueError('Formal raw changed after report validation')
    raw = json.loads(data)
    if raw['experiment'] != 'twins':
        raise ValueError('This adapter only handles the twins experiment')
    plan = raw['budget_plan']
    for row in raw['rows']:
        if row.get('cache') is not False or type(row.get('retry_count')) is not int or row['retry_count'] != 0:
            raise ValueError('Formal raw cannot claim cache or retry semantics outside the fixed protocol')
    attempts = [attempt for row in raw['rows'] for attempt in row['attempts']]
    client_entries = 0
    client_entries_unknown = 0
    worker_invocations = 0
    observed_input = []
    observed_output = []
    for attempt in attempts:
        if (type(attempt.get('debit')) is not int or attempt['debit'] != 1
                or type(attempt.get('reserved_output_tokens')) is not int
                or attempt['reserved_output_tokens'] != 1024):
            raise ValueError('Attempt has an invalid durable reservation')
        invocation = attempt.get('worker_invocations')
        entry = attempt.get('client_request_entries')
        if type(invocation) is not int or not 0 <= invocation <= 1:
            raise ValueError('Worker invocation count is unknown or exceeds one')
        if entry is None:
            client_entries_unknown += 1
        elif type(entry) is not int or not 0 <= entry <= invocation:
            raise ValueError('Client request entries exceed the one-worker contract')
        else:
            client_entries += entry
        worker_invocations += invocation
        received = attempt.get('provider_requests_received')
        if received is not None:
            raise ValueError('Provider receive count requires an independent server receipt')
        usage_record = attempt.get('usage')
        if (type(usage_record) is not dict
                or not {'input_tokens', 'output_tokens'} <= set(usage_record)
                or set(usage_record) - {'input_tokens', 'output_tokens', 'source'}
                or ('source' in usage_record and usage_record['source'] != 'provider-reported-response-not-independent-billing')):
            raise ValueError('Exact observed token usage fields required')
        for field, destination in (('input_tokens', observed_input), ('output_tokens', observed_output)):
            value = usage_record[field]
            if value is not None and (type(value) is not int or value < 0
                                      or (field == 'output_tokens' and value > 1024)):
                raise ValueError('Malformed or over-cap provider-reported token usage')
            destination.append(value)
    usage = report['usage_summary']
    for field, values in (('input', observed_input), ('output', observed_output)):
        if (usage['known_' + field + '_tokens'] != sum(v for v in values if v is not None)
                or usage['unknown_' + field + '_attempts'] != sum(v is None for v in values)):
            raise ValueError('Reader token summary disagrees with immutable attempt usage')
    if (type(raw.get('calls')) is not int or raw['calls'] != len(attempts)
            or raw['calls'] > plan['max_calls'] or len(attempts) * 1024 > plan['max_total_output_tokens']):
        raise ValueError('Attempt count exceeds or disagrees with the fixed plan')
    return {'schema': 'twins-formal-controls-report-v1', 'kind': report['kind'],
            'raw_sha256': report['raw_sha256'], 'raw_status': raw['status'], 'metrics': report['metrics'],
            'requested': {'batch_calls_ceiling': plan['max_calls'],
                          'output_tokens_per_call': plan['max_output_tokens'],
                          'batch_output_reservation_ceiling': plan['max_total_output_tokens'],
                          'automatic_retries': plan['automatic_retries'], 'inflight': plan['inflight']},
            'enforced': {'durable_debits_recorded': report['run_debits_recorded'],
                         'reserved_output_tokens_recorded': report['run_reserved_output_tokens'],
                         'worker_invocations_recorded': worker_invocations,
                         'batch_ledger_verified': report['batch_ledger_verified'],
                         'provider_output_cap_independently_verified': None,
                         'provider_internal_retry_control_verified': None},
            'observed': {'client_request_entries_known': client_entries,
                         'client_request_entries_unknown': client_entries_unknown,
                         'provider_requests_received': None,
                         'provider_attempts': None, 'input_tokens': usage['input_tokens'],
                         'output_tokens': usage['output_tokens'],
                         'known_input_tokens': usage['known_input_tokens'],
                         'known_output_tokens': usage['known_output_tokens'],
                         'unknown_input_attempts': usage['unknown_input_attempts'],
                         'unknown_output_attempts': usage['unknown_output_attempts'],
                         'usd': usage['usd'], 'human_minutes': usage['human_minutes'],
                         'billing_verified': usage['billing_verified']},
            'retry': {'requested_automatic_retries': 0,
                      'client_recorded_repeat_dispatches': 0 if client_entries_unknown == 0 else None,
                      'provider_internal_retries': None},
            'context_evidence_gap': {
                'status': 'not-measured', 'viewed_context': 'isolated function included in prompt',
                'declared_context': 'model JSON line/evidence claim only',
                'reason': 'No exploration trace or gold role-tagged code blocks; verdict is not context retrieval recall',
                'method_reference': 'https://arxiv.org/abs/2609.32601'},
            'limitations': 'Read-only raw/artifact replay; requested flags and provider-reported usage are not independent provider-attempt or billing proof'}
