"""Pure artifact-bound stage replay and reviewer-supplied decisions; no dispatch."""
import copy
import hashlib
import importlib.util
import json
import math
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('formal_stage_review_runner', HERE / 'run_v1.py')
runner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(runner)
RAW_CAP = 16 * 1024 * 1024
ARTIFACT_CAP = 4 * 1024 * 1024
TOTAL_ARTIFACT_CAP = 16 * 1024 * 1024
MAX_ARTIFACTS = 40
SEPARATOR = '\nIndependent review of candidate; reject if no concrete flaw: '
CLASSIFICATIONS = {'U', 'code-safe', 'deployment-unknown', 'missing-path', 'unsupported', 'candidate-survives'}
DERIVED_FIELDS = ('finder_candidate', 'detected', 'surfaced', 'root_cause_correct', 'verifier_parent_sha256')


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _equal(left, right):
    # JSON typed equality: True, 1 and 1.0 are distinct observations.
    return _canonical(left) == _canonical(right)


def _pairs(items):
    result = {}
    for key, value in items:
        _require(key not in result, 'Duplicate JSON key')
        result[key] = value
    return result


def _float(value):
    number = float(value)
    _require(math.isfinite(number), 'Nonfinite JSON number')
    return number


def _constant(_value):
    raise ValueError('Nonfinite JSON constant')


def _decoder():
    return json.JSONDecoder(object_pairs_hook=_pairs, parse_float=_float, parse_constant=_constant)


def _json(data, cap):
    _require(type(data) is bytes and len(data) <= cap, 'Snapshot byte cap exceeded or bytes required')
    try:
        return _decoder().decode(data.decode('utf-8', 'strict'))
    except (UnicodeError, RecursionError, OverflowError) as error:
        raise ValueError('Invalid bounded UTF8 JSON') from error


def _text(value):
    return type(value) is str and bool(value.strip())


def _digest(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def _prompt(attempt, prepared, payload, parent):
    prompt = attempt.get('prompt')
    _require(type(prompt) is str and attempt.get('prompt_sha256') == _sha(prompt.encode('utf-8')),
             'Attempt prompt SHA mismatch')
    task = prepared['task']
    _require(prompt.startswith(task), 'Prompt task prefix mismatch')
    tail = prompt[len(task):]
    try:
        observed, end = _decoder().raw_decode(tail)
    except (ValueError, RecursionError) as error:
        raise ValueError('Invalid prompt payload JSON') from error
    _require(_equal(observed, payload), 'Prompt payload mismatch')
    rest = tail[end:]
    if parent is None:
        _require(not rest.strip(), 'Unexpected finder prompt suffix')
    else:
        _require(rest.startswith(SEPARATOR), 'Verifier prompt separator mismatch')
        candidate = _json(rest[len(SEPARATOR):].encode('utf-8'), ARTIFACT_CAP)
        _require(_equal(candidate, parent), 'Verifier prompt candidate mismatch')


def _parse_answer(module, experiment, text, payload):
    if type(text) is not str:
        return None
    # Reject ambiguous JSON even where the historical parser would retain its last key.
    try:
        _decoder().decode(text)
    except json.JSONDecodeError:
        return None
    if experiment == 'context':
        return module.parse_context_answer(text, payload)
    return module.twins.parse_answer(text, payload['source'])


def _artifact_map(blobs):
    _require(type(blobs) is dict and len(blobs) <= MAX_ARTIFACTS, 'Invalid artifact snapshot map')
    total = 0
    for key, data in blobs.items():
        _require(_text(key) and '\x00' not in key and '\\' not in key,
                 'Invalid artifact snapshot key')
        _require(type(data) is bytes and len(data) <= ARTIFACT_CAP, 'Artifact byte cap exceeded')
        total += len(data)
    _require(total <= TOTAL_ARTIFACT_CAP, 'Total artifact byte cap exceeded')


def _attempt(attempt, blobs, used, *, module, prepared, plan, row, stage, parent):
    _require(type(attempt) is dict, 'Invalid attempt')
    reference = attempt.get('attempt_artifact')
    _require(type(reference) is dict and set(reference) == {'path', 'sha256'}
             and _text(reference['path']) and _digest(reference['sha256']), 'Missing attempt artifact binding')
    path = reference['path']
    _require(path not in used and path in blobs, 'Missing or reused attempt artifact')
    used.add(path)
    data = blobs[path]
    _require(_sha(data) == reference['sha256'], 'Attempt artifact SHA mismatch')
    artifact = _json(data, ARTIFACT_CAP)
    projection = {k: v for k, v in attempt.items() if k not in ('parsed', 'attempt_artifact')}
    _require(type(artifact) is dict and _equal(projection, artifact), 'Immutable attempt projection mismatch')
    arm = prepared.get('arm', row.get('arm', row['id']))
    expected_key = f"{arm}|{prepared.get('repeat', 0)}|{row['id']}|{stage}"
    _require(artifact.get('attempt_key') == expected_key, 'Attempt key/stage mismatch')
    role = 'finder' if stage == 'finder' else prepared['arm'] + '_verifier'
    _require(role in plan['models'] and artifact.get('model') == plan['models'][role]['name'], 'Attempt model mismatch')
    _require(type(artifact.get('debit')) is int and artifact['debit'] == 1
             and type(artifact.get('reserved_output_tokens')) is int and artifact['reserved_output_tokens'] == 1024,
             'Invalid attempt reservation')
    parent_sha = None if parent is None else module.transport.digest(parent)
    _require(artifact.get('parent_sha256') == parent_sha, 'Attempt parent parsed lineage mismatch')
    _prompt(artifact, prepared, row['payload'], parent)
    status = artifact.get('status')
    _require(_text(status), 'Missing attempt status')
    parsed = None
    if status == 'complete':
        parsed = _parse_answer(module, prepared['experiment'], artifact.get('text'), row['payload'])
        _require('parsed' in attempt and _equal(attempt['parsed'], parsed), 'Artifact text/derived parsed mismatch')
    else:
        _require('parsed' not in attempt, 'Failed attempt cannot supply parsed candidate')
    return {'stage': stage, 'observation_status': 'parsed' if parsed is not None else 'parse_failure' if status == 'complete' else status,
            'candidate': parsed, 'attempt_sha256': reference['sha256'], 'parent_parsed_sha256': parent_sha,
            'adjudication': 'U', 'classification': 'U', 'reason': None, 'reviewer': None}


def _validate_derived(raw_bytes, attempt_artifacts, *, runner_context=None):
    """Replay caller snapshots only. Never open a path supplied by raw or dispatch."""
    module = runner if runner_context is None else runner_context
    raw = _json(raw_bytes, RAW_CAP)
    _require(type(raw) is dict and raw.get('schema') == 'formal-experiment-v1', 'Formal raw schema required')
    _artifact_map(attempt_artifacts)
    prepared = raw.get('prepared')
    _require(type(prepared) is dict, 'Missing prepared snapshot')
    module.validate_prepared(prepared)
    plan = raw.get('budget_plan')
    module.transport.validate_plan(plan)
    expected_plan = module.budget_plan(prepared, plan['models'], plan['backend'], plan['input_token_cap'])
    _require(_equal(plan, expected_plan) and raw.get('experiment') == prepared['experiment'], 'Prepared/plan mismatch')
    _require(type(raw.get('rows')) is list and len(raw['rows']) <= len(prepared['rows']), 'Invalid raw rows')
    expected = {row['id']: row for row in prepared['rows']}
    ids = [row.get('id') for row in raw['rows'] if type(row) is dict]
    _require(len(ids) == len(raw['rows']) and all(type(i) is str for i in ids)
             and len(ids) == len(set(ids)) and not set(ids) - set(expected), 'Duplicate or unknown raw case')
    labels = {x['id']: x for x in module.protocol.generate()[1]} if prepared['experiment'] == 'twins' else {}
    by_id = {row['id']: row for row in raw['rows']}
    derived = {}; stage_rows = {}; used = set()
    for case_id, original in expected.items():
        row = by_id.get(case_id)
        stages = ['finder']
        if prepared['experiment'] == 'twins' and prepared['arm'] != 'finder-only':
            stages.append('verifier')
        missing_stages = [{'stage': name, 'observation_status': 'missing', 'candidate': None,
                           'attempt_sha256': None, 'parent_parsed_sha256': None, 'adjudication': 'U',
                           'classification': 'U', 'reason': None, 'reviewer': None} for name in stages]
        if row is None:
            derived[case_id] = {}; stage_rows[case_id] = missing_stages
            continue
        fingerprint = module.transport.digest({'prepared': prepared['prepared_sha256'], 'plan': module.transport.digest(plan), 'id': case_id})
        _require(row.get('fingerprint') == fingerprint and row.get('source_sha256') == original['source_sha256']
                 and _equal(row.get('payload'), original['payload']), 'Row source or fingerprint mismatch')
        _require(row.get('adjudication') == 'U'
                 and row.get('detection_adjudication', 'U') == 'U'
                 and type(row.get('differential_oracle')) is bool and row['differential_oracle'] is False
                 and ('differential_status' not in row or row['differential_status'] == 'not-measured'),
                 'Formal producer cannot supply unbound human or differential outcomes')
        attempts = row.get('attempts')
        _require(type(attempts) is list and len(attempts) <= len(stages), 'Invalid attempt stage count')
        state = {}; parsed_parent = None; failure = None; failed_stage = None
        observed = missing_stages
        for index, attempt in enumerate(attempts):
            stage = stages[index]
            _require(failure is None and (index == 0 or parsed_parent is not None), 'Attempt after failed or missing predecessor')
            item = _attempt(attempt, attempt_artifacts, used, module=module, prepared=prepared, plan=plan,
                            row=row, stage=stage, parent=None if index == 0 else parsed_parent)
            observed[index] = item
            parsed = item['candidate']
            if parsed is None:
                failure = 'parse_failure' if attempt['status'] == 'complete' else attempt['status']
                failed_stage = stage
                continue
            if stage == 'finder':
                state['finder_candidate'] = parsed
            else:
                state['verifier_parent_sha256'] = item['parent_parsed_sha256']
            surfaced = bool(parsed['findings']) if prepared['experiment'] == 'context' else parsed['vulnerability']
            state['surfaced'] = surfaced
            if prepared['experiment'] == 'twins':
                hit = parsed['vulnerability'] and parsed['category'] == labels[case_id]['family']
                if stage == 'finder': state['detected'] = bool(hit)
                state['root_cause_correct'] = bool(hit)
            else:
                state['detected'] = state['finder_candidate'].get('vulnerability', surfaced)
            parsed_parent = parsed
        for key in DERIVED_FIELDS:
            _require((key in row) == (key in state) and (key not in state or _equal(row[key], state[key])),
                     'Mutable row derived field mismatch: ' + key)
        status = row.get('status')
        if failure is not None:
            _require(status == failure and row.get('failed_stage') == failed_stage, 'Failed stage/state mismatch')
        elif len(attempts) == len(stages):
            _require(status == 'complete' and 'failed_stage' not in row, 'Complete stage/state mismatch')
        elif attempts:
            _require(status in ('budget_exhausted', 'stage_incomplete')
                     and row.get('failed_stage') == stages[len(attempts)],
                     'Unattempted remaining stage/state mismatch')
            if status == 'stage_incomplete':
                _require(_text(row.get('error')), 'Incomplete stage needs its recorded error')
            _require(raw.get('status') != 'complete', 'Partial stages cannot be a complete run')
        else:
            allowed = {'missing', 'budget_exhausted', 'stage_incomplete'}
            if prepared['experiment'] == 'context' and original.get('selection_status') != 'ready':
                allowed.add(original.get('selection_status'))
            _require(status in allowed, 'No-attempt row cannot be complete')
            if status == 'stage_incomplete':
                _require(row.get('failed_stage') == 'finder' and _text(row.get('error')),
                         'Unattempted finder exception needs its stage and recorded error')
        derived[case_id] = state; stage_rows[case_id] = observed
    if raw.get('status') == 'complete':
        _require(len(raw['rows']) == len(expected) and all(row.get('status') == 'complete' for row in raw['rows']),
                 'Missing or incomplete rows cannot be a complete run')
    _require(set(attempt_artifacts) == used, 'Unreferenced artifact snapshot')
    return {'raw_sha256': _sha(raw_bytes), 'raw': raw, 'derived': derived, 'stage_rows': stage_rows}


def validate_derived(raw_bytes, attempt_artifacts, *, runner_context=None):
    """Return a validated caller snapshot; malformed shapes are typed rejection."""
    try:
        return _validate_derived(raw_bytes, attempt_artifacts, runner_context=runner_context)
    except (KeyError, TypeError, AttributeError, RecursionError, OverflowError, UnicodeError) as error:
        raise ValueError('Malformed derived-state snapshot: ' + type(error).__name__) from error


def _worksheet_sha(worksheet):
    return _sha(_canonical({k: v for k, v in worksheet.items() if k != 'worksheet_sha256'}))


def build_worksheet(raw_bytes, attempt_artifacts, *, runner_context=None):
    module = runner if runner_context is None else runner_context
    verified = validate_derived(raw_bytes, attempt_artifacts, runner_context=module)
    raw = verified['raw']; prepared = raw['prepared']
    _require(prepared['experiment'] == 'twins', 'Worksheet v1 supports twins only')
    by_id = {row['id']: row for row in raw['rows']}
    rows = []
    for original in prepared['rows']:
        case_id = original['id']; row = by_id.get(case_id, {})
        fingerprint = module.transport.digest({'prepared': prepared['prepared_sha256'], 'plan': module.transport.digest(raw['budget_plan']), 'id': case_id})
        rows.append({'id': case_id, 'fingerprint': fingerprint, 'source_sha256': original['source_sha256'],
                     'run_status': row.get('status', 'missing'), 'derived': copy.deepcopy(verified['derived'][case_id]),
                     'stages': copy.deepcopy(verified['stage_rows'][case_id])})
    result = {'schema': 'formal-stage-review-worksheet-v1', 'raw_sha256': verified['raw_sha256'],
              'scope': {key: prepared[key] for key in ('prepared_sha256', 'experiment', 'arm', 'repeat')}, 'rows': rows,
              'semantics': 'Reviewer-supplied judgments about positive stage finding claims only; no human verification, raw mutation, status promotion or metrics recomputation.'}
    result['worksheet_sha256'] = _worksheet_sha(result)
    return result


def _apply_overlay(worksheet, overlay):
    """Record a reviewer statement, never certify identity or finding confirmation."""
    _require(type(worksheet) is dict and worksheet.get('schema') == 'formal-stage-review-worksheet-v1'
             and worksheet.get('worksheet_sha256') == _worksheet_sha(worksheet), 'Worksheet digest mismatch')
    _require(type(overlay) is dict and set(overlay) == {'schema', 'raw_sha256', 'worksheet_sha256', 'reviewer', 'decisions'}
             and overlay['schema'] == 'formal-stage-review-overlay-v1', 'Exact stage overlay schema required')
    _require(overlay['raw_sha256'] == worksheet['raw_sha256']
             and overlay['worksheet_sha256'] == worksheet['worksheet_sha256'], 'Overlay belongs to another snapshot')
    _require(_text(overlay['reviewer']) and len(overlay['reviewer']) <= 256
             and type(overlay['decisions']) is list and len(overlay['decisions']) <= 20, 'Invalid reviewer or decisions')
    result = copy.deepcopy(worksheet)
    rows = {row['id']: row for row in result['rows']}; seen = set()
    for decision in overlay['decisions']:
        _require(type(decision) is dict and set(decision) == {'id', 'fingerprint', 'stage', 'attempt_sha256',
                 'parent_parsed_sha256', 'adjudication', 'classification', 'reason'}, 'Exact stage decision fields required')
        key = (decision['id'], decision['stage'])
        _require(key not in seen and decision['id'] in rows, 'Duplicate or unknown stage decision')
        seen.add(key); row = rows[decision['id']]
        items = {item['stage']: item for item in row['stages']}
        _require(decision['fingerprint'] == row['fingerprint'] and decision['stage'] in items, 'Decision row/stage mismatch')
        item = items[decision['stage']]
        _require(item['observation_status'] == 'parsed' and item['candidate'] is not None
                 and item['attempt_sha256'] is not None, 'Unattempted or failed stage cannot receive a verdict')
        _require(decision['attempt_sha256'] == item['attempt_sha256']
                 and decision['parent_parsed_sha256'] == item['parent_parsed_sha256'], 'Decision artifact/parent mismatch')
        _require(decision['adjudication'] in ('TP', 'FP', 'U') and decision['classification'] in CLASSIFICATIONS
                 and _text(decision['reason']) and len(decision['reason']) <= 4096, 'Invalid stage judgment or reason')
        _require(item['candidate']['vulnerability'] is True or decision['adjudication'] == 'U',
                 'Negative reply has no positive finding claim for TP or FP')
        item.update(adjudication=decision['adjudication'], classification=decision['classification'],
                    reason=decision['reason'], reviewer=overlay['reviewer'])
    result['review_overlay_sha256'] = _sha(_canonical(overlay))
    result['review_semantics'] = 'Recorded reviewer-provided decisions; no independent human authority inferred.'
    # The original worksheet binding is retained as the overlay subject, not reissued.
    return result


def apply_overlay(worksheet, overlay):
    """Reject malformed JSON shapes consistently without catching I/O failures."""
    try:
        return _apply_overlay(worksheet, overlay)
    except (KeyError, TypeError, AttributeError, RecursionError, OverflowError, UnicodeError) as error:
        raise ValueError('Malformed review overlay: ' + type(error).__name__) from error
