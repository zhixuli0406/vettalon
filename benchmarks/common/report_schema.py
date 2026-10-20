"""Per-task evaluation records and their summary. Stdlib only; no model calls.

A record is one attempt at one task on one item:

    {"id": "case-1", "task_type": "detect", "hint_level": "L1",
     "outcome": "success" | "failure" | <failure taxonomy>,
     "cost": {"usd": null, "tokens": 1830, "wall_s": 41.2, "human_review_min": null}}

* task types are scored separately and never summed (detect, localize, poc, patch);
* hint levels follow CyberGym-style disclosure: L0 none, L1 CWE only,
  L2 file/location, L3 advisory text; the main result uses L0 and L1 only;
* operational failures (timeout, infra_error, parse_failure, refusal,
  budget_exhausted) stay in the denominator and are counted by kind;
* cost fields are null when unknown. Zero is rejected: a real measurement of
  zero tokens or zero review minutes is indistinguishable from a filled-in
  default, so record null and say why elsewhere.
"""
import importlib.util
import math
import sys
from pathlib import Path


def _sibling(name):
    """Load a module from this directory by path (works under python -I -S)."""
    key = 'vettalon_eval_common_' + name
    if key not in sys.modules:
        spec = importlib.util.spec_from_file_location(key, Path(__file__).resolve().with_name(name + '.py'))
        module = importlib.util.module_from_spec(spec)
        sys.modules[key] = module
        spec.loader.exec_module(module)
    return sys.modules[key]


stats = _sibling('stats')

SCHEMA = 'eval-task-record-v1'
SUMMARY_SCHEMA = 'eval-task-summary-v1'
TASK_TYPES = ('detect', 'localize', 'poc', 'patch')
HINT_LEVELS = {'L0': 'none', 'L1': 'cwe-only', 'L2': 'file-or-location', 'L3': 'advisory-text'}
MAIN_RESULT_HINT_LEVELS = ('L0', 'L1')
FAILURE_TAXONOMY = ('timeout', 'infra_error', 'parse_failure', 'refusal', 'budget_exhausted')
OUTCOMES = ('success', 'failure') + FAILURE_TAXONOMY
COST_FIELDS = ('usd', 'tokens', 'wall_s', 'human_review_min')
RECORD_FIELDS = {'id', 'task_type', 'hint_level', 'outcome', 'cost'}
OPTIONAL_FIELDS = {'repeat', 'arm', 'note'}


def validate_record(record):
    if type(record) is not dict:
        raise ValueError('task record must be an object')
    keys = set(record)
    if not RECORD_FIELDS <= keys or keys - RECORD_FIELDS - OPTIONAL_FIELDS:
        raise ValueError('task record fields differ from ' + SCHEMA)
    if type(record['id']) is not str or not record['id']:
        raise ValueError('task record id required')
    if record['task_type'] not in TASK_TYPES:
        raise ValueError('unknown task_type; detect/localize/poc/patch are scored separately')
    if record['hint_level'] not in HINT_LEVELS:
        raise ValueError('hint_level must be one of L0, L1, L2, L3')
    if record['outcome'] not in OUTCOMES:
        raise ValueError('unknown outcome; use success, failure or a failure taxonomy kind')
    if 'repeat' in record and (type(record['repeat']) is not int or record['repeat'] < 0):
        raise ValueError('repeat must be a non-negative integer')
    if 'arm' in record and (type(record['arm']) is not str or not record['arm']):
        raise ValueError('arm must be a non-empty string')
    cost = record['cost']
    if type(cost) is not dict or set(cost) != set(COST_FIELDS):
        raise ValueError('cost must carry exactly usd, tokens, wall_s, human_review_min')
    for field in COST_FIELDS:
        value = cost[field]
        if value is None:
            continue
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise ValueError(f'cost.{field} must be null or a positive finite number')
        if value == 0:
            raise ValueError(f'cost.{field} is 0; record null when unknown, never 0')
    return record


def _cost_summary(records):
    out = {}
    for field in COST_FIELDS:
        known = [r['cost'][field] for r in records if r['cost'][field] is not None]
        unknown = len(records) - len(known)
        out[field] = {'known_total': sum(known) if known else None, 'known_count': len(known),
                      'unknown_count': unknown, 'total': sum(known) if records and unknown == 0 else None}
    return out


def _cell(records):
    n = len(records)
    successes = sum(r['outcome'] == 'success' for r in records)
    failures = {kind: sum(r['outcome'] == kind for r in records) for kind in FAILURE_TAXONOMY}
    cost = _cost_summary(records)
    usd = cost['usd']['total']
    return {'n': n, 'success': stats.rate(successes, n),
            'plain_failures': sum(r['outcome'] == 'failure' for r in records),
            'operational_failures': {kind: stats.rate(count, n) for kind, count in failures.items()},
            'cost': cost,
            'usd_per_success': usd / successes if usd is not None and successes else None,
            'denominator_note': 'operational failures are counted, never removed from n'}


def summarize(records):
    """Summary per task type and hint level; main result per task over L0+L1."""
    if type(records) is not list:
        raise ValueError('records must be a list')
    seen = set()
    for record in records:
        validate_record(record)
        key = (record['id'], record['task_type'], record['hint_level'], record.get('arm'), record.get('repeat'))
        if key in seen:
            raise ValueError('duplicate task record for the same item, task, hint, arm and repeat')
        seen.add(key)
    by_task = {}
    main = {}
    for task in TASK_TYPES:
        task_records = [r for r in records if r['task_type'] == task]
        if not task_records:
            continue
        by_task[task] = {level: _cell([r for r in task_records if r['hint_level'] == level])
                         for level in HINT_LEVELS if any(r['hint_level'] == level for r in task_records)}
        main_records = [r for r in task_records if r['hint_level'] in MAIN_RESULT_HINT_LEVELS]
        main[task] = _cell(main_records) if main_records else None
    return {'schema': SUMMARY_SCHEMA, 'record_schema': SCHEMA, 'records': len(records),
            'by_task': by_task, 'main_result': main,
            'main_result_hint_levels': list(MAIN_RESULT_HINT_LEVELS),
            'reported_separately_hint_levels': [level for level in HINT_LEVELS if level not in MAIN_RESULT_HINT_LEVELS],
            'task_types_summed': False}


def format_summary(summary):
    lines = []
    for task, cell in summary['main_result'].items():
        if cell is None:
            lines.append(f'{task} main (L0+L1): no records')
            continue
        lines.append(stats.format_rate(cell['success']['k'], cell['n'], f'{task} main (L0+L1)'))
    for task, levels in summary['by_task'].items():
        for level, cell in levels.items():
            lines.append(stats.format_rate(cell['success']['k'], cell['n'], f'{task} {level}'))
            failed = {k: v['k'] for k, v in cell['operational_failures'].items() if v['k']}
            if failed:
                lines.append(f'  operational failures kept in n: {failed}')
    return lines


def _count(ratio, n):
    if ratio is None or n is None:
        return None
    value = round(ratio * n)
    if not math.isclose(value, ratio * n, abs_tol=1e-6):
        raise ValueError('metric ratio does not correspond to an integer count')
    return value


def adjudication_uncertainty(metrics):
    """Intervals and n for every rate in an adjudication-aware-v3 metrics block.

    Reads only the recorded counts and bound ratios; never changes the metrics.
    """
    if type(metrics) is not dict or metrics.get('metric_schema') != 'adjudication-aware-v3':
        raise ValueError('adjudication-aware-v3 metrics required')
    n_pos = metrics['positive_denominator']
    n_safe = metrics['safe_denominator']
    out = {'schema': 'rate-uncertainty-v1', 'confidence': stats.CONFIDENCE,
           'clt_min_n': stats.CLT_MIN_N, 'normal_approximation_used': False, 'rates': {}}
    rates = out['rates']
    for name, key in (('detection_recall', 'detection_recall_bounds'),
                      ('surfaced_recall', 'surfaced_recall_bounds')):
        bounds = metrics.get(key)
        if bounds is not None:
            rates[name] = stats.bounded_rate(_count(bounds[0], n_pos), _count(bounds[1], n_pos), n_pos)
    exploit = metrics.get('exploit_validated_recall_bounds')
    eligible = metrics.get('canonical_rebuildable_denominator')
    if exploit is not None and eligible:
        rates['exploit_validated_recall'] = stats.bounded_rate(_count(exploit[0], eligible), _count(exploit[1], eligible), eligible)
    tp, fp, u = metrics['TP'], metrics['FP'], metrics['U']
    rates['adjudicated_precision'] = stats.rate(tp, tp + fp)
    rates['adjudicated_FDR'] = stats.rate(fp, tp + fp)
    rates['adjudication_rate'] = stats.rate(tp + fp, tp + fp + u)
    if tp + fp + u:
        rates['precision_with_unresolved'] = stats.bounded_rate(tp, tp + u, tp + fp + u)
    fpr = metrics.get('FPR_bounds')
    if fpr is not None and n_safe:
        rates['FPR'] = stats.bounded_rate(_count(fpr[0], n_safe), _count(fpr[1], n_safe), n_safe)
    return out


def format_uncertainty(uncertainty):
    lines = []
    for name, value in uncertainty['rates'].items():
        if 'k' in value:
            lines.append(stats.format_rate(value['k'], value['n'], name))
        else:
            lines.append(stats.format_bounded(value['k_lower'], value['k_upper'], value['n'], name))
    return lines
