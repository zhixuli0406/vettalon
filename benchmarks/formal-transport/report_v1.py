"""Read-only formal accounting and historical synthetic-twins reader only."""
import argparse
import copy
import importlib.util
import json
import math
import os
import stat
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('formal_report_runner', HERE / 'run_v1.py')
runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)
transport = runner.transport
protocol = runner.protocol
review = runner._load(HERE / 'review_v1.py', 'formal_report_review')
cost = runner._load(HERE / 'cost_v1.py', 'formal_report_cost')
# Shared interval reporting: every metrics rate also gets [lo, hi] and n.
uncertainty = runner._load(HERE.parent / 'common' / 'report_schema.py', 'formal_report_uncertainty')
RAW_CAP = 16 * 1024 * 1024
ARTIFACT_CAP = 4 * 1024 * 1024
ARTIFACT_TOTAL_CAP = 16 * 1024 * 1024
ARTIFACT_COUNT_CAP = 40
ATTACHMENT_CAP = 2 * 1024 * 1024


def _absolute(path):
    path = Path(path)
    if '..' in path.parts: raise ValueError('Parent traversal is not an input path')
    return path.absolute()


def _read_regular(path, cap):
    """Open each POSIX component without following symlinks; never block on FIFO."""
    path = _absolute(path)
    directory = None; leaf = None
    try:
        directory = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for part in path.parts[1:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory); directory = next_fd
        leaf = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        info = os.fstat(leaf)
        if not stat.S_ISREG(info.st_mode) or info.st_size > cap:
            raise ValueError('Regular bounded input file required')
        with os.fdopen(leaf, 'rb') as handle:
            leaf = None
            data = handle.read(cap + 1)
        if len(data) > cap: raise ValueError('Input byte cap exceeded')
        return data
    except OSError as error:
        raise ValueError('Cannot open ordinary input without symlinks') from error
    finally:
        if leaf is not None: os.close(leaf)
        if directory is not None: os.close(directory)


def _track(path, cap, snapshots):
    path = _absolute(path)
    data = _read_regular(path, cap)
    if path in snapshots and snapshots[path][0] != data:
        raise ValueError('Input changed within the read-only snapshot')
    snapshots[path] = (data, cap)
    return data


def _artifact_snapshots(raw, raw_path, snapshots):
    blobs = {}; total = 0; count = 0
    if type(raw.get('rows')) is not list: raise ValueError('Formal rows required')
    for row in raw['rows']:
        if type(row) is not dict or type(row.get('attempts')) is not list:
            raise ValueError('Formal attempt list required')
        for attempt in row['attempts']:
            count += 1
            if count > ARTIFACT_COUNT_CAP: raise ValueError('Attempt count cap exceeded')
            if type(attempt) is not dict or type(attempt.get('attempt_artifact')) is not dict:
                raise ValueError('Immutable attempt artifact required')
            reference = attempt['attempt_artifact']
            if type(reference.get('path')) is not str: raise ValueError('Artifact path required')
            path = _absolute(reference['path'])
            if path.name != 'attempt.json' or raw_path.parent not in path.parents:
                raise ValueError('Attempt artifact outside this run')
            # Admission uses remaining shared bytes, not a fresh full cap per file.
            remaining = ARTIFACT_TOTAL_CAP - total
            if remaining <= 0: raise ValueError('Total attempt byte cap exceeded')
            data = _track(path, min(ARTIFACT_CAP, remaining), snapshots)
            total += len(data)
            blobs[reference['path']] = data
    return blobs


def _cost_inventory(raw):
    prepared = raw['prepared']; plan = raw['budget_plan']; inventory = []
    for row in raw['rows']:
        for index, attempt in enumerate(row['attempts']):
            role = 'finder' if index == 0 else prepared['arm'] + '_verifier'
            inventory.append({'attempt_key': attempt['attempt_key'], 'model': copy.deepcopy(plan['models'][role]),
                'attempt_artifact_sha256': attempt['attempt_artifact']['sha256'],
                'usage': {key: attempt['usage'].get(key) for key in ('input_tokens', 'output_tokens')}})
    return inventory


def _postcheck(snapshots):
    for path, (before, cap) in snapshots.items():
        if _read_regular(path, cap) != before:
            raise ValueError('Input changed during read-only recomputation')


def _legacy_usage(raw):
    result = []
    for row in raw['rows']:
        for attempt in row.get('attempts', []):
            value = attempt.get('raw')
            if type(value) is dict:
                # Historical observations are not evidence of enforced limits.
                usage = {'input_tokens': value.get('prompt_eval_count'), 'output_tokens': value.get('eval_count')}
                for count in usage.values():
                    if count is not None and (type(count) is not int or count < 0):
                        raise ValueError('Invalid historical usage observation')
                result.append(usage)
            else:
                result.append({'input_tokens': None, 'output_tokens': None})
    return result


def _twins_metrics(raw, prepared, denominator_path, frozen=None, canonical_text=None):
    frozen = review._json(_read_regular(denominator_path, ATTACHMENT_CAP), ATTACHMENT_CAP) if frozen is None else frozen
    if prepared['frozen_denominator_sha256'] != protocol.digest(frozen):
        raise ValueError('Frozen denominator fingerprint mismatch')
    canonical_text = (_read_regular(protocol.canonical_path_for_denominator(denominator_path), ATTACHMENT_CAP)
                      if canonical_text is None else canonical_text)
    protocol.validate_frozen_canonical(frozen, canonical_text)
    payloads, labels = protocol.generate()
    payloads, labels = protocol.select_scope(payloads, labels, prepared['scope_manifest'])
    expected = {p['id']: p['source_sha256'] for p in payloads}
    if {row['id']: row['source_sha256'] for row in prepared['rows']} != expected:
        raise ValueError('Prepared scope differs from frozen synthetic sources')
    eligible = sorted({x['pair_id'] for x in labels if x['vulnerable']} & set(frozen['eligible_pairs']))
    return protocol.metrics(labels, raw['rows'], eligible, raw.get('resource_evidence'), raw.get('implementation'))


def _resource_summary(raw):
    """Expose recorded runner observations without sampling or expanding scope."""
    wall = raw.get('wall_seconds')
    if wall is not None and (type(wall) not in (int, float) or not math.isfinite(wall) or wall < 0):
        raise ValueError('Invalid recorded wall time observation')
    result = runner.measurement.summarize(raw.get('resource_evidence'), raw.get('implementation'))
    result['wall_seconds'] = wall
    return result


def _read_report(raw_path, denominator_path=None, *, include_worksheet=False, review_overlay_path=None, cost_attachment_path=None):
    raw_path = _absolute(raw_path)
    snapshots = {}
    before = _track(raw_path, RAW_CAP, snapshots)
    raw = json.loads(before.decode('utf-8', 'strict'))
    denominator_path = Path(denominator_path) if denominator_path else protocol.ARTIFACTS / 'denominator.json'
    if raw.get('schema') == protocol.SCHEMA:
        if include_worksheet or review_overlay_path is not None or cost_attachment_path is not None:
            raise ValueError('New review/cost attachments are not supported on legacy raw')
        frozen = review._json(_track(denominator_path, ATTACHMENT_CAP, snapshots), ATTACHMENT_CAP)
        if raw['frozen_denominator_sha256'] != protocol.digest(frozen):
            raise ValueError('Legacy frozen denominator mismatch')
        protocol.validate_frozen_canonical(frozen, _track(protocol.canonical_path_for_denominator(denominator_path), ATTACHMENT_CAP, snapshots))
        payloads, labels = protocol.generate()
        scope = raw.get('scope_manifest')
        if scope is not None and raw.get('scope_manifest_sha256') != protocol.digest(scope):
            raise ValueError('Legacy scope hash mismatch')
        payloads, labels = protocol.select_scope(payloads, labels, scope)
        sources = {p['id']: p['source_sha256'] for p in payloads}
        if any(row['id'] not in sources or row['source_sha256'] != sources[row['id']] for row in raw['rows']):
            raise ValueError('Legacy unknown case or source mismatch')
        eligible = sorted({x['pair_id'] for x in labels if x['vulnerable']} & set(frozen['eligible_pairs']))
        result = {'metrics': protocol.metrics(labels, raw['rows'], eligible, raw.get('resource_evidence'), raw.get('implementation')),
                  'raw_sha256': transport.digest(before)}
        result.update(kind='legacy-synthetic-twins-readonly', provider_controls_verified=None,
                      usage_summary=transport.summarize_usage(_legacy_usage(raw)),
                      historical_controls='unknown; never retrofilled from present implementation')
    elif raw.get('schema') == 'formal-experiment-v1':
        raw = review._json(before, RAW_CAP)
        artifacts = _artifact_snapshots(raw, raw_path, snapshots)
        verified = review.validate_derived(before, artifacts, runner_context=runner)
        raw = verified['raw']; prepared = raw['prepared']
        usages = [attempt['usage'] for row in raw['rows'] for attempt in row['attempts']]
        run_debits = sum(attempt['debit'] for row in raw['rows'] for attempt in row['attempts'])
        frozen = None
        canonical_text = None
        if prepared['experiment'] == 'twins':
            frozen = review._json(_track(denominator_path, ATTACHMENT_CAP, snapshots), ATTACHMENT_CAP)
            canonical_text = _track(protocol.canonical_path_for_denominator(denominator_path), ATTACHMENT_CAP, snapshots)
        result = {'kind': 'formal-v1-readonly-recomputed', 'raw_sha256': verified['raw_sha256'],
            'usage_summary': transport.summarize_usage(usages), 'run_debits_recorded': run_debits,
            'run_reserved_output_tokens': run_debits * 1024,
            'batch_totals_recorded': copy.deepcopy(raw.get('budget_totals')), 'batch_ledger_verified': False,
            'provider_controls_verified': None,
            'control_evidence_scope': 'Recorded readiness is a version binding, not independent provenance or billing',
            'resource_summary': _resource_summary(raw),
            'metrics': _twins_metrics(raw, prepared, denominator_path, frozen, canonical_text) if prepared['experiment'] == 'twins' else None,
            'effectiveness': 'unknown pending accepted ground truth/adjudication' if prepared['experiment'] != 'twins' else 'synthetic bounds; no human verdict inferred'}
        if include_worksheet or review_overlay_path is not None:
            worksheet = review.build_worksheet(before, artifacts, runner_context=runner)
            if review_overlay_path is not None:
                data = _track(review_overlay_path, ATTACHMENT_CAP, snapshots)
                overlay = review._json(data, ATTACHMENT_CAP)
                worksheet = review.apply_overlay(worksheet, overlay)
                result['review_overlay_sha256'] = transport.digest(data)
            result['review_worksheet'] = worksheet
        attachment = None; attachment_sha = None
        if cost_attachment_path is not None:
            data = _track(cost_attachment_path, ATTACHMENT_CAP, snapshots)
            attachment = review._json(data, ATTACHMENT_CAP); attachment_sha = transport.digest(data)
        result['cost_summary'] = cost.summarize_cost(verified['raw_sha256'], _cost_inventory(raw),
            attachment, attachment_sha256=attachment_sha)
    else:
        raise ValueError('Only historical synthetic twins and formal-v1 are supported')
    _postcheck(snapshots)
    if type(result.get('metrics')) is dict:
        result = {**result, 'uncertainty': uncertainty.adjudication_uncertainty(result['metrics'])}
    return result


def read_report(raw_path, denominator_path=None, *, include_worksheet=False, review_overlay_path=None, cost_attachment_path=None):
    """Reject malformed snapshots without converting annotations into metrics."""
    try:
        return _read_report(raw_path, denominator_path, include_worksheet=include_worksheet,
                            review_overlay_path=review_overlay_path, cost_attachment_path=cost_attachment_path)
    except (KeyError, TypeError, AttributeError, RecursionError, OverflowError, UnicodeError) as error:
        raise ValueError('Malformed report snapshot: ' + type(error).__name__) from error


def main(argv=None):
    parser = argparse.ArgumentParser(); parser.add_argument('--raw', type=Path, required=True)
    parser.add_argument('--denominator', type=Path); parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--worksheet', action='store_true')
    parser.add_argument('--review-overlay', type=Path); parser.add_argument('--cost-attachment', type=Path)
    args = parser.parse_args(argv)
    result = read_report(args.raw, args.denominator, include_worksheet=args.worksheet,
                         review_overlay_path=args.review_overlay, cost_attachment_path=args.cost_attachment)
    transport.write_new(args.output, result)


if __name__ == '__main__': main()
