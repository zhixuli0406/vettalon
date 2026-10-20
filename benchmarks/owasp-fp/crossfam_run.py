#!/usr/bin/env python3
"""O13 runner: the cross-family matrix on owasp-fp, with a hard call ledger.

  python3 crossfam_run.py reanalyze [--out FILE]        # stored results, 0 calls
  python3 crossfam_run.py plan [--arms FILE] [--out FILE]
  python3 crossfam_run.py dry-run --out-dir DIR [--arms FILE] [--budget N]
  python3 crossfam_run.py analyze RECORDS.json [--arms FILE]
  python3 crossfam_run.py execute ...                   # refuses without approval

`dry-run` drives the real scheduler, ledger and report parser with a fake
model that writes vettalon-shaped reports and traces; no process starts.
`execute` stays closed until the owner signs an approval bound to the plan
hash (D01) and the roster passes the per-call checks.
"""
import argparse
import datetime
import hashlib
import json
import random
import re
import subprocess
import sys
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import crossfam as xf  # noqa: E402

DEFAULT_ARMS = HERE / 'crossfam.arms.example.json'
SAMPLE = HERE / 'reports' / 'sample.json'
APPROVAL_SCHEMA = 'owasp-xfam-approval-v1'
SEVERITY_MULTI_RUN = ('high', 'critical')


class BudgetHalt(RuntimeError):
    """A scan used more calls than its reservation: stop, keep what exists."""


class Ledger:
    """Calls are reserved per case row before any scan and settled after."""

    def __init__(self, budget):
        if type(budget) is not int or budget < 0:
            raise ValueError('budget must be a non-negative integer')
        self.budget, self.spent = budget, 0

    def remaining(self):
        return self.budget - self.spent

    def fits(self, calls):
        return calls <= self.remaining()

    def debit(self, calls):
        if calls > self.remaining():
            raise BudgetHalt('debit beyond budget')
        self.spent += calls


def stratified_order(cases):
    """Round-robin over the (category, TP/FP) cells, so any prefix stays balanced."""
    cells = {}
    for case in cases:
        cells.setdefault((case['cat'], case['real']), []).append(case)
    keys = sorted(cells, key=lambda k: (k[0], not k[1]))
    out = []
    for i in range(max(len(v) for v in cells.values())):
        out += [cells[k][i] for k in keys if i < len(cells[k])]
    return out


def schedule(cases, arms, seed=0):
    """Case-major order: every arm runs case i before any arm runs case i+1, so a
    budget stop truncates all arms at the same case and pairs stay aligned. Cases
    are stratified round-robin; arm order inside a case is shuffled (seeded)
    against time-of-run drift."""
    rng = random.Random(seed)
    out = []
    for case in stratified_order(cases):
        order = list(arms)
        rng.shuffle(order)
        out.append((case, order))
    return out


def count_calls(trace_lines):
    """Calls by step from a vettalon --trace JSONL text."""
    counts = {}
    for line in trace_lines.splitlines():
        if line.strip():
            step = json.loads(line)['step']
            counts[step] = counts.get(step, 0) + 1
    return counts


def run_matrix(arms_cfg, cases, scanner, out_dir, budget, seed=0, max_cases=None):
    """Scan every (case, arm) within `budget` calls and at most `max_cases` case
    rows. Each record is appended to records.jsonl as soon as it exists, so a
    halt never loses records of calls already paid for."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ledger = Ledger(budget)
    f_cap, v_cap = xf.calls_cap_per_case(arms_cfg['refuter_runs'])
    case_cap = f_cap + v_cap
    records, stop_reason, halt = [], None, None
    with open(out_dir / 'records.jsonl', 'w') as log:
        def keep(record):
            records.append(record)
            log.write(json.dumps(record, sort_keys=True) + '\n')
            log.flush()
        for i, (case, order) in enumerate(schedule(cases, arms_cfg['arms'], seed)):
            if stop_reason is None and max_cases is not None and i >= max_cases:
                stop_reason = 'max_cases_reached'
            if stop_reason is None and not ledger.fits(case_cap * len(order)):
                stop_reason = 'budget_exhausted'
            for arm in order:
                if stop_reason:
                    keep(_not_run(case, arm, stop_reason))
                    continue
                try:
                    keep(_scan_one(case, arm, scanner, out_dir, ledger, case_cap))
                except BudgetHalt as exc:
                    keep(dict(_not_run(case, arm, str(exc)), outcome='infra_error'))
                    stop_reason, halt = 'halted_over_ceiling', exc
    result = {'schema': xf.RECORDS_SCHEMA, 'records': records,
              'ledger': {'budget': budget, 'spent': ledger.spent, 'stop_reason': stop_reason,
                         'case_ceiling': case_cap, 'max_cases': max_cases}}
    if halt is not None:
        (out_dir / 'records.partial.json').write_text(json.dumps(result, indent=1, sort_keys=True))
        raise halt
    return result


def _not_run(case, arm, why):
    return {'case': case['id'], 'cat': case['cat'], 'real': case['real'], 'arm': arm['id'],
            'finder_pos': False, 'outcome': 'not_run', 'rationale': None, 'reason': why, 'calls': {}}


def _scan_one(case, arm, scanner, out_dir, ledger, case_cap):
    base = out_dir / arm['id'].replace('>', '_to_').replace('=', '_self') / case['id']
    base.mkdir(parents=True, exist_ok=True)
    report_path, trace_path = base / 'report.json', base / 'trace.jsonl'
    exit_code = scanner.scan(case, arm, report_path, trace_path)
    try:
        calls = count_calls(trace_path.read_text())
    except (OSError, ValueError, KeyError):
        ledger.debit(case_cap)  # unknown usage: charge the full ceiling
        return dict(_not_run(case, arm, 'trace_unreadable'), outcome='infra_error')
    used = sum(calls.values())
    # Charge what was used before deciding anything, so an overshoot is on the books.
    ledger.spent += used
    if used > case_cap or calls.get('poc') or ledger.spent > ledger.budget:
        raise BudgetHalt(f'{arm["id"]}/{case["id"]}: {calls} exceeds the per-case ceiling or budget')
    try:
        report = json.loads(report_path.read_text())
        record = xf.classify_report(report, case, arm)
    except (OSError, ValueError) as exc:
        return dict(_not_run(case, arm, f'report_unusable (exit {exit_code}): {exc}'),
                    outcome='infra_error', calls=calls)
    return dict(record, calls=calls, exit_code=exit_code)


# ── fake model (dry run) ─────────────────────────────────────────────────

# Synthetic behaviour per family; only exercises the pipeline, never evidence.
FAKE_FINDER = {'fam_a': (0.95, 0.05), 'fam_b': (0.80, 0.30)}      # P(flag | TP), P(flag | FP)
FAKE_REFUTER = {'fam_a': (0.06, 0.92), 'fam_b': (0.12, 0.70)}     # P(refute run | TP), P(refute run | FP)


class FakeScanner:
    """Writes vettalon-shaped report.json + trace.jsonl from seeded draws."""

    def __init__(self, arms_cfg, seed=0):
        self.models, self.runs, self.seed = arms_cfg['models'], arms_cfg['refuter_runs'], seed
        families = sorted({m['family'] for m in self.models.values()})
        self.profile = dict(zip(families, ('fam_a', 'fam_b')))
        self.scans = 0

    def _u(self, *parts):
        digest = hashlib.sha256('|'.join(map(str, (self.seed, *parts))).encode()).digest()
        return int.from_bytes(digest[:8], 'big') / 2 ** 64

    def scan(self, case, arm, report_path, trace_path):
        self.scans += 1
        ff, rf = (self.models[arm[k]]['family'] for k in ('finder', 'refuter'))
        trace = [self._event('audit', arm['finder'], ff)]
        if self._u(arm['id'], case['id'], 'reflector') < 0.05:
            trace.append(self._event('audit', arm['finder'], ff))
        p_tp, p_fp = FAKE_FINDER[self.profile[ff]]
        findings = []
        if self._u(arm['id'], case['id'], 'flag') < (p_tp if case['real'] else p_fp):
            findings.append(self._finding(case, arm, ff, rf, case['expect_class'], 'high', trace))
        if self._u(arm['id'], case['id'], 'extra') < 0.25:
            findings.append(self._finding(case, arm, ff, rf, 'info-leak', 'medium', trace))
        report_path.write_text(json.dumps({'findings': findings}))
        trace_path.write_text(''.join(json.dumps(e) + '\n' for e in trace))
        return 0

    def _event(self, step, model, family):
        return {'step': step, 'model': model, 'family': family, 'prompt_bytes': 4000,
                'reply_bytes': 600, 'latency_ms': 1, 'outcome': 'ok'}

    def _finding(self, case, arm, ff, rf, cls, severity, trace):
        n = self.runs if severity in SEVERITY_MULTI_RUN else 1
        p_kill = FAKE_REFUTER[self.profile[rf]][0 if case['real'] else 1]
        votes, evidence = [], []
        for i in range(n):
            trace.append(self._event('verify', arm['refuter'], rf))
            draw = self._u(arm['id'], case['id'], cls, i)
            verdict = 'no_verdict' if draw > 0.99 else ('refuted' if draw < p_kill else 'plausible')
            votes.append({'model': arm['refuter'], 'family': rf, 'verdict': verdict,
                          'cross_family': ff != rf, 'same_model': arm['finder'] == arm['refuter']})
        verdicts = [v['verdict'] for v in votes]
        if all(v == 'plausible' for v in verdicts):
            status = 'needs_human'
        elif all(v == 'refuted' for v in verdicts):
            status = 'refuted'
            evidence.append({'kind': 'adversarial_review', 'source': 'verify',
                             'detail': 'refuted: input is replaced by a constant before the sink'})
        else:
            status = 'candidate'
            if 'no_verdict' not in verdicts:
                k = verdicts.count('plausible')
                evidence.append({'kind': 'verify_uncertain', 'source': 'verify',
                                 'detail': f'verify_uncertain: {k}/{n} plausible'})
        return {'source_engine': 'ai_audit', 'rule_id': f'ai/{cls}', 'severity': severity,
                'status': status, 'found_by': [arm['finder']], 'verification': votes,
                'evidence': evidence}


# ── real scanner (gated) ─────────────────────────────────────────────────


def roster_findings(roster_text, arms_cfg):
    """D01 per-call checks on the roster for every model the arms use."""
    roster = tomllib.loads(roster_text)
    by_id = {m.get('id'): m for m in roster.get('model', [])}
    problems = []
    for mid, meta in arms_cfg['models'].items():
        m = by_id.get(mid)
        if m is None:
            problems.append(f'{mid}: not in roster')
            continue
        if m.get('backend') not in ('openai', 'ollama'):
            problems.append(f'{mid}: backend {m.get("backend")!r} cannot enforce the output cap')
        if type(m.get('max_tokens')) is not int or not 0 < m['max_tokens'] <= xf.D01_OUTPUT_TOKENS_PER_CALL:
            problems.append(f'{mid}: max_tokens must be set and <= {xf.D01_OUTPUT_TOKENS_PER_CALL}')
        if type(m.get('timeout_secs')) is not int or not 0 < m['timeout_secs'] <= xf.D01_TIMEOUT_SECONDS:
            problems.append(f'{mid}: timeout_secs must be set and <= {xf.D01_TIMEOUT_SECONDS}')
        if m.get('family') != meta['family']:
            problems.append(f'{mid}: roster family {m.get("family")!r} != arms family {meta["family"]!r}')
    return problems


def approval_findings(approval, plan, today=None):
    """Why an approval does not authorize this exact plan (empty = authorized)."""
    today = today or datetime.date.today().isoformat()
    if type(approval) is not dict or approval.get('schema') != APPROVAL_SCHEMA:
        return [f'approval needs schema {APPROVAL_SCHEMA}']
    problems = []
    if approval.get('plan_sha256') != plan['plan_sha256']:
        problems.append('approval is bound to a different plan')
    calls = approval.get('max_calls')
    if type(calls) is not int or not 0 < calls <= plan['total']['calls_cap']:
        problems.append('max_calls must be a positive integer within the plan ceiling')
    accepted = approval.get('accepted_blockers', [])
    if type(accepted) is not list or not all(type(b) is str for b in accepted):
        return problems + ['accepted_blockers must be a list of blocker ids']
    accepted = set(accepted)
    cases = approval.get('max_cases')
    if type(cases) is not int or not 0 < cases <= plan['total']['cases'] // len(plan['arms']):
        problems.append('max_cases must be a positive integer within the plan case count')
    expires = approval.get('expires_on')
    if type(expires) is not str or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', expires) or expires < today:
        problems.append('approval needs an expires_on date (YYYY-MM-DD) that has not passed')
    for b in plan['blockers']:
        if b['owner_can_accept'] and b['id'] not in accepted:
            problems.append(f'blocker {b["id"]} not accepted')
    for field in ('approved_by', 'approved_on'):
        if not approval.get(field):
            problems.append(f'approval needs {field}')
    return problems


class VettalonScanner:
    """One `vettalon scan` per (case, arm). Built only after every gate passed."""

    def __init__(self, binary, roster, cases_dir, refuter_runs):
        self.binary, self.roster, self.cases_dir, self.runs = binary, roster, Path(cases_dir), refuter_runs

    def command(self, case, arm, report_path, trace_path):
        f_cap, v_cap = xf.calls_cap_per_case(self.runs)
        return [str(self.binary), 'scan', str(self.cases_dir / case['id']), '--profile', 'deep',
                '--config', str(self.roster), '--finders', arm['finder'], '--verifiers', arm['refuter'],
                '--max-modules', '1', '--cross-check-top', '0', '--refuter-runs', str(self.runs),
                '--time-budget', str((f_cap + v_cap) * xf.D01_TIMEOUT_SECONDS),
                '--report', str(report_path), '--trace', str(trace_path), '--no-prior', '--fail-on', 'none']

    def scan(self, case, arm, report_path, trace_path):
        cmd = self.command(case, arm, report_path, trace_path)
        with open(report_path.with_suffix('.log'), 'w') as log:
            return subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, check=False).returncode


# ── CLI ──────────────────────────────────────────────────────────────────


def _load_json(path):
    return json.loads(Path(path).read_text())


def _write(obj, out):
    text = json.dumps(obj, indent=1, sort_keys=True, ensure_ascii=False) + '\n'
    if out:
        Path(out).write_text(text)
    else:
        sys.stdout.write(text)


def _cases():
    return _load_json(SAMPLE)


def cmd_execute(args):
    arms_cfg = xf.load_arms(_load_json(args.arms))
    cases = _cases()
    plan = xf.build_plan(arms_cfg, len(cases))
    problems = [f'missing {flag}' for flag, value in (('--cases-dir', args.cases_dir),
                ('--out-dir', args.out_dir), ('--vettalon-bin', args.vettalon_bin)) if not value]
    if not args.approval or not Path(args.approval).is_file():
        problems.append('no owner approval file: D01 keeps formal model calls at 0')
    else:
        problems += approval_findings(_load_json(args.approval), plan)
    if not args.roster or not Path(args.roster).is_file():
        problems.append('no roster')
    else:
        problems += roster_findings(Path(args.roster).read_text(), arms_cfg)
    if problems:
        sys.stderr.write('execute refused (0 model calls):\n' + ''.join(f'  - {p}\n' for p in problems))
        return 2
    approval = _load_json(args.approval)
    scanner = VettalonScanner(args.vettalon_bin, args.roster, args.cases_dir, arms_cfg['refuter_runs'])
    result = run_matrix(arms_cfg, cases, scanner, args.out_dir, approval['max_calls'],
                        max_cases=approval['max_cases'])
    _write(dict(result, plan_sha256=plan['plan_sha256']), Path(args.out_dir) / 'records.json')
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='cmd', required=True)
    r = sub.add_parser('reanalyze')
    r.add_argument('--out')
    pl = sub.add_parser('plan')
    pl.add_argument('--arms', default=DEFAULT_ARMS)
    pl.add_argument('--out')
    d = sub.add_parser('dry-run')
    d.add_argument('--arms', default=DEFAULT_ARMS)
    d.add_argument('--out-dir', required=True)
    d.add_argument('--budget', type=int)
    d.add_argument('--seed', type=int, default=0)
    a = sub.add_parser('analyze')
    a.add_argument('records')
    a.add_argument('--arms', default=DEFAULT_ARMS)
    e = sub.add_parser('execute')
    for flag in ('--arms', '--roster', '--approval', '--cases-dir', '--out-dir', '--vettalon-bin'):
        e.add_argument(flag, default=DEFAULT_ARMS if flag == '--arms' else None)
    args = p.parse_args(argv)

    if args.cmd == 'reanalyze':
        _write(xf.reanalyze(HERE / 'reports'), args.out)
    elif args.cmd == 'plan':
        _write(xf.build_plan(xf.load_arms(_load_json(args.arms)), len(_cases())), args.out)
    elif args.cmd == 'dry-run':
        arms_cfg = xf.load_arms(_load_json(args.arms))
        cases = _cases()
        budget = args.budget if args.budget is not None else xf.build_plan(arms_cfg, len(cases))['total']['calls_cap']
        result = run_matrix(arms_cfg, cases, FakeScanner(arms_cfg, args.seed), args.out_dir, budget, args.seed)
        result['model_calls'] = 0
        result['fake_model'] = True
        _write(result, Path(args.out_dir) / 'records.json')
        _write(xf.analyze(arms_cfg, result['records']), Path(args.out_dir) / 'analysis.json')
        sys.stdout.write(f'dry run: {len(result["records"])} records, fake calls {result["ledger"]["spent"]}, '
                         f'real model calls 0 -> {args.out_dir}\n')
    elif args.cmd == 'analyze':
        _write(xf.analyze(xf.load_arms(_load_json(args.arms)), _load_json(args.records)['records']), None)
    elif args.cmd == 'execute':
        return cmd_execute(args)
    return 0


if __name__ == '__main__':
    sys.exit(main())
