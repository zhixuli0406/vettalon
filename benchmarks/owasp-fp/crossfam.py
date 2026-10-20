"""O13: does cross-family review help? Arms, outcomes, metrics and the run plan.

Pure functions over saved data. Stdlib only. Nothing here starts a process or
calls a model; `crossfam_run.py` drives scans and its real path stays gated.

Design (owasp-fp, 160 cases = 80 TP + 80 FP):

* 2x2 finder family x refuter family. The diagonal cells use a *different*
  model of the same family, so "same family" and "same model" are separate.
* Same-model fresh-session arms: the finder reviews its own finding in a new
  call (vettalon's single-model fallback; every HTTP call is stateless).
* Per arm: recall, FP rate, uncertain rate, flip rate (refuter overturns the
  finder) and flip correctness, with intervals from benchmarks/common/stats.py.
* Between arms: error-overlap Jaccard, finder agreement, directionality (who
  reviews whom) and item-paired differences for the pre-registered contrasts.
"""
import hashlib
import importlib.util
import json
import re
import sys
from itertools import combinations
from pathlib import Path

ARMS_SCHEMA = 'owasp-xfam-arms-v1'
RECORDS_SCHEMA = 'owasp-xfam-records-v1'
PLAN_SCHEMA = 'owasp-xfam-plan-v1'

ARM_ID = re.compile(r'[A-Za-z0-9_-]{1,16}(>[A-Za-z0-9_-]{1,16}=?)?')
KINDS = ('cross_family', 'same_family', 'same_model_fresh')
# A finding the refuter overturned. `not_survived` is the legacy reading of a
# stored boolean: refuted, verify error and unreviewed cannot be told apart.
FLIP_OUTCOMES = ('refuted', 'not_survived')
OUTCOMES = ('survived', 'refuted', 'uncertain', 'verify_error', 'not_survived', 'precheck_refuted',
            'not_flagged', 'not_run', 'arm_mismatch', 'infra_error')
# Kept in every denominator, but not comparable between arms.
UNSCANNED = ('not_run', 'arm_mismatch', 'infra_error')
# When one case has several matching findings, the case takes the best one.
# `precheck_refuted`: refuted with no refuter vote (local pre-check or the
# zero-LLM path), so it counts against recall but is not a refuter flip.
OUTCOME_PRIORITY = ('survived', 'uncertain', 'verify_error', 'refuted', 'precheck_refuted')

# Product caps mirrored from crates/vettalon/src/audit (a test reads the Rust
# source and fails if they drift).
MAX_CANDIDATES_PER_MODULE = 8
AI_AUDIT_PARSE_RETRIES = 1
MAX_REFUTER_RUNS = 5
MODULE_PROMPT_BUDGET_BYTES = 48 * 1024
VERIFIER_FILE_BUDGET_BYTES = 24 * 1024
# Each case directory holds one Java file, and a single file is one page.
PAGES_PER_CASE = 1

# D01 per-call ceilings for any formal model run.
D01_OUTPUT_TOKENS_PER_CALL = 1024
D01_TIMEOUT_SECONDS = 90
D01_AUTOMATIC_RETRIES = 0

PLANNED_EFFECT = (0.20, 0.30)

RATIONALE_KEYWORDS = (
    ('deployment_context', ('authenticat', 'authoriz', 'deploy', 'exposure', 'exposed',
                            'endpoint is', 'base path', 'reverse proxy')),
    ('guarded', ('sanitiz', 'escap', 'parameteriz', 'prepared statement', 'allow-list',
                 'allowlist', 'whitelist', 'validat', 'encod', 'normaliz')),
    ('constant_or_dead_flow', ('constant', 'hard-coded', 'hardcoded', 'dead code', 'unreachable',
                               'never reach', 'overwritten', 'not attacker', 'not user-controlled',
                               'always ')),
    ('not_dangerous', ('not dangerous', 'safe sink', 'harmless', 'no impact')),
)


def stats():
    """benchmarks/common/stats.py, loaded by path like the other runners."""
    key = 'vettalon_eval_common_stats'
    if key not in sys.modules:
        path = Path(__file__).resolve().parents[1] / 'common' / 'stats.py'
        if not path.is_file():
            raise RuntimeError(f'{path} is missing: it lands with the O12 eval-protocol change; '
                               'rebase onto a main that has it')
        spec = importlib.util.spec_from_file_location(key, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[key] = module
        spec.loader.exec_module(module)
    return sys.modules[key]


# ── arms ────────────────────────────────────────────────────────────────


def arm_kind(finder, refuter, models):
    if finder == refuter:
        return 'same_model_fresh'
    if models[finder]['family'] == models[refuter]['family']:
        return 'same_family'
    return 'cross_family'


def load_arms(cfg):
    """Validate an arms config and return it with each arm's kind and families."""
    if type(cfg) is not dict or cfg.get('schema') != ARMS_SCHEMA:
        raise ValueError(f'arms config needs schema {ARMS_SCHEMA}')
    models, arms, runs = cfg.get('models'), cfg.get('arms'), cfg.get('refuter_runs')
    if type(models) is not dict or not models:
        raise ValueError('models must be a non-empty {id: {family}} map')
    for mid, m in models.items():
        if type(m) is not dict or type(m.get('family')) is not str or not m['family']:
            raise ValueError(f'model {mid!r} needs a family')
    if type(runs) is not int or not 1 <= runs <= MAX_REFUTER_RUNS:
        raise ValueError(f'refuter_runs must be 1..{MAX_REFUTER_RUNS}')
    if type(arms) is not list or not arms:
        raise ValueError('arms must be a non-empty list')
    out, seen = [], set()
    for a in arms:
        if type(a) is not dict or set(a) != {'id', 'finder', 'refuter'}:
            raise ValueError('each arm is exactly {id, finder, refuter}')
        if type(a['id']) is not str or not ARM_ID.fullmatch(a['id']):
            raise ValueError(f'arm id {a["id"]!r} must match {ARM_ID.pattern}')
        if a['id'] in seen:
            raise ValueError(f'duplicate arm id {a["id"]!r}')
        seen.add(a['id'])
        for role in ('finder', 'refuter'):
            if a[role] not in models:
                raise ValueError(f'arm {a["id"]!r}: unknown {role} {a[role]!r}')
        out.append(dict(a, kind=arm_kind(a['finder'], a['refuter'], models),
                        finder_family=models[a['finder']]['family'],
                        refuter_family=models[a['refuter']]['family']))
    pairs = [(a['finder'], a['kind']) for a in out]
    if len(pairs) != len(set(pairs)):
        raise ValueError('one arm per (finder, refuter kind), so each contrast is unambiguous')
    _check_design(out)
    return {'schema': ARMS_SCHEMA, 'models': models, 'refuter_runs': runs, 'arms': out}


def _check_design(arms):
    """The matrix must hold a full 2x2 of families plus a fresh-session arm."""
    families = sorted({a['finder_family'] for a in arms} | {a['refuter_family'] for a in arms})
    if len(families) != 2:
        raise ValueError('the 2x2 needs exactly two model families')
    for ff in families:
        for rf in families:
            kinds = {a['kind'] for a in arms if (a['finder_family'], a['refuter_family']) == (ff, rf)}
            want = 'cross_family' if ff != rf else 'same_family'
            if want not in kinds:
                raise ValueError(f'2x2 cell {ff}->{rf} needs a {want} arm')
    if not any(a['kind'] == 'same_model_fresh' for a in arms):
        raise ValueError('the design needs at least one same-model fresh-session arm')


# ── outcome of one scan ───────────────────────────────────────────────────


def rationale_category(reason):
    """Keyword bucket for a refutation reason. Derived text match, not the
    model's refute_basis (the report does not persist that field)."""
    text = (reason or '').lower()
    if not text:
        return 'not_recorded'
    for name, words in RATIONALE_KEYWORDS:
        if any(w in text for w in words):
            return name
    return 'other'


def _finding_outcome(f):
    status = f.get('status')
    if status == 'needs_human':
        return 'survived'
    if status == 'refuted':
        # No refuter vote: the local pre-check (source "precheck") or the
        # zero-LLM path refuted it before any refuter call.
        return 'refuted' if f.get('verification') else 'precheck_refuted'
    if status == 'candidate':
        kinds = {e.get('kind') for e in f.get('evidence', []) if type(e) is dict}
        return 'uncertain' if 'verify_uncertain' in kinds else 'verify_error'
    raise ValueError(f'unexpected finding status {status!r} from an automated scan')


def _refute_reason(f):
    for e in reversed(f.get('evidence', [])):
        detail = e.get('detail', '') if type(e) is dict else ''
        if detail.startswith('refuted: '):
            return detail[len('refuted: '):]
    return None


def _votes_match_arm(f, arm):
    """Every recorded vote came from the arm's refuter with the arm's independence."""
    for v in f.get('verification', []):
        if v.get('model') != arm['refuter']:
            return False
        if arm['kind'] == 'cross_family' and v.get('cross_family') is not True:
            return False
        if arm['kind'] == 'same_family' and (v.get('cross_family') or v.get('same_model')):
            return False
        if arm['kind'] == 'same_model_fresh' and v.get('same_model') is not True:
            return False
    return f.get('found_by', [arm['finder']]) == [arm['finder']]


def classify_report(report, case, arm):
    """One (case, arm) record from a vettalon JSON report."""
    base = {'case': case['id'], 'cat': case['cat'], 'real': case['real'], 'arm': arm['id'],
            'finder_pos': False, 'outcome': 'not_flagged', 'rationale': None, 'reason': None}
    findings = [f for f in report.get('findings', [])
                if f.get('source_engine') == 'ai_audit' and case['expect_class'] in f.get('rule_id', '')]
    if not findings:
        return base
    if not all(_votes_match_arm(f, arm) for f in findings):
        return dict(base, finder_pos=True, outcome='arm_mismatch')
    best = min(findings, key=lambda f: OUTCOME_PRIORITY.index(_finding_outcome(f)))
    outcome = _finding_outcome(best)
    reason = _refute_reason(best) if outcome == 'refuted' else None
    return dict(base, finder_pos=True, outcome=outcome, reason=reason,
                rationale=rationale_category(reason) if outcome == 'refuted' else None)


# ── metrics ─────────────────────────────────────────────────────────────


def _rate(k, n):
    return stats().rate(k, n)


def arm_metrics(recs, boolean_outcomes=False):
    """Rates for one arm. `boolean_outcomes` marks legacy data where only
    survived / not survived was stored, so uncertain and error are unknown."""
    tp = [r for r in recs if r['real']]
    fp = [r for r in recs if not r['real']]
    reviewed = [r for r in recs if r['finder_pos'] and r['outcome'] not in UNSCANNED + ('precheck_refuted',)]
    flips = [r for r in reviewed if r['outcome'] in FLIP_OUTCOMES]
    count = lambda items, pred: sum(1 for r in items if pred(r))
    survived = lambda r: r['outcome'] == 'survived'
    out = {
        'n_cases': len(recs), 'n_tp': len(tp), 'n_fp': len(fp),
        'not_run': count(recs, lambda r: r['outcome'] == 'not_run'),
        'arm_mismatch': count(recs, lambda r: r['outcome'] == 'arm_mismatch'),
        'infra_error': count(recs, lambda r: r['outcome'] == 'infra_error'),
        'precheck_refuted': count(recs, lambda r: r['outcome'] == 'precheck_refuted'),
        'finder_recall': _rate(count(tp, lambda r: r['finder_pos']), len(tp)),
        'finder_fp_rate': _rate(count(fp, lambda r: r['finder_pos']), len(fp)),
        'recall': _rate(count(tp, survived), len(tp)),
        'fp_rate': _rate(count(fp, survived), len(fp)),
        'flip_rate': _rate(len(flips), len(reviewed)),
        'flip_correctness': _rate(count(flips, lambda r: not r['real']), len(flips)),
        'wrong_kill_rate': _rate(count(flips, lambda r: r['real']),
                                 count(reviewed, lambda r: r['real'])),
        'fp_catch_rate': _rate(count(flips, lambda r: not r['real']),
                               count(reviewed, lambda r: not r['real'])),
        'uncertain_rate': None, 'verify_error_rate': None,
        'flip_definition': 'not needs_human after the finder flagged (refuted, error or unreviewed)'
                           if boolean_outcomes else 'status refuted after the finder flagged',
    }
    if not boolean_outcomes:
        out['uncertain_rate'] = _rate(count(reviewed, lambda r: r['outcome'] == 'uncertain'), len(reviewed))
        out['verify_error_rate'] = _rate(count(reviewed, lambda r: r['outcome'] == 'verify_error'),
                                         len(reviewed))
    rationale = {}
    for r in flips:
        key = r.get('rationale') or 'not_recorded'
        side = 'wrong' if r['real'] else 'correct'
        rationale.setdefault(key, {'correct': 0, 'wrong': 0})[side] += 1
    out['flip_rationale'] = dict(sorted(rationale.items()))
    scanned_tp = [r for r in tp if r['outcome'] not in UNSCANNED]
    scanned_fp = [r for r in fp if r['outcome'] not in UNSCANNED]
    out['scanned'] = {'recall': _rate(count(scanned_tp, survived), len(scanned_tp)),
                      'fp_rate': _rate(count(scanned_fp, survived), len(scanned_fp)),
                      'finder_recall': _rate(count(scanned_tp, lambda r: r['finder_pos']), len(scanned_tp)),
                      'finder_fp_rate': _rate(count(scanned_fp, lambda r: r['finder_pos']), len(scanned_fp)),
                      'note': 'same rates on scanned cases only; headline rates keep unscanned cases in n'}
    return out


def _by_case(recs):
    return {r['case']: r for r in recs}


def _comparable(a, b):
    """Case ids both arms actually scanned (budget stops and mismatches excluded)."""
    return sorted(c for c in set(a) & set(b) if a[c]['outcome'] not in UNSCANNED and b[c]['outcome'] not in UNSCANNED)


def final_errors(recs, ids):
    return {c for c in ids if (recs[c]['outcome'] == 'survived') != recs[c]['real']}


def refuter_errors(recs, ids):
    """Wrong review decisions: a true finding overturned, or a false one kept."""
    out = set()
    for c in ids:
        r = recs[c]
        if not r['finder_pos']:
            continue
        if (r['real'] and r['outcome'] in FLIP_OUTCOMES) or (not r['real'] and r['outcome'] == 'survived'):
            out.add(c)
    return out


def jaccard(a, b):
    union = a | b
    return {'intersection': len(a & b), 'union': len(union),
            'jaccard': len(a & b) / len(union) if union else None}


def pair_overlap(recs_a, recs_b):
    a, b = _by_case(recs_a), _by_case(recs_b)
    ids = _comparable(a, b)
    fa, fb = ({c for c in ids if x[c]['finder_pos']} for x in (a, b))
    return {'n_compared': len(ids),
            'final_error_overlap': jaccard(final_errors(a, ids), final_errors(b, ids)),
            'refuter_error_overlap': jaccard(refuter_errors(a, ids), refuter_errors(b, ids)),
            'finder_positive_overlap': jaccard(fa, fb)}


def paired_contrast(recs_a, recs_b):
    """Item-paired survived-rate difference (b - a) on TP and on FP cases."""
    s = stats()
    a, b = _by_case(recs_a), _by_case(recs_b)
    ids = _comparable(a, b)
    out = {'n_compared': len(ids)}
    for label, real in (('recall_on_true_cases', True), ('fp_rate_on_false_cases', False)):
        items = [c for c in ids if a[c]['real'] is real]
        if not items:
            out[label] = None
            continue
        arm_a = {c: a[c]['outcome'] == 'survived' for c in items}
        arm_b = {c: b[c]['outcome'] == 'survived' for c in items}
        out[label] = dict(s.paired_difference(arm_a, arm_b),
                          power=s.power_label(len(items), *PLANNED_EFFECT))
        # Refuter-only view: cases both arms' finders flagged, so finder noise drops out.
        both = [c for c in items if a[c]['finder_pos'] and b[c]['finder_pos']]
        out['refuter_only_' + label] = None if not both else dict(
            s.paired_difference({c: arm_a[c] for c in both}, {c: arm_b[c] for c in both}),
            power=s.power_label(len(both), *PLANNED_EFFECT))
    return out


def planned_contrasts(arms):
    """Pre-registered contrasts: same finder, refuter kind changes."""
    out = []
    for finder in sorted({a['finder'] for a in arms}):
        group = {a['kind']: a['id'] for a in arms if a['finder'] == finder}
        for x, y in (('same_family', 'cross_family'), ('same_model_fresh', 'cross_family'),
                     ('same_model_fresh', 'same_family')):
            if x in group and y in group:
                out.append({'finder': finder, 'a': group[x], 'b': group[y], 'question': f'{y} minus {x}'})
    return out


def directionality(arms, metrics):
    """Who reviews whom: refuter-level rates for every finder->refuter family cell.
    Different finders feed each cell, so cells are compared descriptively only."""
    rows = []
    for a in arms:
        m = metrics[a['id']]
        rows.append({'arm': a['id'], 'kind': a['kind'], 'finder_family': a['finder_family'],
                     'refuter_family': a['refuter_family'],
                     'wrong_kill_rate': m['wrong_kill_rate'], 'fp_catch_rate': m['fp_catch_rate'],
                     'flip_correctness': m['flip_correctness']})
    return {'cells': rows, 'note': 'unpaired across finders: descriptive, no significance claim'}


def analyze(arms_cfg, records):
    """Full matrix analysis over records from crossfam_run (dry or real)."""
    arms = arms_cfg['arms']
    by_arm = {a['id']: [r for r in records if r['arm'] == a['id']] for a in arms}
    unknown = {r['arm'] for r in records} - set(by_arm)
    if unknown:
        raise ValueError(f'records for arms not in the config: {sorted(unknown)}')
    case_sets = set()
    for aid, recs in by_arm.items():
        if not recs or len({r['case'] for r in recs}) != len(recs):
            raise ValueError(f'arm {aid!r} has no records or a duplicate case')
        case_sets.add(frozenset(r['case'] for r in recs))
    if len(case_sets) != 1:
        raise ValueError('arms cover different case sets; a run must keep every case in every arm')
    metrics = {aid: arm_metrics(recs) for aid, recs in by_arm.items()}
    overlaps = {f'{x}|{y}': pair_overlap(by_arm[x], by_arm[y]) for x, y in combinations(sorted(by_arm), 2)}
    contrasts = [dict(c, result=paired_contrast(by_arm[c['a']], by_arm[c['b']])) for c in planned_contrasts(arms)]
    return {'arms': {a['id']: {'kind': a['kind'], 'finder': a['finder'], 'refuter': a['refuter'],
                               'metrics': metrics[a['id']]} for a in arms},
            'overlap': overlaps, 'directionality': directionality(arms, metrics),
            'paired_contrasts': contrasts}


# ── legacy re-analysis (existing two result files, zero calls) ─────────────


LEGACY = (
    ('claude>codex', 'results-claude-codex.json', 'anthropic', 'openai'),
    ('qwen>claude', 'results-qwen-claude.json', 'qwen', 'anthropic'),
)


def legacy_records(arm_id, rows):
    out = []
    for r in rows:
        if r['crossfamily_pos'] and not r['finder_pos']:
            raise ValueError(f'{r["id"]}: survived without a finder hit')
        outcome = ('survived' if r['crossfamily_pos'] else 'not_survived') if r['finder_pos'] else 'not_flagged'
        out.append({'case': r['id'], 'cat': r['cat'], 'real': r['real'], 'arm': arm_id,
                    'finder_pos': r['finder_pos'], 'outcome': outcome, 'rationale': None, 'reason': None})
    return out


def reanalyze(reports_dir):
    """What the two stored cross-family runs can already say, with no new calls."""
    reports_dir = Path(reports_dir)
    sample = json.loads((reports_dir / 'sample.json').read_text())
    recs, meta = {}, {}
    for arm_id, name, ff, rf in LEGACY:
        rows = json.loads((reports_dir / name).read_text())
        if [r['id'] for r in rows] != [c['id'] for c in sample]:
            raise ValueError(f'{name} does not follow sample.json')
        recs[arm_id] = legacy_records(arm_id, rows)
        meta[arm_id] = {'source': f'reports/{name}', 'finder_family': ff, 'refuter_family': rf}
    arms = {}
    for arm_id, rs in recs.items():
        m = arm_metrics(rs, boolean_outcomes=True)
        killed = [{'case': r['case'], 'cat': r['cat'], 'rationale': 'not_recorded'}
                  for r in rs if r['real'] and r['outcome'] == 'not_survived']
        missed = [r['case'] for r in rs if r['real'] and not r['finder_pos']]
        arms[arm_id] = dict(meta[arm_id], metrics=m, killed_true_positives=killed,
                            finder_missed_true_positives=missed,
                            within_arm_paired=_finder_vs_final(rs))
    a, b = (recs[x] for x, *_ in LEGACY)
    return {'schema': 'owasp-xfam-reanalysis-v1', 'model_calls': 0, 'arms': arms,
            'cross_arm': {'overlap': pair_overlap(a, b), 'paired_final': paired_contrast(a, b),
                          'same_case_review_disagreement': _review_disagreement(a, b)},
            'rationale_note': 'the stored result files keep booleans only; per-case reports, refuter '
                              'reasons and logs were not committed, so every rationale is not_recorded',
            'limits': ['each config changes finder and refuter at once; no same-family control',
                       'non-survival mixes refuted, verify error and unreviewed',
                       'the runs predate repeated refuter runs, so uncertain is not measurable']}


def _finder_vs_final(recs):
    """Paired finder-only vs after-review on the same cases (b - a)."""
    s = stats()
    out = {}
    for label, real in (('recall_on_true_cases', True), ('fp_rate_on_false_cases', False)):
        items = [r for r in recs if r['real'] is real]
        out[label] = s.paired_difference({r['case']: r['finder_pos'] for r in items},
                                         {r['case']: r['outcome'] == 'survived' for r in items})
    return out


def _review_disagreement(a, b):
    """TP cases both finders flagged where one review kept it and the other did not."""
    ra, rb = _by_case(a), _by_case(b)
    both = [c for c in sorted(ra) if ra[c]['real'] and ra[c]['finder_pos'] and rb[c]['finder_pos']]
    kept = lambda r: r['outcome'] == 'survived'
    return {'tp_flagged_by_both': len(both),
            'kept_by_both': sum(1 for c in both if kept(ra[c]) and kept(rb[c])),
            'killed_by_both': [c for c in both if not kept(ra[c]) and not kept(rb[c])],
            'killed_only_in_' + a[0]['arm']: [c for c in both if not kept(ra[c]) and kept(rb[c])],
            'killed_only_in_' + b[0]['arm']: [c for c in both if kept(ra[c]) and not kept(rb[c])]}


# ── run plan ─────────────────────────────────────────────────────────────


def calls_cap_per_case(refuter_runs):
    finder = PAGES_PER_CASE * (1 + AI_AUDIT_PARSE_RETRIES)
    verify = MAX_CANDIDATES_PER_MODULE * refuter_runs
    return finder, verify


def build_plan(arms_cfg, n_cases, expected_candidates_per_case=1.0, assumed_seconds_per_call=30,
               pilot_cases=16):
    """Exact call ceilings per arm plus a stated-assumption estimate."""
    runs = arms_cfg['refuter_runs']
    f_cap, v_cap = calls_cap_per_case(runs)
    rows = []
    for a in arms_cfg['arms']:
        cap = n_cases * (f_cap + v_cap)
        expected = round(n_cases * (1 + runs * expected_candidates_per_case))
        rows.append({'arm': a['id'], 'kind': a['kind'], 'finder': a['finder'], 'refuter': a['refuter'],
                     'cases': n_cases, 'finder_calls_cap': n_cases * f_cap,
                     'verify_calls_cap': n_cases * v_cap, 'calls_cap': cap,
                     'output_tokens_cap': cap * D01_OUTPUT_TOKENS_PER_CALL,
                     'wall_seconds_cap': cap * D01_TIMEOUT_SECONDS,
                     'calls_expected': expected,
                     'output_tokens_expected_cap': expected * D01_OUTPUT_TOKENS_PER_CALL,
                     'wall_seconds_expected': expected * assumed_seconds_per_call})
    total = {k: sum(r[k] for r in rows) for k in rows[0] if k.endswith(('_cap', '_expected')) or k == 'cases'}
    reserve = len(rows) * (f_cap + v_cap)
    proposed = total['calls_expected'] + reserve
    pilot = len(rows) * round(pilot_cases * (1 + runs * expected_candidates_per_case)) + reserve
    plan = {
        'schema': PLAN_SCHEMA, 'model_calls_so_far': 0, 'status': 'awaiting owner approval (D01)',
        'per_call': {'output_tokens_max': D01_OUTPUT_TOKENS_PER_CALL, 'timeout_seconds': D01_TIMEOUT_SECONDS,
                     'automatic_retries': D01_AUTOMATIC_RETRIES, 'inflight': 1},
        'per_case_ceiling': {'finder_calls': f_cap, 'verify_calls': v_cap, 'calls': f_cap + v_cap,
                             'basis': f'{PAGES_PER_CASE} page x (1 + {AI_AUDIT_PARSE_RETRIES} reflector) + '
                                      f'{MAX_CANDIDATES_PER_MODULE} candidates x {runs} refuter runs'},
        'refuter_runs': runs, 'arms': rows, 'total': total,
        'proposed_budget': {'calls': proposed, 'output_tokens': proposed * D01_OUTPUT_TOKENS_PER_CALL,
                            'wall_seconds_ceiling': proposed * D01_TIMEOUT_SECONDS,
                            'rule': 'ledger reserves one full case row (all arms at the ceiling) before '
                                    'each case and stops when it does not fit; unrun cases stay in n'},
        'pilot_budget': {'cases': pilot_cases, 'calls': pilot,
                         'output_tokens': pilot * D01_OUTPUT_TOKENS_PER_CALL,
                         'wall_seconds_ceiling': pilot * D01_TIMEOUT_SECONDS,
                         'purpose': 'first stratified case rows only: measure real calls per case and '
                                    'latency before the full budget is approved'},
        'assumptions': {'expected_candidates_per_case': expected_candidates_per_case,
                        'expected_finder_calls_per_case': 1,
                        'assumed_seconds_per_call': assumed_seconds_per_call,
                        'note': 'estimates only; ceilings are exact. Measure both in the first case rows.'},
        'input_bytes_cap_per_call': {'finder_source': MODULE_PROMPT_BUDGET_BYTES,
                                     'verifier_source': VERIFIER_FILE_BUDGET_BYTES,
                                     'note': 'prompt templates not included; the trace records prompt_bytes'},
        'usd': {'formula': 'sum over calls of input_tokens*price_in + output_tokens*price_out',
                'value': None, 'why_null': 'providers and prices are not chosen yet'},
        'blockers': plan_blockers(),
    }
    plan['plan_sha256'] = plan_digest(plan)
    return plan


def plan_blockers():
    return [
        {'id': 'finder_reflector_call', 'owner_can_accept': True,
         'detail': f'vettalon re-asks the finder up to {AI_AUDIT_PARSE_RETRIES} time when its JSON breaks '
                   'the contract (AI_AUDIT_PARSE_RETRIES, no CLI switch). D01 says zero retries: accept it '
                   'as a budgeted correction call (already in the ceiling) or add a switch first.'},
        {'id': 'cli_backend_output_cap', 'owner_can_accept': False,
         'detail': 'CLI presets (claude, codex) cannot enforce 1,024 output tokens; formal arms must use '
                   'backend openai/ollama with max_tokens <= 1024 and timeout_secs <= 90.'},
        {'id': 'no_verify_only_entry', 'owner_can_accept': True,
         'detail': 'vettalon has no verify-only entry, so every arm re-runs its finder; finder noise '
                   'enters arm-to-arm comparisons and is reported as finder agreement.'},
        {'id': 'capability_matching', 'owner_can_accept': True,
         'detail': 'the same-family model must be close in capability to the cross-family refuter, or '
                   'family and capability stay confounded (B8, B9).'},
    ]


def plan_digest(plan):
    body = {k: v for k, v in plan.items() if k != 'plan_sha256'}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
