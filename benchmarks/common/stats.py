"""Small-sample statistics for evaluation reports. Stdlib only; no model calls.

Reporting rules this module enforces (see README.md next to this file):

* every rate is reported as k/n with a 95% interval, never as a bare percentage;
* below CLT_MIN_N items no normal-approximation (Wald/CLT) error bar is produced;
* 0/n and n/n use the exact Clopper-Pearson bound instead of Wilson;
* two-arm comparisons on the same items use item-level paired differences
  (exact sign test on discordant items plus a seeded item bootstrap);
* repeated runs of the same item are clustered by item, never treated as
  independent observations;
* a comparison whose sample is below the pre-registered power target is
  labelled underpowered and is descriptive only.
"""
import math
import random
from statistics import NormalDist

CONFIDENCE = 0.95
CLT_MIN_N = 300
BOOTSTRAP_RESAMPLES = 2000
UNDERPOWERED_LABEL = 'underpowered: descriptive only'
POWERED_LABEL = 'adequately powered'


def _z(confidence):
    if not 0 < confidence < 1:
        raise ValueError('confidence must be in (0, 1)')
    return NormalDist().inv_cdf(1 - (1 - confidence) / 2)


def _check_counts(k, n):
    if type(k) is not int or type(n) is not int or n < 0 or not 0 <= k <= n:
        raise ValueError('rate needs integer counts with 0 <= k <= n')


def wilson(k, n, confidence=CONFIDENCE):
    """Wilson score interval; None when n == 0."""
    _check_counts(k, n)
    if n == 0:
        return None
    z = _z(confidence)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def _log_binom_pmf(i, n, p):
    if p <= 0:
        return 0.0 if i == 0 else -math.inf
    if p >= 1:
        return 0.0 if i == n else -math.inf
    return (math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1)
            + i * math.log(p) + (n - i) * math.log1p(-p))


def binom_cdf(k, n, p):
    """P(X <= k) for X ~ Binomial(n, p), computed in log space (no overflow)."""
    if k < 0:
        return 0.0
    if k >= n:
        return 1.0
    logs = [_log_binom_pmf(i, n, p) for i in range(k + 1)]
    top = max(logs)
    if top == -math.inf:
        return 0.0
    return min(1.0, math.exp(top) * sum(math.exp(v - top) for v in logs))


def _bisect(func, target, increasing):
    lo, hi = 0.0, 1.0
    for _ in range(200):
        mid = (lo + hi) / 2
        value = func(mid)
        if (value < target) == increasing:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def clopper_pearson(k, n, confidence=CONFIDENCE):
    """Exact two-sided Clopper-Pearson interval; None when n == 0."""
    _check_counts(k, n)
    if n == 0:
        return None
    tail = (1 - confidence) / 2
    if k == 0:
        lower = 0.0
    elif k == n:
        lower = tail ** (1 / n)
    else:
        # P(X >= k | p) increases with p; find where it equals tail.
        lower = _bisect(lambda p: 1 - binom_cdf(k - 1, n, p), tail, True)
    if k == n:
        upper = 1.0
    elif k == 0:
        upper = 1 - tail ** (1 / n)
    else:
        # P(X <= k | p) decreases with p; find where it equals tail.
        upper = _bisect(lambda p: binom_cdf(k, n, p), tail, False)
    return (lower, upper)


def zero_upper_bound(n, confidence=CONFIDENCE, two_sided=True):
    """Exact upper bound for 0/n successes.

    two_sided=True matches the upper end of the two-sided Clopper-Pearson
    interval (0/7 -> 0.410, 0/30 -> 0.116). two_sided=False is the one-sided
    bound, which the rule of three (3/n) approximates (0/80 -> 0.0367).
    """
    if type(n) is not int or n <= 0:
        raise ValueError('zero_upper_bound needs n > 0')
    alpha = 1 - confidence
    return 1 - ((alpha / 2) if two_sided else alpha) ** (1 / n)


def normal_interval(k, n, confidence=CONFIDENCE):
    """Wald interval. Refuses small samples: callers cannot slip a CLT bar in."""
    _check_counts(k, n)
    if n < CLT_MIN_N:
        raise ValueError(f'normal approximation refused for n={n} < {CLT_MIN_N}')
    p = k / n
    half = _z(confidence) * math.sqrt(p * (1 - p) / n)
    return (max(0.0, p - half), min(1.0, p + half))


def rate(k, n, confidence=CONFIDENCE):
    """A reportable rate: point value, interval, n and the method that made it."""
    _check_counts(k, n)
    out = {'k': k, 'n': n, 'value': k / n if n else None, 'interval': None,
           'method': None, 'confidence': confidence, 'clt_allowed': n >= CLT_MIN_N}
    if n == 0:
        out['method'] = 'undefined (n=0)'
        return out
    if k in (0, n):
        out['interval'] = list(clopper_pearson(k, n, confidence))
        out['method'] = 'clopper-pearson-exact'
        if k == 0:
            out['one_sided_upper'] = zero_upper_bound(n, confidence, two_sided=False)
    else:
        out['interval'] = list(wilson(k, n, confidence))
        out['method'] = 'wilson'
    return out


def bounded_rate(k_lower, k_upper, n, confidence=CONFIDENCE):
    """A rate known only within [k_lower, k_upper]/n (unknown items kept in n).

    The interval spans the lower end of the pessimistic count and the upper end
    of the optimistic count, so unresolved items widen it instead of vanishing.
    """
    _check_counts(k_lower, n)
    _check_counts(k_upper, n)
    if k_lower > k_upper:
        raise ValueError('k_lower must not exceed k_upper')
    low, high = rate(k_lower, n, confidence), rate(k_upper, n, confidence)
    return {'n': n, 'k_lower': k_lower, 'k_upper': k_upper,
            'point_bounds': [low['value'], high['value']] if n else None,
            'interval': [low['interval'][0], high['interval'][1]] if n else None,
            'method': 'bracket(' + low['method'] + ', ' + high['method'] + ')',
            'confidence': confidence, 'clt_allowed': n >= CLT_MIN_N}


def _pct(value):
    return f'{100 * value:.1f}%'


def format_rate(k, n, label='', confidence=CONFIDENCE):
    """One printable line: 'label k/n = x% [lo, hi] <method> n=N'."""
    r = rate(k, n, confidence)
    prefix = f'{label} ' if label else ''
    if n == 0:
        return f'{prefix}0/0 = n/a (n=0, no estimate)'
    level = int(round(confidence * 100))
    method = 'Wilson' if r['method'] == 'wilson' else 'exact CP'
    lo, hi = r['interval']
    return f'{prefix}{k}/{n} = {_pct(r["value"])} [{_pct(lo)}, {_pct(hi)}] {method} {level}% n={n}'


def format_bounded(k_lower, k_upper, n, label='', confidence=CONFIDENCE):
    if k_lower == k_upper:
        return format_rate(k_lower, n, label, confidence)
    b = bounded_rate(k_lower, k_upper, n, confidence)
    prefix = f'{label} ' if label else ''
    if n == 0:
        return f'{prefix}n/a (n=0, no estimate)'
    lo, hi = b['interval']
    return (f'{prefix}{k_lower}..{k_upper}/{n} = {_pct(b["point_bounds"][0])}..{_pct(b["point_bounds"][1])} '
            f'[{_pct(lo)}, {_pct(hi)}] bracket {int(round(confidence * 100))}% n={n} '
            f'({k_upper - k_lower} unresolved kept in n)')


def exact_sign_test(a_only, b_only):
    """Two-sided exact sign test (exact McNemar) on discordant item counts."""
    if type(a_only) is not int or type(b_only) is not int or a_only < 0 or b_only < 0:
        raise ValueError('discordant counts must be non-negative integers')
    n = a_only + b_only
    if n == 0:
        return 1.0
    return min(1.0, 2 * binom_cdf(min(a_only, b_only), n, 0.5))


def _aligned(arm_a, arm_b):
    if type(arm_a) is not dict or type(arm_b) is not dict:
        raise ValueError('paired arms must be {item_id: value} maps')
    if set(arm_a) != set(arm_b):
        raise ValueError('paired arms must cover exactly the same item ids')
    if not arm_a:
        raise ValueError('paired comparison needs at least one item')
    ids = sorted(arm_a)
    values = []
    for item in ids:
        pair = []
        for value in (arm_a[item], arm_b[item]):
            if type(value) is bool:
                value = int(value)
            if type(value) not in (int, float) or not math.isfinite(value):
                raise ValueError('paired values must be finite numbers or booleans')
            pair.append(float(value))
        values.append(tuple(pair))
    return ids, values


def _percentile(sorted_values, q):
    index = q * (len(sorted_values) - 1)
    lo, hi = math.floor(index), math.ceil(index)
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (index - lo)


def paired_difference(arm_a, arm_b, confidence=CONFIDENCE, resamples=BOOTSTRAP_RESAMPLES, seed=0):
    """Item-level paired difference mean(b) - mean(a) on the same items.

    Values may be booleans (solved / not solved) or per-item means over repeats.
    Inference uses the exact sign test over items whose values differ and a
    seeded percentile bootstrap that resamples items (not observations).
    """
    ids, values = _aligned(arm_a, arm_b)
    n = len(ids)
    diffs = [b - a for a, b in values]
    a_better = sum(d < 0 for d in diffs)
    b_better = sum(d > 0 for d in diffs)
    rng = random.Random(seed)
    boot = sorted(sum(diffs[rng.randrange(n)] for _ in range(n)) / n for _ in range(resamples))
    tail = (1 - confidence) / 2
    return {'n_items': n, 'mean_a': sum(a for a, _ in values) / n, 'mean_b': sum(b for _, b in values) / n,
            'difference': sum(diffs) / n, 'a_better_items': a_better, 'b_better_items': b_better,
            'tied_items': n - a_better - b_better, 'sign_test_p': exact_sign_test(a_better, b_better),
            'bootstrap_interval': [_percentile(boot, tail), _percentile(boot, 1 - tail)],
            'bootstrap_resamples': resamples, 'bootstrap_seed': seed, 'confidence': confidence,
            'method': 'item-paired difference; exact sign test over items; item bootstrap'}


def clustered_mean(observations, confidence=CONFIDENCE, resamples=BOOTSTRAP_RESAMPLES, seed=0):
    """Mean over repeated runs with item-clustered standard error.

    observations: {item_id: [value per repeat, ...]}. The clustered SE follows
    the sandwich form sqrt(sum_c (sum_{i in c} (x_i - mean))^2) / N with the
    usual C/(C-1) small-cluster correction. The interval is a cluster
    bootstrap; a normal interval is attached only when there are at least
    CLT_MIN_N clusters.
    """
    if type(observations) is not dict or not observations:
        raise ValueError('clustered_mean needs {item_id: [values]}')
    clusters = []
    for item in sorted(observations):
        values = observations[item]
        if type(values) is not list or not values:
            raise ValueError('each cluster needs at least one observation')
        row = []
        for value in values:
            if type(value) is bool:
                value = int(value)
            if type(value) not in (int, float) or not math.isfinite(value):
                raise ValueError('observations must be finite numbers or booleans')
            row.append(float(value))
        clusters.append(row)
    total = sum(len(c) for c in clusters)
    count = len(clusters)
    mean = sum(sum(c) for c in clusters) / total
    naive_var = sum((x - mean) ** 2 for c in clusters for x in c) / max(total - 1, 1)
    se_naive = math.sqrt(naive_var / total)
    score = sum(sum(x - mean for x in c) ** 2 for c in clusters)
    correction = count / (count - 1) if count > 1 else 1.0
    se_clustered = math.sqrt(correction * score) / total
    rng = random.Random(seed)
    boot = []
    for _ in range(resamples):
        picked = [clusters[rng.randrange(count)] for _ in range(count)]
        boot.append(sum(sum(c) for c in picked) / sum(len(c) for c in picked))
    boot.sort()
    tail = (1 - confidence) / 2
    out = {'n_observations': total, 'n_clusters': count, 'mean': mean,
           'se_clustered': se_clustered, 'se_naive': se_naive,
           'design_effect': (se_clustered / se_naive) ** 2 if se_naive > 0 else None,
           'cluster_bootstrap_interval': [_percentile(boot, tail), _percentile(boot, 1 - tail)],
           'normal_interval': None, 'confidence': confidence,
           'note': 'repeats are clustered by item; independent-observation SE is shown only for comparison'}
    if count >= CLT_MIN_N:
        half = _z(confidence) * se_clustered
        out['normal_interval'] = [mean - half, mean + half]
    return out


def two_proportion_sample_size(p1, p2, alpha=0.05, power=0.8):
    """Per-arm n for an unpaired two-sided two-proportion z test (pooled null).

    20% -> 30% at alpha 0.05, power 0.8 needs 294 items per arm. A paired
    design on the same items can need fewer, so this is a conservative bound.
    """
    for p in (p1, p2):
        if not 0 < p < 1:
            raise ValueError('proportions must be in (0, 1)')
    if p1 == p2:
        raise ValueError('effect size must be non-zero')
    za = _z(1 - alpha)
    zb = NormalDist().inv_cdf(power)
    pbar = (p1 + p2) / 2
    numerator = (za * math.sqrt(2 * pbar * (1 - pbar)) + zb * math.sqrt(p1 * (1 - p1) + p2 * (1 - p2))) ** 2
    return math.ceil(numerator / (p1 - p2) ** 2)


def two_proportion_power(p1, p2, n_per_arm, alpha=0.05):
    """Approximate power of the same test at a given per-arm n."""
    if type(n_per_arm) is not int or n_per_arm <= 0:
        raise ValueError('n_per_arm must be a positive integer')
    za = _z(1 - alpha)
    pbar = (p1 + p2) / 2
    se0 = math.sqrt(2 * pbar * (1 - pbar) / n_per_arm)
    se1 = math.sqrt((p1 * (1 - p1) + p2 * (1 - p2)) / n_per_arm)
    return NormalDist().cdf((abs(p1 - p2) - za * se0) / se1)


def power_label(n_per_arm, p1, p2, alpha=0.05, power=0.8):
    """Pre-registered power check for a planned comparison p1 -> p2."""
    required = two_proportion_sample_size(p1, p2, alpha, power)
    achieved = two_proportion_power(p1, p2, n_per_arm, alpha) if n_per_arm > 0 else 0.0
    powered = n_per_arm >= required
    return {'planned_effect': [p1, p2], 'alpha': alpha, 'target_power': power,
            'required_n_per_arm': required, 'actual_n_per_arm': n_per_arm,
            'achieved_power': achieved, 'powered': powered,
            'label': POWERED_LABEL if powered else UNDERPOWERED_LABEL,
            'design': 'unpaired two-proportion bound; paired designs may need fewer items'}
