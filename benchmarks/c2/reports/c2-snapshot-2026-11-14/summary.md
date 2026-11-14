# C2 snapshot summary

Commit: 6604c3b8784ecc7cf5ac0b7412d916989b4c7d45

Rates are k/n with a Wilson 95% interval.

| Scanner | n | refuted | maintained | uncertain | error | zero-call |
|---|---|---|---|---|---|---|
| bandit | 28 | 25/28 (72.8-96.3%) | 3/28 (3.7-27.2%) | 0/28 (0.0-12.1%) | 0/28 (0.0-12.1%) | 0/28 (0.0-12.1%) |
| opengrep | 46 | 43/46 (82.5-97.8%) | 3/46 (2.2-17.5%) | 0/46 (0.0-7.7%) | 0/46 (0.0-7.7%) | 0/46 (0.0-7.7%) |
| overall | 74 | 68/74 (83.4-96.2%) | 6/74 (3.8-16.6%) | 0/74 (0.0-4.9%) | 0/74 (0.0-4.9%) | 0/74 (0.0-4.9%) |

Overlap by (file, line, CWE): 4 of 30 locations were selected from more than one scanner.
- bandit+opengrep: 4

Without a CWE (CWE-unknown, reported separately): 0 of 38 locations were selected from more than one scanner.

- Refuted is a model judgement, not ground truth.
- Execution-confirmed: not measured (verify runs no PoC).
