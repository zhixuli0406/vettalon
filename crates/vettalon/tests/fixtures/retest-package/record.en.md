# Retest record

## 1. Basic information

Client, engagement and date fields are operator supplied and unchecked by the tool; commits, report hash and replay counts come from receipts.

| Field | Content |
| --- | --- |
| Client | Example &lt;script&gt;alert(1)&lt;/script&gt; |
| Identifier | not recorded |
| Scope | not recorded |
| Scope approval reference | not recorded |
| Original test start | not recorded |
| Original test end | not recorded |
| Retest date | not recorded |
| Tester | not recorded |
| Reviewer | not recorded |
| Contracted unit | not recorded |
| Method note | not recorded |
| Project test command note | not recorded |
| Original commit | `1111111111111111111111111111111111111111` `E3` |
| Retest commit | `2222222222222222222222222222222222222222` `E3` |
| Original report SHA-256 | not recorded `E3` |
| Requested replays | 2 `E3` |
| Package producer version | `sample-version` |

Vettalon (automated)

The new working tree is not confirmed clean.

Package source files: `E1`, `E2`, `E3`

## 2. Summary

| Outcome | Count |
| --- | --- |
| No effect observed at this revision, with these inputs and variants | 1 |
| partial checks passed: no effect observed at this revision, with these inputs and variants; project tests not run | 1 |

Total: 1 findings; 1 retests and 1 change verification checks.

Summary sources: `E3`, `E1`

## 3. Per finding

### `F-1[U+202E]`

Location, function and CWE are report text, unchecked by receipts. Evidence ids in parentheses trace observations; missing per-input verdicts are not inferred from aggregate results.

| Field | Content |
| --- | --- |
| Identifier | `F-1[U+202E]` |
| Location | `src/a\|b.py:7` |
| Function | ``lookup`name`` |
| CWE | `CWE-22` |
| Oracle class | `file_read` |
| Runtime | `python` |

#### Test syntax and results

| Input | Test syntax | Original | Patched copy | Verdict |
| --- | --- | --- | --- | --- |
| `base` (Base input) | `````<script>```payload````</script>````` | Effect observed `E2` | No effect observed (`E1`) | No effect observed in this check (`E1`) |
| Benign input | not recorded | not recorded | Pass (`E1`) | Pass (`E1`) |

Call plan: 1 args, SHA-256 `7777777777777777777777777777777777777777777777777777777777777777` (`E1`, `E2`, `E3`)

Original: Effect observed (`E2`)

Retest conclusion: No effect observed at this revision, with these inputs and variants (`E3`)

Fix check conclusion: partial checks passed: no effect observed at this revision, with these inputs and variants; project tests not run (`E1`)

#### Tester's own judgement (unchecked by the tool)

```
fixed / secure / 已修補 — tester statement
```

Evidence: `E1`, `E2`, `E3`

## 4. Environment

### `python` (`E2`, `E3`)

| Field | Content |
| --- | --- |
| Adapter SHA-256 | not recorded |
| Harness SHA-256 | not recorded |
| Harness version | not recorded |
| Image identifier | `sha256:sample` |
| Node environment | not recorded |
| Policy version | not recorded |
| Per-run sandbox settings | not recorded |
| Source tree SHA-256 | not recorded |

### `python` (`E1`)

| Field | Content |
| --- | --- |
| Adapter SHA-256 | not recorded |
| Harness SHA-256 | not recorded |
| Harness version | not recorded |
| Image identifier | not recorded |
| Node environment | not recorded |
| Policy version | not recorded |
| Per-run sandbox settings | not recorded |
| Source tree SHA-256 | not recorded |

## 5. What this record does not show

- This is a tool rerun record, not a manual penetration retest.
- Field mapping does not establish PCI DSS, procurement or other compliance or certification.
- File hashes establish package integrity only when the manifest hash arrives through a trusted channel or has a trusted signature.
- Tester, client, dates and human conclusions are operator supplied and unchecked by the tool.
- Results apply only to this revision, inputs and variants; other inputs may still produce an effect.
- Receipts record image and harness/policy versions and hashes; network, privilege and resource settings are harness declarations, not per-run observations.
- Project tests passing means only that the operator command exited 0; receipts retain its hash, not evidence of test quality.
- Raw transcripts are not retained, so transcript hashes cannot be recomputed.
- Tree cleanliness is limited to the recorded field; unknown or false values produce a warning.
- Without a signature verified against a trusted key, receipts establish internal consistency only, not that a real run occurred.
- Per-variant results on the original copy are not recorded and cannot be inferred.
- Receipts do not record the producing Vettalon version; the package version is not the receipt producer version.

## 6. Field mapping

### PCI DSS v4.0.1 11.4.4

PCI DSS v4.0.1 11.4.4 field intent has not been checked against PCI SSC text; this table does not establish compliance.

| Requirement element | Machine record | Operator supplied | Gap |
| --- | --- | --- | --- |
| Changes made | Fix check: Diff SHA-256, Retest: New file SHA-256, Retest: Original file SHA-256, Retest: Rebound | Change summary | Diff text is not included. |
| Original and repeat test dates | Original scan start (report text) | Original test end, Original test start, Retest date |  |
| Evidence retained | Fix check: Receipt SHA-256, Original: Receipt SHA-256, Original: Transcript SHA-256, Retest: Receipt SHA-256, Source file SHA-256, Source file Signature information, ML-DSA content binding, ML-DSA verification key hash, ML-DSA signature verification |  | Raw transcripts are not retained; their hashes cannot be recomputed. |
| Finding in the original test | CWE, File, Identifier, Line, Title | Original test reference | Titles are report text, unchecked by receipts. |
| Method and scope | Call plan, Fix check: Execution environment, Per-input test syntax, Original: Execution environment, Retest: Execution environment | Method note, Scope, Scope approval reference |  |
| Performer | Package producer version | Reviewer, Tester | Vettalon runs automatically; qualifications and independence (11.4.1) are operator statements. |
| Result of repeat testing | Fix check: Benign input check, Fix check: Original check, Fix check: Outcome, Fix check: Variant check, Retest: Observation status | Tester’s judgement | Machine results describe this observation; the tester supplies the conclusion. |
| Testing repeated | Retest: Replays, Retest: Observation status, Retest commit | Retest date | Receipts record no machine execution date. |
| Correction according to entity risk ranking (6.3.1) | CWE | Risk rating | The tool does not rank entity risk. |

### Taiwan joint procurement penetration retest report

Based on a sample referencing the 112 procurement specification; the 115 edition is unconfirmed. This table does not establish compliance.

| Requirement element | Machine record | Operator supplied | Gap |
| --- | --- | --- | --- |
| Evidence and attack process | Fix check: Receipt SHA-256, Original: Receipt SHA-256, Original: Transcript SHA-256, Retest: Receipt SHA-256, Source file SHA-256, Source file Signature information, ML-DSA content binding, ML-DSA verification key hash, ML-DSA signature verification |  | No screenshots or raw transcripts; receipts and transcript hashes only. |
| Per-finding retest results | Fix check: Benign input check, Fix check: Original check, Fix check: Outcome, Fix check: Variant check, Retest: Observation status | Tester’s judgement | Human conclusions are shown separately as tester statements. |
| Test scope and method | Call plan, Fix check: Execution environment, Original: Execution environment, Retest: Execution environment | Method note, Scope |  |
| Test inputs and call shape | Call plan, Per-input test syntax |  |  |
| Test and retest dates | Original scan start (report text) | Original test end, Original test start, Retest date |  |
| Finding name, risk and location | CWE, File, Identifier, Line, Title | Location, Risk rating | Names are report text; risk and black-box locations are operator supplied. |

## 7. Evidence appendix

| Identifier | Kind | Package path | SHA-256 | Signature information |
| --- | --- | --- | --- | --- |
| `E1` | Change verification receipt | `receipts/fix-check/check.json` | `eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee` | No signature |
| `E2` | Reproduce receipt | `receipts/reproduce/original.json` | `dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd` | No signature |
| `E3` | Retest receipt | `receipts/retest/sample.json` | `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` | No signature |

## 8. How to verify

Verify package: `vettalon receipt verify-package .`
