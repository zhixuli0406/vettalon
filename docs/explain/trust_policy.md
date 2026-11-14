# trust_policy: A model refutation was not allowed to close this finding

## What it means

The refuter model judged the finding false, but its weakness class is one where models often dismiss real bugs. For these CWEs a model refutation alone does not close the finding, so it stays `needs_human`. The item reads `trust_policy: llm_refute_capped CWE-<n>`.

The capped CWEs are CWE-327 (broken or risky cryptographic algorithm), CWE-328 (weak hash), CWE-501 (trust boundary violation) and CWE-614 (sensitive cookie without the `Secure` attribute). Source: Sifting the Noise, ISSTA 2026, arXiv 2601.22952, which measured LLM agents wrongly dismissing true positives at 77.17%, 84.50%, 77.11% and 50% for these CWEs, against 2.38% for CWE-78.

Two related items can appear:

- `trust_policy: prior_refutation_not_carried CWE-<n>: …` — a previous report refuted this finding with a model verdict only. That verdict is not carried over; the finding is reviewed again, as if its source had changed.
- `trust_policy: carried_refutation CWE-<n>` — a previous report closed this finding by an operator decision or a failed deterministic pre-check, and that verdict was carried over on unchanged source.

## Why you see it

A refuter answered `refuted` (in every run, when there were several) for a finding whose CWE is on the list. This applies in both `vettalon scan` and `vettalon verify`, and to verdicts carried from a prior report. Deterministic outcomes are not affected: a failed pre-check, an unreadable source file, execution proof and operator decisions keep their usual results.

When a SARIF result names several CWEs (several `external/cwe/…` tags, gosec rule relationships, Snyk's `cwe` list), the finding takes a capped one if any of them is capped, and lists all of them in a `sarif_cwes:` item.

The report validator enforces the same rule: a `refuted` finding with a capped CWE needs an operator decision, a failed pre-check or the `carried_refutation` item.

A report saved before this policy existed may hold such a model-only `refuted` finding. Wherever a saved report is loaded for further use (prior-run carry-over, the `--since-last` baseline, delivery, MCP and remediation commands, the Pro workspace and dashboard), the finding is first reopened as `needs_human` with the `llm_refute_capped` item, a blocker and a validation plan, the summary is recomputed, and the strict validator then runs on the result. A line on stderr (or in the server log) gives the count. Reading does not rewrite the file; `vettalon validate` checks the file as it is and still reports the violation.

What the policy guarantees: a model refutation, current or saved before the policy, is not what closes a capped CWE. What it does not do: authenticate a report. The operator, pre-check and carried markers are plain report fields; anyone who edits the JSON can write them, and the policy cannot tell that apart from a real decision.

## What to do

Read the refuter's reason in the `refuted:` item next to the cited code. If the weakness is really absent (for example, the hash is not used for security), close the finding yourself; otherwise fix it. The refuter's vote stays recorded as `refuted`.

## Related

[refuted](refuted.md), [refute_basis](refute_basis.md), [plausible](plausible.md).
