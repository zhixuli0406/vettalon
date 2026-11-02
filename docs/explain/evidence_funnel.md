# evidence_funnel: Evidence counts derived from the report

## What it means

The CLI summary, SARIF run property `vettalon.funnel`, and public Rust function `audit::funnel::derive(&AuditReport)` derive the same counts at render time. The report schema remains 3. Each retained AI finding is counted once per applicable layer. These independent layers overlap and can increase or decrease along the displayed arrow; the arrow describes review stages, without claiming conversion rates.

| Layer | Definition |
| --- | --- |
| `candidates` | All retained findings whose `source_engine` is `ai_audit`, including refuted, suppressed and carried findings. |
| `refuted` | AI findings currently carrying status `refuted`. |
| `needs_human` | AI findings currently carrying status `needs_human`. |
| `poc_differential` | AI findings with a strictly parsed `PocOracle` whose `level()` is `PocDifferential`: nonce-bound accepted effect, control without effect, fresh successful rerun. This counts recorded oracle evidence independently of the current status and evidence-level caps. |
| `fix_verified` | AI findings whose existing `fix_check()` derives `FixVerified`, including the exact suggested diff, complete matching paired execution binding, passing regression check and configured project tests. This describes the recorded snapshot. |
| `human_confirmed` | AI findings whose existing `evidence_level()` derives `MaintainerConfirmed`, requiring confirmed status and operator provenance. |
| `scanner_findings` | All retained findings whose source engine differs from `ai_audit`, regardless of status, counted separately from every AI layer. |

Target reproduction is not counted because reproduce receipts are not stored in reports. Attached `target_execution` artifacts and exit 0 cannot supply that missing receipt.

## Why you see it

A report can contain many candidates while having little execution or human evidence. Historical reports derive only from the evidence they retain. Stored summary counters, standalone pattern transcripts and model claims never supply stronger evidence.

## What to do

Review the underlying evidence and proof gaps. Run target reproduction and fix checks where supported, then record an explicit human decision. The funnel leaves gate, `--fail-on` and `evidence_level` behavior unchanged.

## Related

- [poc_differential](poc_differential.md)
- [fix_check](fix_check.md)
- [maintainer_confirmed](maintainer_confirmed.md)
