# refuter_inconsistent: The refuter runs could not agree on this finding

## What it means

The finding carries a `verify_uncertain` item, so the review did not settle. Some runs said plausible and others refuted, or an evidence-based review could not decide. The finding stays `candidate`, which counts toward `--fail-on`. This gap remains even when other evidence exists.

## Why you see it

Multiple refuter runs split, which is possible for High and above (`--refuter-runs`, default 3).

## What to do

Compare each `refuter_run` item and the listed blockers. Collect the missing facts yourself and decide from the code.

## Related

[verify_uncertain](verify_uncertain.md), [refuter_consistent](refuter_consistent.md).
