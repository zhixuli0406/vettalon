# static_only: Nothing but code reading supports this finding

## What it means

This is the lowest `evidence_level`. The finding is backed by a scanner match or a model's analysis, with no accepted refuter verdict and no sandbox result. A finding that was refuted, or whose verification failed (`verify_error`), also sits here.

## Why you see it

The evidence chain has no `plausible` verdict and no harness-judged PoC. Most scanner findings are at this level.

## What to do

Do not treat the claim as proven. Run a deep scan so a second model reviews AI findings, or use `vettalon verify` on a saved report. For supported classes add `--poc`.

## Related

[refuter_survived](refuter_survived.md), [verify_error](verify_error.md), [no_refuter](no_refuter.md).
