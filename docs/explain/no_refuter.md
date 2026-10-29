# no_refuter: No second model has given a verdict on this finding

## What it means

The evidence has no usable refuter verdict: no `plausible`, `refuted`, `refuter_run` or `verify_uncertain` item. A refuter call that failed does not count.

## Why you see it

Scanner findings are not sent to the refuter in a normal scan. AI findings can also lack a verdict if the call failed, the pre-check failed, or the refuter budget ran out.

## What to do

Look for a `verify_error` item to see what failed. For AI candidates in a saved report, `vettalon verify . --input report.json --verifier <id> --out verified.json` gets a verdict now.

## Related

[verify_error](verify_error.md), [refuter_survived](refuter_survived.md).
