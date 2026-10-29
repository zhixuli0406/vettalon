# prior_gap: An earlier scan reviewed this module poorly, so it moved up the queue

## What it means

In the previous saved report, this module was deferred, failed, only partly reviewed or reviewed without checks. Vettalon ranks such modules first this time. The module's `prior_status` field holds `prior_gap:<reason>`. The `--max-modules` limit still applies.

## Why you see it

You scanned with `--profile deep` and a saved report from an earlier scan exists for this repository.

## What to do

Check the module's `attempts` and `reason` to see whether this scan closed the gap. If it is still `deferred`, raise `--max-modules`. To ignore saved reports, use `--no-prior`.

## Related

[shallow_no_checks](shallow_no_checks.md), [partially_reviewed](partially_reviewed.md), [max_modules](max_modules.md).
