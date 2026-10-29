# shallow_no_checks: The module was reviewed, but the model listed no checks

## What it means

This is the `reason` on a module whose status is `reviewed_no_checks`. The model found no vulnerabilities and gave no list of what it checked, so the report cannot show what the review covered. It is informational and does not change the exit code.

## Why you see it

The finder's reply had an empty `checks` list. A later scan with `--profile deep` also moves such modules to the front of the queue (see `prior_gap`).

## What to do

Rescan with `--attack-classes auto` to get checks per attack class, or review the module by hand.

## Related

[reviewed_no_checks](reviewed_no_checks.md), [covered](covered.md), [prior_gap](prior_gap.md).
