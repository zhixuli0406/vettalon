# refuter_consistent: Three or more refuter runs all found the claim plausible

## What it means

Several independent refuter runs each failed to disprove the finding. The evidence line `refuter_consistent: n/n` records this. The evidence level `refuter_consistent` needs at least three runs in agreement, which is the default for High and above. The status is `needs_human`, not confirmed.

## Why you see it

All runs answered `plausible`. A `verify_error` or `verify_uncertain` item on the same finding would lower the level.

## What to do

Treat it as a finding worth a human's time. Look for PoC or operator evidence next. `--refuter-runs 1` makes this level unreachable.

## Related

[refuter_survived](refuter_survived.md), [verify_uncertain](verify_uncertain.md), [poc_differential](poc_differential.md).
