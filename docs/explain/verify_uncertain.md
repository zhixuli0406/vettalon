# verify_uncertain: The refuter could not settle this finding

## What it means

The review did not end in a clear yes or no. Repeated refuter runs disagreed (`verify_uncertain: k/n plausible`), the evidence-based refuter stayed `unresolved`, or the prosecutor found a bypass. The finding stays `candidate`, which counts toward `--fail-on`. Its evidence level is capped at `refuter_survived`, except for a person's confirmation.

## Why you see it

Runs split, required facts were missing, or a checked bypass vetoed closing the finding.

## What to do

Read each `refuter_run` item and the blockers, and collect the facts that would decide the case. The run is not marked `incomplete` for this alone.

## Related

[refuter_inconsistent](refuter_inconsistent.md), [prosecutor](prosecutor.md), [refuter_survived](refuter_survived.md).
