# reviewed_no_checks: The model reviewed the module, reported nothing, and listed no checks

## What it means

In the `coverage` list, this status means the model gave a valid reply with no findings and no validated checks (named security rules it examined, with paths). Review happened, but there is nothing to show what was examined. It does not count as supported coverage. On its own it does not make the run `incomplete` and does not affect the exit code.

## Why you see it

The model returned an empty `checks` list. With `--attack-classes`, it also appears when a requested class got no check.

## What to do

Rescan with `vettalon scan . --profile deep --attack-classes auto`, which tells the finder to return a check for each selected attack class. Or review the module yourself.

## Related

[shallow_no_checks](shallow_no_checks.md), [covered](covered.md).
