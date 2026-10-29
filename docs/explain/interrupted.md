# interrupted: The run was recorded as interrupted

## What it means

This is a value the report format allows in `incomplete_reason`. It says execution stopped early, so work done before the stop does not cover the rest of the scope.

## Why you see it

No code path in `vettalon scan` sets this value in this version. If you see it, the report was not written by this version of `vettalon scan`.

## What to do

Treat the report as partial. Check `coverage` for modules that were never reviewed, then rerun the scan for that scope.

## Related

[incomplete](incomplete.md), [units_failed](units_failed.md).
