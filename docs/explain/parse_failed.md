# parse_failed: The model's reply for this module was not valid output

## What it means

The finder's reply broke the required JSON format and was thrown away whole. Nothing from it is used, so the module has no review. It counts as failed in the coverage summary and normally makes the run `incomplete` with `units_failed`.

## Why you see it

The reply was not valid JSON for the audit format, or it broke the format's rules. By default Vettalon asks once more with the problem named (`--finder-parse-retries`, 0 or 1). This module failed after that retry, or the retry was set to 0.

## What to do

Rerun, or choose a model that follows the format better with `--finders <id>`.

## Related

[units_failed](units_failed.md), [verifier_reflector](verifier_reflector.md).
