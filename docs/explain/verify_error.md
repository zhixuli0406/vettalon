# verify_error: The refuter gave no usable answer for this finding

## What it means

The verification step failed: the model call errored, the reply broke the format even after a retry, a refutation cited a guard that does not exist, or the local pre-check failed so no call was made. The finding stays `candidate`, and its evidence level is capped at `static_only`. It still counts toward `--fail-on`. A person's confirmation overrides the cap.

## Why you see it

The detail after `verify_error:` says which of these happened.

## What to do

Read that detail, restore the verifier model if needed, and rerun. To retry only verification on a saved report, use `vettalon verify . --input report.json --verifier <id> --out verified.json`.

## Related

[static_only](static_only.md), [no_refuter](no_refuter.md), [units_failed](units_failed.md).
