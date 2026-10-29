# adversarial_review: A note from the second model that tried to disprove the finding

## What it means

This evidence item holds a note from the review stage, where a model from a different vendor (the refuter) tries to disprove an AI finding. The note text varies: `plausible:`, `refuted:`, a `precheck:` failure, a `verify_error:`, or one line per refuter run. The kind alone does not tell you the outcome.

## Why you see it

A `--profile deep` scan reviewed the finding, or a saved report from an earlier scan left a note on it (source `prior_run`).

## What to do

Read the `detail` text of each item, then check the finding's `status` field. Run `vettalon explain plausible`, `refuted` or `verify_error` to decode the common prefixes.

## Related

[plausible](plausible.md), [precheck](precheck.md), [verify_error](verify_error.md).
