# poc_not_demonstrable: The model could not write a runnable demonstration

## What it means

The PoC model answered that it could not demonstrate the claim in a standalone script, returned an empty script, or, for the oracle classes, did not give a Python sink. Nothing ran. This does not show the finding is false. It shows the model could not build a test inside the sandbox, which has no network and no copy of your repository.

## Why you see it

You used `--poc`. The tag is stored as `poc_skipped` evidence with the model's note.

## What to do

Read the note. Many real issues (SSRF, for example) cannot be shown in this sandbox. Reproduce them in your own test environment.

## Related

[poc_skipped](poc_skipped.md), [poc_generation_failed](poc_generation_failed.md), [no_poc](no_poc.md).
