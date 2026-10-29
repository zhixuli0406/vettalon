# poc_generation_failed: The model did not produce a usable proof-of-concept

## What it means

For this finding, the PoC step needed a model to write a script, and that did not work. The call failed, the reply could not be parsed, or the script was in a language the sandbox does not accept (Python or bash for a plain PoC, Python only for an oracle). Nothing ran in the sandbox.

## Why you see it

You used `--poc`. The tag is stored as `poc_skipped` evidence, and the `detail` text gives the error.

## What to do

Read the detail. If the model call failed, check the model and rerun. If not, test the claim by hand.

## Related

[poc_skipped](poc_skipped.md), [no_poc](no_poc.md), [poc_not_demonstrable](poc_not_demonstrable.md).
