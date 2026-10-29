# comment_sensitivity: The refuter changed its answer when code comments were visible

## What it means

The refuter normally reads code with comments and docstrings removed. For a finding with several refuter runs, the second run reads the code with its comments. If that run decided one way and every comment-free run decided the other, this item is recorded. The runs disagree, so the finding stays `candidate`.

## Why you see it

A comment such as "verified safe" may have swayed the model. This only happens when a finding gets several runs (High and above by default, see `--refuter-runs`).

## What to do

Read the code without trusting its comments, and compare the `refuter_run` items. Decide from the code itself.

## Related

[verify_uncertain](verify_uncertain.md), [refuter_inconsistent](refuter_inconsistent.md).
