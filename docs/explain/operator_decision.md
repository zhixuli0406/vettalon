# operator_decision: A person's decision and the reason they gave

## What it means

This is the text at the start of an `operator_review` item: `operator_decision: confirmed`, `refuted` or `suppressed`, followed by `; reason: ...`. The decision also changes the finding's `status`, marks its severity as set by an operator, and updates the report summary.

## Why you see it

A reviewer applied a decision to the finding in a triage tool. A reason is required.

## What to do

Read the latest decision and its reason next to the model evidence. Refuted and suppressed findings stop counting toward `--fail-on` and `--gate`. Confirmed ones keep counting.

## Related

[operator_review](operator_review.md), [maintainer_confirmed](maintainer_confirmed.md).
