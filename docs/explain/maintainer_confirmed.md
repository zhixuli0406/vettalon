# maintainer_confirmed: A person confirmed this finding

## What it means

A human reviewer marked the finding `confirmed` in a review tool, and that decision is recorded on it. This is the highest evidence level. Model errors in verification do not cap it. Only a person can set it. Confirmed findings count toward `--fail-on` and satisfy the `cross_family` condition of `--gate`.

## Why you see it

The finding has status `confirmed` and the latest operator decision says confirmed.

## What to do

Read the operator's reason on the `operator_review` item and track the fix. `vettalon disclose report.json` lists the findings eligible for an upstream disclosure draft.

## Related

[operator_review](operator_review.md), [no_maintainer_confirmation](no_maintainer_confirmation.md).
