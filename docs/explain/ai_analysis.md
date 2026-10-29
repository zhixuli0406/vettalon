# ai_analysis: The finder model's explanation of why the code is vulnerable

## What it means

This evidence item holds the reasoning text (it starts with `reasoning:`) written by the finder, the first model that proposed the finding. It is a claim made by a model. It is not proof, and it does not confirm the finding.

## Why you see it

Every AI finding from a `--profile deep` scan carries one, because the finder had to justify each candidate it reported.

## What to do

Read the reasoning next to the finding's trace and threat model. Then check what the refuter said (`adversarial_review` items) and the finding's `evidence_level`. A finding at `static_only` has not survived any independent check yet.

## Related

[static_only](static_only.md), [adversarial_review](adversarial_review.md).
