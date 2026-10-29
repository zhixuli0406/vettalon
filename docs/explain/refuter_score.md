# refuter_score: The refuter's own probability that the claim is real

## What it means

Each refuter run reported a number from 0 to 100 for how likely the claim is real, plus an evidence category. Missing or invalid values are recorded as such. This is model output, not a measured probability. By default no decision reads it. With `--refuter-score-threshold P`, a refutation only closes the finding if its score is below P.

## Why you see it

You used `--refuter-score` or `--refuter-score-threshold`. Both are experimental and off by default.

## What to do

Use the score only to sort your reading order. Check the cited evidence and the threshold you set.

## Related

[adversarial_review](adversarial_review.md), [verify_uncertain](verify_uncertain.md).
