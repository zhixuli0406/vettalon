# reasoning: The prefix of the finder model's explanation

## What it means

The `detail` of an `ai_analysis` evidence item starts with `reasoning:`. What follows is the finder model's own explanation of why the code is vulnerable, cut to a bounded length. It is a claim made by a model, and nobody has checked it.

## Why you see it

A deep scan turned a model's candidate into a finding and stored the explanation on it.

## What to do

Compare the reasoning with the trace and the real code. Then look at what the refuter said. If the refuter's note disagrees, trust the code, not either model.

## Related

[ai_analysis](ai_analysis.md), [adversarial_review](adversarial_review.md), [static_only](static_only.md).
