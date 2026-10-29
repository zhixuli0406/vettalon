# validation_budget_exhausted: The run reached its limit on AI candidates

## What it means

A run accepts at most 60 AI candidates, shared between finders when more than one runs. When that limit was reached, the remaining modules were skipped (`candidate_cap`) and the run was marked `incomplete` with this reason.

## Why you see it

Earlier modules produced many candidates, which is common in code with many weak spots.

## What to do

Triage the candidates you have, then scan the skipped modules in a separate smaller run, for example with `--diff-base <ref>`. There is no flag to raise the limit.

## Related

[candidate_cap](candidate_cap.md), [incomplete](incomplete.md).
