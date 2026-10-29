# candidate_cap: The module was skipped because the run already had too many candidates

## What it means

A deep scan stops sending new modules to a finder once the run holds 60 AI candidates (the limit is shared between finders when several run). Modules after that point are `deferred` with this reason. They were not reviewed, and they are not clean.

## Why you see it

Earlier modules produced many candidates. The run is usually marked `incomplete` with `validation_budget_exhausted`.

## What to do

Triage the candidates you have. Then scan the skipped modules in a smaller run, for example with `--diff-base <ref>` or after fixing the first batch. No flag raises the cap.

## Related

[deferred](deferred.md), [validation_budget_exhausted](validation_budget_exhausted.md).
