# refuter_run: One of several refuter runs on this finding

## What it means

High and above findings get several independent refuter runs. Each run is stored as `refuter_run i/n:` followed by its verdict, plus `(with comments)` for the run that read the code with its comments. A run that never started reads `not run: ...` with the reason, such as the time budget.

## Why you see it

The finding was reviewed with more than one run (`--refuter-runs`, default 3, maximum 5).

## What to do

Compare all the runs with the final `status`. If all agree, the result is settled. If they differ, the finding stays `candidate` and carries `verify_uncertain`.

## Related

[refuter_consistent](refuter_consistent.md), [verify_uncertain](verify_uncertain.md), [comment_sensitivity](comment_sensitivity.md).
