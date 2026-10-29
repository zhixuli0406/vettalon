# critic_budget_exhausted: The time cap for the refuter step ran out

## What it means

The refuter step has its own time cap, set with `--refuter-budget`. When it ran out, some findings were never reviewed by the refuter. They keep status `candidate`, and candidates count toward `--fail-on` at their severity.

## Why you see it

Many findings needed review, or the cap was set low. The run is marked `incomplete` with this reason.

## What to do

Raise `--refuter-budget` (it cannot exceed `--time-budget`). Or review the leftovers later with `vettalon verify . --input report.json --verifier <id> --out verified.json`.

## Related

[no_refuter](no_refuter.md), [incomplete](incomplete.md).
