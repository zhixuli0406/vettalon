# budget_cannot_fund_reserves: The budget was too small to reserve room for verification

## What it means

This is a value the report format allows in `incomplete_reason`. It says the run's budget could not set aside enough capacity for the verification stage. It describes the run, not any single finding.

## Why you see it

No code path in `vettalon scan` sets this value in this version. If you see it, the report was most likely not written by this version of `vettalon scan`.

## What to do

Look at `run_status`, `incomplete_reason` and the `coverage` list to see what was left unfinished. Rerun with `vettalon scan . --profile deep` and a larger `--time-budget` if time was the limit.

## Related

[validation_budget_exhausted](validation_budget_exhausted.md), [critic_budget_exhausted](critic_budget_exhausted.md), [incomplete](incomplete.md).
