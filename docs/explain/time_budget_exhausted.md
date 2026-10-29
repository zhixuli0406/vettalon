# time_budget_exhausted: The scan hit its time limit with work left over

## What it means

A time cap ran out: `--time-budget` for the whole deep audit, `--finder-budget` for the finders, or `--poc-budget` for sandbox tests. Modules were deferred, a model call timed out, or PoCs never started. Findings found so far stay in the report.

## Why you see it

The run has unfinished work because of its deadline. It is marked `incomplete` and can still exit 0.

## What to do

Check `coverage` for deferred modules and findings with `no_poc`. Raise the cap or narrow the scope, for example `vettalon scan . --profile deep --time-budget 3600 --max-modules 8`.

## Related

[time_budget](time_budget.md), [incomplete](incomplete.md), [no_poc](no_poc.md).
