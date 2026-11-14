# fix_check_cap_reached: The scan reached its cap on harness fix checks

## What it means

`incomplete_reason: fix_check_cap_reached` means this `--poc` scan already started five harness fix checks (`MAX_FIX_CHECKS_PER_SCAN`). Later suggested fixes that would have run are recorded `fix_unverified` with reason `fix_check_cap_reached`. They do not draw the 20-run PoC counter. A finding with no harness, one that is not PoC-eligible, or one whose diff is refused does not count toward the five. A check that did start uses its own container budget, sized like `vettalon fix check`.

## Why you see it

The scan had more than five findings with a suggested fix in command injection, path traversal or SQL injection, and `--poc` was on.

## What to do

Check the later fixes with `vettalon fix check`. The five that ran are unaffected. This cap is not the clock (`--poc-budget` or `--time-budget`) and not the 20-run PoC counter ([poc_budget_exhausted](poc_budget_exhausted.md)).

## Related

[fix_check](fix_check.md), [poc_budget_exhausted](poc_budget_exhausted.md), [incomplete](incomplete.md).
