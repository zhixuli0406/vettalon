# refuted: A refuter judged the claim false

## What it means

A refuter model decided the finding is not supported by the code. If the finding had one refuter run, its status becomes `refuted`. With several runs (High and above, by default), all of them must say refuted. Refuted findings stay in the report but no longer count toward `--fail-on` or `--gate`.

## Why you see it

The refuter answered `refuted` and passed the format checks.

## What to do

Spot-check high-severity ones. Read the reason and the cited guard in the `refute_basis` item, and confirm the guard exists. A refuter can be wrong, and it can be misled by comments in the code.

## Related

[refute_basis](refute_basis.md), [refuter_run](refuter_run.md), [verify_uncertain](verify_uncertain.md).
