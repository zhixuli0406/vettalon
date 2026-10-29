# shallow_missing_class_checks: The finder skipped some attack classes it was asked to check

## What it means

With `--attack-classes auto` or `all`, the finder must return at least one check for each selected attack class. For this module, one or more classes have no check. The module is `reviewed_no_checks`, and the reason lists the missing class ids. It does not show that those classes are safe.

## Why you see it

The model replied without a check for every requested class.

## What to do

Review the listed classes in this module by hand, or rescan with a different finder via `--finders <id>`. The code is informational and does not change the exit code.

## Related

[shallow_no_checks](shallow_no_checks.md), [reviewed_no_checks](reviewed_no_checks.md), [scope_not_fully_reviewed](scope_not_fully_reviewed.md).
