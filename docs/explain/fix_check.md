# fix_check: The result of testing the finding's suggested fix

## What it means

The evidence records whether the suggested fix diff stopped the attack and whether your tests still passed. The outcome is one of `fix_verified`, `fix_check_partial` (attack stopped, no test command given), `fix_rejected` or `fix_unverified`. It names the diff by SHA-256 and applies only to that exact diff. It never changes the finding's status.

## Why you see it

A `--poc` scan checked the suggested fix of a High or above finding, or you ran `vettalon fix check`. Only command injection, path traversal and SQL injection findings have a harness for this.

## What to do

Confirm the hash matches the fix you plan to apply. For a full check, add `--fix-test-command "<your test command>"`.

## Related

[poc_oracle](poc_oracle.md), [operator_review](operator_review.md).
