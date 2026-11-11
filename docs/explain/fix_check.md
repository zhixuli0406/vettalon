# fix_check: The result of testing the finding's suggested fix

## What it means

The evidence records whether the suggested fix diff stopped the attack and whether your tests still passed. The outcome is one of `fix_verified`, `fix_check_partial` (attack stopped, no test command given), `fix_rejected` or `fix_unverified`. It names the diff by SHA-256 and applies only to that exact diff. It never changes the finding's status.

The fixed copy runs the patched code, so the fix itself can end a run there: exit non-zero (for example `os._exit`), hang until the timeout, or print no, an invalid or a duplicate verdict line. The harness runner also reports `error=true` when the child running the checked code times out, exits non-zero, returns a missing or invalid result, or changes the evidence while it runs. When the original copy gave a verdict for that input, any of these on the fixed copy (an `error=true` run counts only when it shows no effect) means the input is not counted as blocked. The remaining inputs and the benign control still run, so a later effect or a broken benign input still makes the outcome `fix_rejected`; otherwise the regression check is inconclusive with reason `fixed_copy_no_verdict` and the outcome is `fix_unverified`. A Python exception raised by the checked code (`raised=true`) is different: with no effect it counts as blocked, and the benign control catches a fix that always raises.

A pass means only that no effect was observed for this revision and these inputs. It does not prove the fix is complete. It is also not proof against an adversarial diff: the inputs are fixed and known, so a diff that special-cases them can pass while the bug stays. For SQL injection, a target function that writes to the SQLite database during the run (for example enabling WAL or inserting a log row) changes the database file's change time, which the evidence check treats as tampering; that input is then not counted as blocked. The per-run marker reaches the harness runner on stdin only, and the adapter and project code run in a child process of the runner. The runner is PID 1 of its container and makes itself non-dumpable before any checked code starts, so checked code cannot read its memory or outlive its cleanup. After checked code ran, the runner checks each evidence file's content and whether it was renamed, replaced or had its permissions changed, even if the change was undone. Code in the checked copy also runs as the same user as the harness, so it can still detect the harness or alter evidence files in ways the runner's integrity check does not catch.

Receipts made by harness versions before `vettalon-three-class-oracle-v3` (Vettalon 0.7.0 and earlier) still read, but they no longer count as a complete binding. Run the check again with 0.7.1 or later.

## Why you see it

A `--poc` scan checked the suggested fix of a High or above finding, or you ran `vettalon fix check`. Only command injection, path traversal and SQL injection findings have a harness for this.

## What to do

Confirm the hash matches the fix you plan to apply. For a full check, add `--fix-test-command "<your test command>"`.

## Related

[poc_oracle](poc_oracle.md), [operator_review](operator_review.md).
