# prior_changed_source: An earlier scan judged this issue, but the file has changed since

## What it means

A saved report from an earlier scan contains a finding with the same root cause. The file's content now differs (or could not be hashed), so the old verdict is not reused. It appears as a note only, and the finding goes through normal review.

## Why you see it

Carry-over compares the newest report saved with `--save` for this repository. Any edit to the file, even far from the flagged line, breaks the match.

## What to do

Read the note to see what the earlier scan decided, then judge the finding on the current code. To ignore saved reports entirely, add `--no-prior`.

## Related

[carried_from_prior](carried_from_prior.md), [prior_confirmed_same_source](prior_confirmed_same_source.md).
