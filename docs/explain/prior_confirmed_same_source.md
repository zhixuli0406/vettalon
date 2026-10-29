# prior_confirmed_same_source: An earlier report confirmed this issue, and it is being checked again

## What it means

A saved report marked this root cause `confirmed` on identical file content. Vettalon does not copy that status. The finding stays `candidate` and goes through the refuter again instead of inheriting the confirmation.

## Why you see it

The finding matches a prior confirmed finding by root cause and file hash. This is on by default and uses the newest report saved with `--save`.

## What to do

Compare the old confirmation (the note names the report file) with this scan's refuter result. If they differ, investigate why.

## Related

[carried_from_prior](carried_from_prior.md), [prior_changed_source](prior_changed_source.md).
