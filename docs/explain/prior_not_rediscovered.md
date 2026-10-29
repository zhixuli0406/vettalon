# prior_not_rediscovered: An open issue from the last scan was not found again and is re-checked

## What it means

A saved report had this finding open (`candidate` or `needs_human`), but the finders did not report it this time. The file is unchanged, so Vettalon adds the claim back as a new candidate. The old verdicts and proofs are dropped, and the refuter judges it again. At most 50 claims are re-added per run.

## Why you see it

Finders can miss a real issue from one run to the next, so silence does not mean it was fixed. Deep scans with carry-over (the default) do this.

## What to do

Read the new refuter result. The finding is not closed just because a finder stayed quiet. The count is in `prior_run.carried_not_rediscovered`.

## Related

[quick_profile_not_rechecked](quick_profile_not_rechecked.md), [prior_gap](prior_gap.md).
