# refuter_survived: A refuter could not disprove the claim

## What it means

At least one refuter run judged the claim plausible, so it survived one independent check. This level also appears when uncertain verification (`verify_uncertain`) lowers a stronger level to it. It does not mean an exploit ran, and it does not mean a person confirmed it.

## Why you see it

A `plausible:` item is in the evidence chain.

## What to do

Read the reason and `proof_gaps` in the report. The next step is a PoC (`--poc`, for supported classes) or your own reproduction.

## Related

[refuter_consistent](refuter_consistent.md), [plausible](plausible.md), [no_poc](no_poc.md).
