# refute_basis: The refuter's stated reason for closing a finding

## What it means

Each refutation records its basis as `refute_basis: run i/n <basis>; guard=...; cited=...; outcome=...`. Bases include `guarded` (a check stops the attack), `defect_absent` and `unreachable`. A guard must be cited with a real file and a line on the claimed trace, or the refutation is dropped and the finding stays `candidate`.

## Why you see it

A refuter returned `refuted`, and the scan recorded how it justified that.

## What to do

Open the cited lines and check that the guard really stops every form of the input. A basis label is a model's claim, not independent proof.

## Related

[precheck](precheck.md), [prosecutor](prosecutor.md), [verify_uncertain](verify_uncertain.md).
