# plausible: The refuter tried to disprove the finding and could not

## What it means

A refuter model from a different vendor read the claim and the code and could not refute it. The finding moves to `needs_human`. It is not confirmed. The refuter also lists what is still unverified (`blockers`) and a validation plan.

## Why you see it

The refuter answered `plausible`. With several runs, which is the default for High and above, all runs must say so.

## What to do

Read the reason, the blockers and the proof gaps. Reproduce the claim or review the code yourself. `needs_human` findings do not count toward `--fail-on` unless you add `--fail-on-needs-human`.

## Related

[refuter_survived](refuter_survived.md), [refuter_consistent](refuter_consistent.md), [no_maintainer_confirmation](no_maintainer_confirmation.md).
