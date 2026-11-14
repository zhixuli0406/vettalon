# replay_inconsistent: Repeated reproductions of a finding did not all agree

## What it means

`vettalon reproduce --replays N` runs the full three-phase target check (attack, benign control, fresh-nonce rerun) N times, each time in new containers with new one-time secrets. The receipt says `effect_observed` only when every replay observed the effect, and `effect_absent` only when every replay saw none. This code means some replays observed the effect and others did not, so the receipt is `inconclusive`.

Agreement over N replays raises confidence that the effect is reproducible on this revision. It does not prove the issue is exploitable, and not observing an effect does not prove the code is safe.

## Why you see it

The target's behaviour depends on something that changes between runs: timing, randomness, environment, or state outside the copied source. A replay that is inconclusive for another reason (for example a malformed verdict) is reported with that reason instead. If the sandbox itself fails, the replays stop early and the receipt carries the sandbox reason; `replays.completed` is then lower than `replays.requested`.

## What to do

Open the receipt's `replays.runs` and compare the phases of the replays that disagree. Make the target call deterministic or pin the input it depends on, then run `vettalon reproduce` again. The finding's status is never changed by a reproduction.

## Related

[no_fresh_rerun](no_fresh_rerun.md), [poc_differential](poc_differential.md), [fix_context_v1](fix_context_v1.md).
