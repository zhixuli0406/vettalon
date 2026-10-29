# poc_not_harness_judged: A PoC ran, but the harness did not confirm an effect

## What it means

There is PoC activity on record, but no oracle result shows a real effect. A transcript of a script that printed "success" does not count, and neither does an oracle record that was rejected. Only the harness watching for an effect tied to its one-time secret does.

## Why you see it

The finding is outside the oracle classes (only CWE-78/77, 22/73 and 89 have one), or the oracle record was rejected, for example by the anti-cheat checks.

## What to do

Open the `poc_oracle` and `poc_transcript` items. Read the `rejected` field if there is one, and test the claim yourself.

## Related

[poc_transcript](poc_transcript.md), [poc_oracle](poc_oracle.md), [no_poc](no_poc.md).
