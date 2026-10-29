# poc_effect_no_control: A sandbox test showed an effect, but the proof is incomplete

## What it means

The harness saw an effect tied to its one-time secret. The checks that would make the result convincing are missing: either no control run came back clean (or the control showed the effect too), or the fresh-container rerun did not succeed. The finding stays `needs_human`.

## Why you see it

The `poc_oracle` item lacks `control=false`, `rerun=true`, or both.

## What to do

Read the `control` and `rerun` fields of the item and `strongest_counterevidence`. Run `vettalon scan . --profile deep --poc` again, or reproduce the effect yourself with a benign control input.

## Related

[poc_differential](poc_differential.md), [no_control](no_control.md), [no_fresh_rerun](no_fresh_rerun.md).
