# quick_profile_not_rechecked: A quick scan could not tell whether an old finding is still there

## What it means

A saved report has an open finding that this quick scan did not produce. The quick profile runs only open-source scanners and no AI, so it cannot re-judge them. It lists the old finding under `prior_run.changed_unrediscovered` and does nothing else with it: no new finding, no model input, no closing.

## Why you see it

You ran `vettalon scan .` (quick is the default profile) in a repository whose newest saved report has open findings this scan did not produce.

## What to do

Run `vettalon scan . --profile deep`, which re-checks such claims, or check the old finding by hand.

## Related

[prior_not_rediscovered](prior_not_rediscovered.md), [prior_gap](prior_gap.md).
