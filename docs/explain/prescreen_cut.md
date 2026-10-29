# prescreen_cut: A cheap model ranked this module too low to audit

## What it means

With `--prescreen cheap-model`, a cheap model scores the top audit units from 1 to 5, and only the top share (20% by default) go on to the deep audit. This module was in the pool but fell below the cut. It is `deferred`, not reviewed, and not clean.

## Why you see it

You set `--prescreen cheap-model --prescreen-model <id>`. The scores are in `ensemble.prescreen` in the report.

## What to do

Raise `--prescreen-top`, scan without `--prescreen`, or review this module separately.

## Related

[deferred](deferred.md), [max_modules](max_modules.md).
