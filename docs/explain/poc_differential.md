# poc_differential: A sandbox test showed a real effect, and a control did not

## What it means

This is the second-highest evidence level. The harness ran a PoC and saw the effect tied to its one-time secret. The control run with benign input showed nothing, and a rerun in a fresh container reproduced the effect. It still does not confirm the finding, and the status stays `needs_human`.

## Why you see it

You ran with `--poc`, and the finding is command injection, path traversal or SQL injection, the classes with an oracle. No refuter error capped the level.

## What to do

Open the `poc_oracle` item and judge whether the effect really matches the claim. A person still decides whether it is confirmed.

## Related

[poc_oracle](poc_oracle.md), [maintainer_confirmed](maintainer_confirmed.md).
