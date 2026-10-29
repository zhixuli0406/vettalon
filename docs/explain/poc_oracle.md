# poc_oracle: The harness's own verdict on a sandbox test

## What it means

An evidence item written by the harness, not by a model. Its fields are `effect`, `control`, `rerun`, `nonce_bound` and `rejected`. They say whether the one-time secret showed up in the target's output, whether a benign control stayed clean, whether a fresh rerun repeated the effect, and why a PoC was rejected. Only this format raises the finding's evidence level. It never sets the finding's status.

## Why you see it

You ran with `--poc` on a command injection, path traversal or SQL injection finding.

## What to do

Read every field, plus `rejected` if present, before you judge the effect.

## Related

[poc_differential](poc_differential.md), [poc_effect_no_control](poc_effect_no_control.md).
