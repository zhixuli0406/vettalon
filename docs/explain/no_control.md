# no_control: No control run shows the effect is specific to the bug

## What it means

When a sandbox PoC works, the harness also runs a control with benign input. The control should show no effect. This gap means the report has no control result recording `control=false`. Either the control did not run, or it showed the same effect, which would point at the harness instead of the bug.

## Why you see it

The finding has a harness-observed effect but no passing control.

## What to do

Check the `poc_oracle` item and `strongest_counterevidence` for a failed control. Run `--poc` again. Only command injection, path traversal and SQL injection findings get this oracle.

## Related

[poc_effect_no_control](poc_effect_no_control.md), [poc_differential](poc_differential.md).
