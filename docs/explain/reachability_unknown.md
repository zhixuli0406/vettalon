# reachability_unknown: Nothing has shown that an attacker can actually reach this code

## What it means

No sandbox run has observed the claimed effect on this finding. Its evidence level is below `poc_effect_no_control`, so the path from an entry point to the flaw rests on reading code only. Findings confirmed by a person do not get this gap.

## Why you see it

You did not run `--poc`, the finding is not in a class with an oracle (command injection, path traversal, SQL injection), or the PoC did not work.

## What to do

Trace the real entry point to the flagged line, for example from the HTTP handler or CLI argument. For the supported classes, run `vettalon scan . --profile deep --poc`.

## Related

[static_only](static_only.md), [poc_effect_no_control](poc_effect_no_control.md).
