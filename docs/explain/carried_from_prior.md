# carried_from_prior: An earlier suppressed or refuted verdict was reused on an unchanged file

## What it means

This finding has the same root cause as one that a previous saved report marked suppressed or refuted, and the file content is identical. Vettalon copied that status without calling a refuter. Refuted and suppressed findings do not count toward `--fail-on` or `--gate`, so this can quiet a finding.

## Why you see it

Carry-over is on by default and compares against the newest report saved with `--save` for the same repository. It applies only when every matching prior record had that dismissed status.

## What to do

The evidence item names the prior report file. Check that decision still makes sense. Run `vettalon scan . --profile deep --no-prior` to ignore the saved report and review from scratch.

## Related

[prior_changed_source](prior_changed_source.md), [prior_confirmed_same_source](prior_confirmed_same_source.md).
