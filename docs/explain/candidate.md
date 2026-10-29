# candidate: The module review reported at least one finding

## What it means

In the `coverage` list, `candidate` is a module status. It means the finder model reported one or more findings for that module. The count includes findings the local pre-check later rejected. It is not the same as a finding whose `status` is `candidate`.

## Why you see it

The module entry lists `candidate_ids`, and each id points to a finding in the report.

## What to do

Open the findings with those ids and read their `status`. A module can be `candidate` and still have unreviewed files, so also check the module's `attempts` and `truncated_paths`.

## Related

[covered](covered.md), [partially_reviewed](partially_reviewed.md), [precheck](precheck.md).
