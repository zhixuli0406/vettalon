# covered: The module was reviewed, found nothing, and listed what it checked

## What it means

In the `coverage` list, `covered` means the model reviewed the module, reported no findings, and returned at least one validated check: a named security rule it examined, with the file paths it looked at. It records review activity. It does not prove the code has no vulnerabilities.

## Why you see it

The review was valid, no file was cut off, and the checks passed validation.

## What to do

Open the module's `checks` in the JSON report and judge whether they cover what matters for that code. A short or generic list is a weak basis for a coverage claim.

## Related

[reviewed_no_checks](reviewed_no_checks.md), [partially_reviewed](partially_reviewed.md), [candidate](candidate.md).
