# partially_reviewed: The model saw only part of this module

## What it means

The model gave a valid reply, but some of the module's files were cut off, skipped or unreadable. Each module prompt holds 48 KiB of source. Larger modules are truncated, and later files can be left out entirely. The status stays partial even if other files in the module reviewed fine.

## Why you see it

The module's file records show `truncated`, `budget_excluded` or `unreadable` entries.

## What to do

Open the module's `attempts` and file records to see which files were missed. Review those files yourself, or split the code into smaller modules and rescan.

## Related

[scope_not_fully_reviewed](scope_not_fully_reviewed.md), [prompt_byte_budget](prompt_byte_budget.md), [reviewed_no_checks](reviewed_no_checks.md).
