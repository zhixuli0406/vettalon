# prompt_byte_budget: This file did not fit in the module's prompt

## What it means

Each module prompt holds 48 KiB of source. Earlier files used it all, so no bytes of this file were sent. The file still counts in the module's source total, so the module cannot be reported as fully covered.

## Why you see it

The module is large, or its first files are. The file record says `budget_excluded`, and the module becomes `partially_reviewed` (or the run `incomplete`).

## What to do

Review the omitted file yourself. Or split the module into smaller directories so each part fits in one prompt, then rescan with `vettalon scan . --profile deep`.

## Related

[prompt_byte_budget_utf8_boundary](prompt_byte_budget_utf8_boundary.md), [partially_reviewed](partially_reviewed.md).
