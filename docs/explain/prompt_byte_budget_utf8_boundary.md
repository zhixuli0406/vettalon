# prompt_byte_budget_utf8_boundary: Too little prompt space was left for even one character of this file

## What it means

The module prompt (48 KiB) had a few bytes left, but not enough to cut a valid UTF-8 piece from the start of this file. Vettalon sends no partial characters, so it sent nothing and recorded the file as budget-excluded.

## Why you see it

Earlier files filled the prompt almost to the limit.

## What to do

Review the file by hand, or move it into a smaller module so it gets its own prompt. This is the same situation as `prompt_byte_budget`, just at the edge.

## Related

[prompt_byte_budget](prompt_byte_budget.md), [partially_reviewed](partially_reviewed.md).
