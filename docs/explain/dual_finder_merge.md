# dual_finder_merge: Two finder models reported the same root cause and were merged

## What it means

Two finder models from different vendors audited the same module and each reported this issue. Vettalon merged the two reports into one finding. The evidence names the merged id, the model, and the match basis (`same_patch` when their suggested fixes touch the same lines, or `location_cwe` for the same sink location and CWE). It can keep each model's severity assessment.

## Why you see it

You enabled `--dual-finder-top N`, which is off by default.

## What to do

Treat the agreement as a reason to look first, not as proof. Check the refuter's evidence on the finding.

## Related

[ai_analysis](ai_analysis.md), [adversarial_review](adversarial_review.md).
