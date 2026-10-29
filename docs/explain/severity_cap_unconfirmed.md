# severity_cap_unconfirmed: The finder's proposed severity reduction lacks independent impact evidence

## What it means

The finding keeps its claimed severity. This note appears only when the finder's own impact rating would have lowered that severity. A finder cannot lower it using only its own impact rating, so this record does not authorize a downgrade.

## Why you see it

The finder's impact would have lowered the severity, but no plausible refuter from a different model family supplied a usable impact. Review may be pending, skipped, unavailable, inconclusive, or missing an impact. A same-family verifier, including the same model, cannot authorize a reduction.

## What to do

Treat `severity_claimed` as the effective severity for this finding. Inspect the review evidence and arrange independent review if needed. Refuted findings remain excluded from gates.

## Related

[severity_cap_proposed](severity_cap_proposed.md), [severity_capped](severity_capped.md), [refuter_impact_missing](refuter_impact_missing.md).
