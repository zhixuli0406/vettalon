# severity_cap_proposed: The finder proposed a lower severity

## What it means

The finder claimed an overall severity above its own impact rating. Vettalon records the proposed cap but keeps `severity` at `severity_claimed` until independent review supports a reduction.

## Why you see it

For example, `severity_cap_proposed: high→medium (finder impact=medium)` means the finder suggested medium impact for a high claim. This proposal alone cannot lower a gate threshold.

## What to do

Read the impact reason and check the review evidence. A plausible refuter from a different model family must report an impact before any reduction is allowed. Skipped or failed reviews keep the original claim.

## Related

[severity_capped](severity_capped.md), [severity_cap_unconfirmed](severity_cap_unconfirmed.md).
