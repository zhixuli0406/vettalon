# severity_capped: Independent review supported a lower severity

## What it means

A plausible refuter from a different model family supplied an impact. Vettalon caps the claimed severity at the higher of the finder impact and the highest independent refuter impact. The original remains in `severity_claimed`.

## Why you see it

Both assessments support lowering the claim, for example `severity_capped: critical→high (finder impact=low, refuter impact=high)`. Same-family or same-model review cannot authorize this cap.

## What to do

Read both assessments. Gates and subsequent PoC selection use the effective `severity`. Without an independent plausible impact, severity stays claimed; refuted findings do not count toward gates.

## Related

[severity_cap_proposed](severity_cap_proposed.md), [severity_cap_unconfirmed](severity_cap_unconfirmed.md), [severity_disagreement](severity_disagreement.md).
