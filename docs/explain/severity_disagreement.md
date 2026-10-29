# severity_disagreement: The refuter rated the impact differently from the finder

## What it means

The refuter said the claim is plausible and gave its own impact rating (low to critical). It differs from the finder's. Both ratings are kept. The verdict does not change. Independent review can cap severity at the higher finder/refuter impact; without an independent impact, severity stays claimed.

## Why you see it

The note reads `severity_disagreement: finder impact=..., refuter impact=...`. With several runs, the run numbers are listed. SARIF carries `vettalon.severity_disagreement`.

## What to do

Compare both reasons and think about your deployment. The same flaw can matter more or less depending on who can reach it.

## Related

[severity_capped](severity_capped.md), [refuter_impact_missing](refuter_impact_missing.md), [tier_disagreement](tier_disagreement.md).
