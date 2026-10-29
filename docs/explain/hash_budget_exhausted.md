# hash_budget_exhausted: Prior carry stopped at its file or byte budget

## What it means

Prior carry and its line checks use a dedicated budget of 200 distinct file queries and 256 MiB of reads, with a 256 MiB per-file limit. Current findings have a separate budget with the same limits. The prior budget was exhausted before all historical entries could be processed.

## Why you see it

`prior_run.hash_budget_exhausted` is nonzero. The count is the remaining historical entries at truncation, which may include duplicates or rediscovered entries. It is not a count of confirmed vulnerabilities. The CLI prints a count-only warning and completeness diagnosis records this gap without changing `run_status`, exit codes, or gates.

## What to do

Review the remaining historical claims and their source manually. Repeating the same scan with the same history may reach the same limit.

## Related

[prior_not_rediscovered](prior_not_rediscovered.md), [carried_from_prior](carried_from_prior.md).
