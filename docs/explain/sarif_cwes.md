# sarif_cwes: The SARIF result named more than one CWE

## What it means

The finding came from a SARIF log (`vettalon verify --input <log.sarif>`), and that result named several CWE ids. The item lists all of them, for example `sarif_cwes: CWE-319, CWE-614`. The finding's `cwe` field holds one of them.

## Why you see it

`verify` collects every CWE a SARIF result names: the result's `taxa` in the CWE taxonomy, the result's tags, the rule's tags (such as `external/cwe/cwe-614`), gosec's rule `relationships` into the CWE taxonomy and Snyk Code's rule `properties.cwe`. The finding's `cwe` is the first of them, except that when one of them is on the per-CWE trust policy list (CWE-327, CWE-328, CWE-501, CWE-614), that one is used, so a model refutation alone cannot close the finding. At most 16 ids are listed; the rest are counted.

## What to do

Check which weakness the scanner meant and whether the code has it. If the finding is closed or kept for a CWE other than the one in `cwe`, record that in your own decision.

## Related

[trust_policy](trust_policy.md), [static_hit](static_hit.md), [refuted](refuted.md).
