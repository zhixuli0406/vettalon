# tier_disagreement: The finder and refuter disagree on how hard the attack is

## What it means

Both models list preconditions an attacker needs, such as authentication or a specific configuration. Vettalon turns each list into an exploitability tier. Here the tiers differ. The effective tier uses the one with more friction, meaning the harder attack. The finding is not settled by this.

## Why you see it

A refuter that judged the claim plausible listed its own conditions. The note reads `tier_disagreement: finder=... refuter=... effective=...`.

## What to do

Check which preconditions really hold in your deployment. The CLI summary, SARIF and the report all show this disagreement.

## Related

[severity_disagreement](severity_disagreement.md), [adversarial_review](adversarial_review.md).
