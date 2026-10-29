# unresolved: The refuter could not decide, so the finding stays open

## What it means

Under the conservative refuter policy, closing a finding needs cited, checked evidence. Here the refuter either could not decide, or its refutation failed the citation checks. The detail reads `unresolved:` or `unresolved (downgraded refutation: ...):`. The finding stays `candidate`, which counts toward `--fail-on`, and the facts that would decide it are listed as blockers.

## Why you see it

You set `--refuter-policy evidence+retrieval` (or another `evidence` policy). The default policy does not produce it.

## What to do

Read the blockers and supply the missing code or facts. Then decide the finding yourself.

## Related

[verify_uncertain](verify_uncertain.md), [retrieval](retrieval.md), [refute_basis](refute_basis.md).
