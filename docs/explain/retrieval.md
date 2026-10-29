# retrieval: Missing definitions were looked up and the refuter was asked again

## What it means

The refuter answered `unresolved` and named code it could not see. Vettalon searched your checkout for those definitions with a plain search, no model involved, and asked the same question once more with the excerpts. If the second reply fails or is malformed, the unresolved result stands.

## Why you see it

You set `--refuter-policy evidence+retrieval`. It is opt-in.

## What to do

Read the retrieved locations and the final verdict. Code the search did not find still needs your review.

## Related

[verify_uncertain](verify_uncertain.md), [refute_basis](refute_basis.md).
