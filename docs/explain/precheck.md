# precheck: Local checks found a problem with the finding's claim

## What it means

Before any refuter is called, Vettalon checks the finder's claim without a model. It confirms that the cited file and line exist, the trace steps are real and in the right order, and all six threat-model fields have text. This item lists the violations. The finding stays `candidate`, no refuter call is made, and it still counts toward `--fail-on` at its severity.

## Why you see it

The model cited a wrong line, an invented file or an incomplete trace.

## What to do

Check each violation against the real source. A failed pre-check says the claim is badly formed. It does not show the code is safe, so read the source around the real sink yourself.

## Related

[adversarial_review](adversarial_review.md), [verifier_corrected](verifier_corrected.md).
