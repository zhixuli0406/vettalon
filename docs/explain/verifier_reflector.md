# verifier_reflector: The refuter's reply was malformed, so it was asked again once

## What it means

A refuter reply broke the required format, for example it was not JSON, or it said `plausible` without blockers. A malformed reply is never a verdict. Vettalon asks once more with the problem named. The item records how many replies were re-asked and how many recovered.

## Why you see it

The default `--verifier-parse-retries 1` allowed the retry. `--verifier-parse-retries 0` turns it off.

## What to do

Read the final outcome. If the second reply also failed, the run counts as a `verify_error` and the finding stays `candidate`.

## Related

[verify_error](verify_error.md), [adversarial_review](adversarial_review.md).
