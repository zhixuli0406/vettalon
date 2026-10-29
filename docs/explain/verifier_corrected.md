# verifier_corrected: The refuter fixed a wrong line number in the finding

## What it means

The refuter agreed the root cause is real but saw that the finder cited the wrong line or trace location. Its correction passed the same local checks as the original claim, so the finding's `line`, `trace` and snippet were updated from the file on disk. The finding's id and root fingerprint stay the same. A correction that fails those checks leaves the finding `candidate` with a `verify_error`.

## Why you see it

The refuter returned `plausible` with `corrected_line` or `corrected_trace`.

## What to do

Check the corrected location in the code, and read the refuter's verdict that went with it.

## Related

[precheck](precheck.md), [plausible](plausible.md).
