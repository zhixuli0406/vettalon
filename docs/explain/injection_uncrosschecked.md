# injection_uncrosschecked: Text aimed at the AI reviewer was found and only one model family reviewed it

## What it means

Before the audit, Vettalon scans every module for text that tells a reviewing model to report the code as clean. Modules that match should get an extra review from a model of a different family. Here every configured finder belonged to one family, so that second look was impossible. The matches are listed in `ensemble.suspected_injection`.

## Why you see it

Your model list has a single family, which is the default (`claude` only).

## What to do

Add a model from another vendor to `~/.vettalon/config.toml` or pass `--finders a,b`, then rescan. Until then, read the flagged modules yourself.

## Related

[incomplete](incomplete.md), [ai_analysis](ai_analysis.md).
