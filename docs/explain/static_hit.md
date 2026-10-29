# static_hit: A scanner reported this finding

## What it means

A rule-based scanner (Semgrep, Gitleaks, OSV-Scanner or cargo-audit) found a match. No model is involved. Scanner findings stay `candidate` and keep the rule's severity, so they count toward `--fail-on`. A scanner match is not an exploit. The rule may not apply to how your code is used.

## Why you see it

Every scan runs the scanners, including the default quick profile.

## What to do

Read the scanner rule and the file or dependency it names, and check whether the affected function is actually used.

## Related

[static_only](static_only.md), [adversarial_review](adversarial_review.md).
