# prosecutor: A third call tried to break the refuter's reason for closing a finding

## What it means

When the refuter closes a finding because a guard or check stops the attack, the prosecutor makes one blind call that tries to bypass that guard. It sees the claim and the cited lines, but not the refuter's reasoning. A bypass whose path checks out against the real code vetoes the closure and keeps the finding open. A failed or unusable attempt leaves the closure standing.

## Why you see it

You set `--refuter-policy evidence+prosecutor`. It is experimental and off by default.

## What to do

Read the `prosecutor:` item and the finding's final `status`. A veto means the guard may be bypassable. Check the cited lines yourself.

## Related

[verify_uncertain](verify_uncertain.md), [refute_basis](refute_basis.md).
