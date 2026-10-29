# max_modules: The module was ranked below the module limit

## What it means

A deep scan ranks modules by risk and sends only the top `--max-modules` to the models. The default is 5. This module ranked lower, so it is `deferred` and was not reviewed. It is not clean.

## Why you see it

The repository has more modules than the limit allows.

## What to do

Raise the limit, for example `vettalon scan . --profile deep --max-modules 12`. `--max-modules 0` reviews every module, up to a safety cap of 40, and costs more model calls. Or scan only what changed with `--diff-base <ref>`.

## Related

[deferred](deferred.md), [scope_not_fully_reviewed](scope_not_fully_reviewed.md).
