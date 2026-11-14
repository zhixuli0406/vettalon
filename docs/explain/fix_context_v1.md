# fix_context_v1: The exact files and settings a fix check or reproduction used

## What it means

This record pins a check to the snapshot it ran on: hashes of the source file and the diff, a digest of the prepared copy of the repository, the harness and policy versions, and the sandbox image. The copy leaves out `.git` folders, symlinks, secret files and special files. It says nothing about what your repository looks like now.

The fix check detail the record covers has 12 parts: `fix_check: outcome= original= variants= benign= tests= inputs=k/n decoding=b/a/t diff_sha256= reason= blocker= variant_set_sha256= variant_generator_version=`, under policy `vettalon-fix-check-v4`. `check_sha256` covers all of it, including `blocker`. A record made under an earlier policy (the single `regression=` detail of 6, 7 or 9 parts) is read as legacy and never shows as verified; rerun the check to get a current one. A pass in it means only that no effect was observed for this revision, these inputs and these variants.

For a fix check, `harness_sha256` covers every variant runner that check can execute, including inputs that only need decoding, plus the benign runner. The scan-time PoC harness hash stays on the single base input.

## Why you see it

`vettalon fix check` or `vettalon reproduce` stored its receipt next to the check result.

## What to do

Compare the hashes with your current tree. If the code changed since, rerun the check before you rely on the result.

## Related

[fix_check](fix_check.md), [poc_oracle](poc_oracle.md).
