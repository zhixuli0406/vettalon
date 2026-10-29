# fix_context_v1: The exact files and settings a fix check or reproduction used

## What it means

This record pins a check to the snapshot it ran on: hashes of the source file and the diff, a digest of the prepared copy of the repository, the harness and policy versions, and the sandbox image. The copy leaves out `.git` folders, symlinks, secret files and special files. It says nothing about what your repository looks like now.

## Why you see it

`vettalon fix check` or `vettalon reproduce` stored its receipt next to the check result.

## What to do

Compare the hashes with your current tree. If the code changed since, rerun the check before you rely on the result.

## Related

[fix_check](fix_check.md), [poc_oracle](poc_oracle.md).
