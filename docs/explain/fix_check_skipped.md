# fix_check_skipped: A step of the fix check could not run

## What it means

The fix check needs several steps: read the code excerpt, have a model write a small adapter, start the sandbox and run the tests. This note says which step failed. The structured `fix_check` item records the actual outcome, usually `fix_unverified`, with a reason.

## Why you see it

A prerequisite failed. Common causes are an unreadable excerpt, a failed model call, or Docker not running or the sandbox image not pulled.

## What to do

Read the note and the `fix_check` item together. If the sandbox was unavailable, start Docker and run `docker pull python:3.12-slim`, then repeat the check.

## Related

[fix_check](fix_check.md), [poc_skipped](poc_skipped.md), [fix_context_v1](fix_context_v1.md).
