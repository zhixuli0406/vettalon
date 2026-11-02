# provider_usage_limit: Provider allowance exhausted for this scan

## What it means

A failed CLI invocation or HTTP error reported exhausted provider allowance. The scan-local breaker is shared by model id across finder, verifier, PoC and prescreen calls. Once detected, later calls for that id fail immediately without starting a backend process or HTTP request. Calls for the same id are serialized so queued work observes the breaker. Other model ids keep their own state, and a new scan starts with a fresh breaker.

Affected modules are `deferred` with reason `provider_usage_limit`. The run is `incomplete` with existing reason `units_failed`. Verifier and refuter exhaustion leaves the finding unverified (`candidate`), including exhaustion after earlier votes or in the prosecutor. Successful finder attempts and reviewed paths remain visible. Deferred here describes unfinished work in a later phase or another finder share.

## Why you see it

Detection is limited to nonzero process stdout/stderr and unsuccessful HTTP bodies. Successful model replies never enter the detector. A transient 429, rate limit, concurrency limit, context limit or disk quota does not trip the breaker.

CLI patterns were checked on 2026-11-02 against strings in the installed Claude Code and Grok 1.0.70 binaries, the installed Codex binary (`usage_limit_reached`), and the [Codex error formatter](https://github.com/openai/codex/blob/main/codex-rs/protocol/src/error.rs) (usage-limit phrase). Matching uses the program basename, ASCII lowercase and normalized apostrophes:

- Claude: `you've hit your limit`; `your credit balance is too low to access the anthropic api`.
- Codex: `usage_limit_reached`; `you've hit your usage limit`.
- Grok: `you hit your weekly limit`; `you hit your free usage limit`; `you've reached your free grok build usage limit`; `usage balance exhausted`; `usage_pool_exhausted`; `usage_limit_reached`.
- OpenAI-compatible HTTP: a parsed `error.code` or `error.type` exactly equal to `insufficient_quota`.

These are conservative known markers. Other messages remain ordinary failures. Container CLI execution applies the same detector. Successful CLI exit codes remain successful even when their content mentions an allowance limit.

## What to do

Use `--save` to retain the report. Restore provider allowance, then rerun the same command with prior-run loading enabled. Saved deferred modules enter the existing prior-gap priority, subject to the module cap and scope. Without a saved report, the next run cannot recover those priorities. `--no-prior` disables them.

## Related

- [deferred](deferred.md)
- [units_failed](units_failed.md)
- [prior_gap](prior_gap.md)
