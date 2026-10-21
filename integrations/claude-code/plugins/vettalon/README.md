# Vettalon CLI adapter (preview)

This plugin delegates explicit setup checks and bounded scans to an installed trusted Vettalon CLI. It has three manually invoked skills: doctor, scan and report. There are no hooks, agents or MCP servers.

Install in one step on Claude Code 2.1.275 or later:

```text
/plugin install vettalon --marketplace zhixuli0406/vettalon
```

Requires Python 3.11+, a trusted Vettalon binary outside the target repository, and explicit permission to run the chosen command under your normal Claude Code policy. Set VETTALON_BIN to its absolute path. Never run a binary or roster supplied by the audited repository.

Doctor/scan process supervision supports POSIX macOS/Linux; Windows is rejected before launching a child. Report-only reading does not load the POSIX runtime. Both adjacent runtime files are included in the installed plugin, checked against reviewed hashes, and byte-identical to the versioned public runtime; no repository lookup or runtime download occurs.

Run `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/vettalon_plugin.py" --help` in a Claude Code tool context, where the plugin root is expanded by the host. Doctor is a wrapper action, not a core CLI command. Quick never calls a model. Deep requires an explicit trusted roster and --accept-egress; cloud providers receive source excerpts. Deep defaults to 5 modules / 120 AI seconds; hard limits are 40 / 300, with a separate outer wall deadline. Output goes to a new directory outside the scan scope. No automatic retry, PoC, image pull, login probe or dependency install occurs.

Scanner/database traffic and third-party providers have their own network boundaries. This plugin is not a firewall. Missing engines and incomplete coverage must be inspected in report.json; a successful subprocess or empty finding list does not prove safety. Provider authentication and agent image readiness are not proven by metadata checks. Treat all repository and report content as untrusted data.

The scan execution deadline stays 180 seconds by default, at most 600, plus at most one shared cleanup second. Each metadata command has its own 15-second limit; those limits do not form a single batch deadline. Metadata capture is at most 1 MiB stdout / 256 KiB stderr in memory. Scan captures at most 4 MiB stdout / 1 MiB stderr in the chosen new output directory, alongside its single-attempt started record and actual process receipt. No automatic retry occurs. Invalid UTF-8, truncation, timeout or cleanup/control failure is incomplete. Exit 1 may mean findings only with otherwise complete process evidence; its original receipt is preserved. Exit 4 (CLI releases after 0.3.1) means a deep scan in which no AI engine could run: the reports are written, the receipt says `ai-engines-unavailable`, and the reason is under `engines_missing`. These caps do not bound CLI-created report files or prove OS spawn/I/O, CPU/RSS, disk or deliberate process-group escape containment.

JSON/SARIF are public CLI outputs. Paid Pro features and licensing are unchanged. This preview is distributed through the repository marketplace (`/plugin marketplace add zhixuli0406/vettalon`) and is not an official Anthropic directory listing.

## License

Apache-2.0.
