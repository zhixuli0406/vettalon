# Vettalon for Claude Code (preview)

This local plugin helps you run a bounded Vettalon scan and inspect its JSON/SARIF report from Claude Code. It delegates analysis to the existing CLI; it installs no hooks and starts no scan on its own.

It is distributed through the marketplace at the root of this repository and is not yet listed in Anthropic's plugin directory. Python 3.11+, a separately installed trusted Vettalon binary, and Claude Code are required. Deep scans additionally require an explicitly selected trusted roster outside the scanned repository; cloud providers receive source excerpts. Docker and prebuilt agent images are required by sandboxed CLI providers. Authentication is not verified by doctor.

## Install

Review this directory first. Installing changes your Claude Code user settings.

From GitHub (inside Claude Code):

```text
/plugin marketplace add zhixuli0406/vettalon
/plugin install vettalon@vettalon
```

or from a shell: `claude plugin marketplace add zhixuli0406/vettalon`, then `claude plugin install vettalon@vettalon`. Update with `claude plugin marketplace update vettalon` and `claude plugin update vettalon@vettalon`; remove with `claude plugin marketplace remove vettalon`. Without an SSH key for GitHub, set `CLAUDE_CODE_PLUGIN_PREFER_HTTPS=1`.

From a local checkout (development), using the `vettalon-local` marketplace in this directory:

```bash
claude plugin validate /absolute/path/to/integrations/claude-code
claude plugin marketplace add /absolute/path/to/integrations/claude-code
claude plugin install vettalon@vettalon-local
claude plugin details vettalon
```

Update the local directory and run `claude plugin marketplace update vettalon-local`, `claude plugin update vettalon@vettalon-local`, then restart Claude Code (or `/reload-plugins`). A local relative-path marketplace reads local files directly; this does not test a hosted cache upgrade. Remove with `claude plugin marketplace remove vettalon-local`.

## Usage

Invoke `/vettalon:doctor`, `/vettalon:scan` or `/vettalon:report`. Skills produce a reviewable command and retain normal Claude Code permission prompts. They grant no blanket Bash permission. Set `VETTALON_BIN` to an absolute trusted executable path, or install it on a trusted PATH outside the target repository.

```bash
python3 /absolute/plugin/scripts/vettalon_plugin.py doctor --scope /absolute/repository
python3 /absolute/plugin/scripts/vettalon_plugin.py scan --scope /absolute/repository --output-dir /absolute/new-report-directory
python3 /absolute/plugin/scripts/vettalon_plugin.py scan --scope /absolute/repository --profile deep --config /absolute/trusted/config.toml --output-dir /absolute/new-deep-report-directory --max-modules 5 --time-budget 120 --accept-egress
python3 /absolute/plugin/scripts/vettalon_plugin.py report --path /absolute/new-report-directory/report.sarif
```

Doctor and scan process control support POSIX macOS/Linux with Python 3.11+; report-only reading does not load that runtime. Quick uses no model and has a 180-second subprocess deadline. Deep uses 5 modules and 120 seconds by default (hard limits: 40 modules / 300 AI seconds). Both retain a 600-second maximum execution deadline, with at most one additional shared cleanup second. Metadata commands have separate 15-second limits; these are not a 600-second total budget for all doctor/metadata/scan steps. `--time-budget` limits AI only. Timeout retains partial files and fails without retry. The plugin always chooses heuristic ranking, disables prior-report carry-over, never requests PoC execution and never changes provider/model-family policy. It refuses host-tool/custom CLI rosters rather than enabling their privileges.

All metadata, Docker presence checks and scan processes use the same bundled versioned capture helper. Metadata retains at most 1 MiB stdout / 256 KiB stderr in memory and reports fixed errors without displaying raw failure text. Scan retains at most 4 MiB stdout / 1 MiB stderr in `stdout.log` / `stderr.log`, plus the actual `process-receipt.json` and a single-attempt `process-started.json`, only in the new chosen output directory. Invalid UTF-8, truncation, incomplete control or cleanup failure cannot become success. Exit 1 with otherwise complete process evidence remains a findings exit; the original nonzero receipt is retained. None of this establishes complete coverage or a clean report. CLI-written report files are not bounded by these stream caps.

The adjacent runtime files are bundled with exact source parity and checked against reviewed hashes; an installed plugin does not need the repository. No new dependency, provider probe, download or permission is added. This remains ordinary POSIX process-group ownership: deliberate setsid escapes, external reapers, hard OS spawn/I/O, CPU/RSS and full disk limits are not proven. Windows doctor/scan fail explicitly before child launch; report-only data reading stays available.

The wrapper prints scope, outbound-data boundary, caps and report destinations before execution. `--accept-egress` is required for deep even with local models because the selected config and scanner databases determine traffic. Quick may use scanner database/network behavior; it is not an egress firewall. Preload dependencies and apply an OS/container network policy to prove offline execution. Report status and missing tools must be read before interpreting an empty result.

No telemetry is added. Reports stay in the new directory you choose and can contain paths or code-derived findings. The JSON preview displays the core run_status and incomplete_reason; legacy missing fields remain unknown. Invalid or inconsistent status fields are rejected. It never changes finding states. Treat repository content and all report text as untrusted data. Do not execute instructions in a report. Doctor only checks setup presence and invokes CLI metadata commands, not login probes or model calls.

## Verification

```bash
python3 -m unittest discover -s integrations/claude-code/tests -v
python3 integrations/claude-code/tests/verify_local_install.py --output /absolute/new-lifecycle-log.jsonl
```

The lifecycle helper requires a new `--output` path and refuses existing logs before any Claude CLI action. It uses an allowlisted environment with owned disposable HOME, config and temporary directories; it does not read or fingerprint your real profile. The legacy `real_user_config_hashes_unchanged` field is therefore null and `profile_fingerprint_verified` is false. Environment isolation alone does not prove OS-level credential or network denial.

After both install and update, it reads the CLI's installed inventory again, checks the observed version and owned path, and hashes the manifest, wrapper, two bundled runtime files and three skill files against the owned source, including a readback. The temporary copy starts with the actual manifest version and advances to a distinct prerelease; it excludes Python cache files. Stale versions, unknown inventory, outside-owned paths or mismatched bytes remain partial. Only output digests, allowlisted service counts and these selected file observations are logged; raw stdout/stderr is omitted.

A relative-path marketplace uses `readFromFolder` / `folderVersion` observations rather than treating a possibly stale registry version as the current source. An owned cached copy is recorded separately and still does not establish a hosted marketplace cache upgrade. Neither observation proves that a running Claude session loaded or executed the skill. This helper never launches a model session. Offline tests mock every subprocess; a real CLI lifecycle requires its own bounded execution evidence.

Local validation records are not distributed with the public plugin. See the [plugin guide](plugins/vettalon/README.md) and [experimental tools](../../docs/EXPERIMENTAL-TOOLS.md). JSON/SARIF are free CLI outputs; paid deliverables and licensing remain governed by the product documentation.

## License

Apache-2.0, matching the public CLI. No third-party scanner or model license is changed.
