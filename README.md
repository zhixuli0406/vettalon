# Vettalon

<div align="center">

**English** · [繁體中文](README.zh-TW.md)

</div>

[![CI](https://github.com/zhixuli0406/vettalon/actions/workflows/ci.yml/badge.svg)](https://github.com/zhixuli0406/vettalon/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

Vettalon finds security vulnerabilities in your own code: AI models from several vendors split up the review, then a model from a different vendor tries to refute each finding, and only the findings it can't refute are kept.

![Vettalon demo](docs/assets/demo.gif)

Open-source scanners (semgrep, gitleaks, cargo-audit) run a deterministic pass first, and `--profile deep` adds the AI review on top. Most AI security review tools are tied to a single model; Vettalon can mix subscription CLIs such as Claude, Codex and Grok, and also works with any OpenAI-compatible API and a local Ollama. Every model reply has to pass a strict format contract and a location check that uses no LLM, so a finding that cites a made-up file name or line number is refuted on the spot.

## Quick start

```bash
git clone https://github.com/zhixuli0406/vettalon.git vettalon && cd vettalon
cargo install --path crates/vettalon   # or download a prebuilt binary, see "Install"
vettalon scan .                        # open-source scanners only (free, offline)
vettalon scan . --profile deep --report report.json --sarif report.sarif   # add the AI audit
```

Deep mode needs at least one model; see [Install](#install) for the options.

## Sample output

```
$ vettalon scan fixtures/demo-app --profile deep --poc --finders claude --verifiers codex
程式碼安全審計（vettalon）
  ...
AI 深度審計／對抗式覆核／PoC（deep profile）：
  AI 候選：2　已證偽：0（其中前置檢查證偽 0）　待人工覆核：2　PoC 已執行：2
  模組覆蓋：共 4　已審 4（無候選 2、有候選 2）　延後 0　失敗 0
  覆核獨立性：全部跨家族覆核（找洞：claude；覆核：codex）
結論：未達 --fail-on 門檻（high），視為通過。
```

The terminal summary is currently printed in Traditional Chinese only. In English, the lines above read: "AI candidates: 2, refuted: 0 (0 of them by the pre-check), awaiting human review: 2, PoCs run: 2; modules: 4 total, 4 audited (2 with no candidates, 2 with candidates), 0 deferred, 0 failed; verification independence: all cross-family (finder: claude, verifier: codex); result: below the `--fail-on` threshold (high), treated as a pass."

(A finding the AI reported but no human has confirmed yet has the status `needs_human`. By default it doesn't count toward `--fail-on`; add `--fail-on-needs-human` to make it fail CI.)

## Install

Requirements:

- macOS or Linux (container isolation, the PoC sandbox and 0600 file permissions rely on Unix-only mechanisms; Windows isn't supported yet)
- Rust 1.88 or later (`cargo`)
- For deep mode, at least one model, any of:
  - a logged-in `claude` (Claude Code). `codex` and `grok` also work; by default they run inside a container sandbox (needs Docker; run `vettalon agents build` once first). Details in "Security boundaries" below.
  - an API key for an OpenAI-compatible API (kept in an environment variable)
  - a local Ollama
- Optional: `semgrep`, `gitleaks`, `cargo-audit` (each runs only if installed)
- Optional, needed for `--poc`: Docker, with the image pulled in advance: `docker pull python:3.12-slim`

```bash
git clone <this repo> vettalon && cd vettalon
cargo install --path crates/vettalon
vettalon models --probe      # check which models are found and whether they can be reached
docker pull python:3.12-slim  # only needed for --poc
```

You can also download a prebuilt binary (macOS arm64/x64, Linux x64/arm64): get the `vettalon-<platform>.tar.gz` for your platform from [Releases](https://github.com/zhixuli0406/vettalon/releases) and check it against the `.sha256` file of the same name, or verify the signature with cosign (`.sig`, `.pem`).

To scan in GitHub Actions and send the results to code scanning, use [vettalon-action](https://github.com/zhixuli0406/vettalon-action):

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v7
  - uses: zhixuli0406/vettalon-action@v1
```

## Usage

```bash
# Open-source scanners only (free, offline)
vettalon scan .

# AI deep audit: the top 5 highest-risk modules, split across the models
vettalon scan . --profile deep --report report.json --sarif report.sarif

# Choose who finds and who verifies; audit more modules; run sandboxed PoCs for findings of High and above
vettalon scan . --profile deep --finders claude,grok --verifiers codex --max-modules 12 --poc

# High-risk modules get two model families by default; --cross-check-top adds the top N scored modules to the double review
vettalon scan . --profile deep --cross-check-top 5

# Save a copy to ~/.vettalon/reports; on the next scan, files that haven't changed reuse the previous verdicts
vettalon scan . --profile deep --save

# Check whether a report file has been broken or altered
vettalon validate report.json

# Audit every module (--max-modules 0; still bound by the safety cap of 40 modules, the rest are listed as deferred)
vettalon scan . --profile deep --max-modules 0 --report report.json

# Give the AI deep audit an overall time budget: when it runs out, the remaining modules are deferred
# and the run is marked incomplete, instead of grinding on without end
vettalon scan . --profile deep --time-budget 1200 --report report.json

# Record a trace of every model call (JSON Lines: step, model, byte counts, latency, outcome; no content)
vettalon scan . --profile deep --trace trace.jsonl

# Policy gate (repeatable): fail CI when more than 0 findings of "high" or above are upheld by a
# cross-family verifier or confirmed by a human.
# With --gate and no --fail-on, only the gate conditions decide the exit code.
vettalon scan . --profile deep \
  --gate 'severity>=high status=confirmed,needs_human cross_family count>0'

# Disclosure drafts: first list the findings that can be submitted, then generate a draft for one of them on a given channel
# (drafts only, never submitted for you; only findings that verification left as "needs human judgment", or that a human confirmed, qualify)
vettalon disclose report.json
vettalon disclose report.json --finding <id> --channel twcert --out draft.txt

# Supply-chain hunt: audit the source code of the OSS packages your project depends on, looking for new vulnerabilities not yet on record
# Preview what would be audited first (no tokens spent), then run it for real
vettalon hunt . --dry-run
vettalon hunt . --finders claude --verifiers codex --max-deps 20

# Write the full report, and draft upstream disclosures for new vulnerability candidates (drafts only, never sent)
vettalon hunt . --report hunt.json --disclose-dir drafts/
```

### Supply-chain hunt (`vettalon hunt`)

`vettalon hunt <project>` reads the dependencies from the project's lockfile (Cargo.lock, npm `package-lock.json`, pip `requirements.txt`, Go `go.sum`), fetches their official released source code and audits it, looking for new vulnerabilities **that haven't been assigned a CVE yet**. This complements existing SCA tools, which match against known CVEs. It first queries OSV to sort versions into "known" and "possibly new". By default it audits **direct dependencies only** and skips versions that already have a CVE in OSV (SCA tools already track those), so the AI budget goes to what isn't on record. Each dependency gets the same cross-family adversarial verification as `scan --profile deep`. Only new findings that are confirmed and whose PoC runs successfully are listed as disclosure candidates.

Flags: `--max-deps N` (cap, default 20), `--include-transitive` (include indirect dependencies too), `--reaudit-known` (also audit versions with known CVEs), `--dry-run` (preview the selection only; nothing is fetched and no tokens are spent), `--report <file>` (write the full JSON), `--disclose-dir <dir>` (write upstream responsible-disclosure drafts for new candidates, with a pre-submission checklist; drafts only, never sent), `--dep-timeout <seconds>` (time limit for each dependency's fetch + audit, default 300; on timeout it records an error and carries on), `--dep-concurrency N` (how many dependencies to audit at the same time, 1–4, default 2; total token use stays the same, but each model receives N calls at once, so lower it if a CLI account hits rate limits), `--poc`, `--finders`/`--verifiers`. OSV is queried in batches, so even a large dependency tree takes only a few requests. Hunt mode goes online to fetch source code and query OSV, with egress limited to the package registries and `api.osv.dev`. The audited project's own private code never leaves the machine; the only thing sent out is each dependency's `name@version`. The zero-network behavior of `scan` is not affected.

The paid Vettalon Pro can also turn a hunt report into an enterprise supply-chain report (Word/PDF/HTML).

### Disclosure drafts

`vettalon disclose` works out the reporting channel from the repo itself (git remote, SECURITY.md, package metadata; no network access) and generates a draft, with a suggested public disclosure date, in one of these formats: a GitHub private vulnerability report, the project's security email address, Taiwan's TWCERT/CC (90 days to public disclosure suggested) or HITCON ZeroDay (60 days). You have to fill in the "reproduced by a human / not yet reproduced" field in the draft yourself. Only findings that verification left as `needs_human`, or that a human confirmed, can get a draft; findings that were never verified or were refuted are rejected. vettalon never submits anything for you.

### Policy gates (`--gate`)

`--fail-on` only looks at severity. `--gate` is a conditional gate. You can stack several; the run fails if any one of them matches, and the result is written to the report's `summary.policy`:

| Syntax | Meaning | Default |
|---|---|---|
| `severity>=LEVEL` | Count only this level and above (critical/high/medium/low/info) | `info` |
| `status=a,b` | Count only these statuses (candidate/confirmed/needs_human; false positives and exclusions can't be used in a gate) | `candidate,confirmed` |
| `cross_family` | Count only findings that a cross-family verifier upheld, or that a human confirmed | no restriction |
| `count>N`/`count>=N` | Fail once the count reaches this (required) | — |

With `--gate` and no `--fail-on`, `--fail-on` is treated as `none`; with both, failing either one fails the run. Human verdicts added to the report later recompute the gate result. `summary.policy` only proves that the result is consistent with the conditions stored in the report, not that those conditions weren't changed; the exit code at scan time is what counts.

Exit codes: `0` the `--fail-on` threshold wasn't reached and every `--gate` condition passed; `1` failed; `2` the scan itself couldn't finish (bad path, malformed gate condition, report couldn't be written, and so on).

### Module ranking (`--rank`)

By default the deep scan uses a built-in heuristic ranker to decide the order in which modules are audited (git hotspots, entry points, risk score), with **zero network access**. There is also an optional `--rank jev`: it sends the modules' **metadata** (path, file extension, size in bytes, whether it's an entry point, git hotspot count; **no code content of any kind**) to TypeSafe Jev, which ranks them so the high-risk files land inside the audit quota. In benchmarks, Jev raised the deep scan's hit@40 from 6/9 to 8/9 (see the [benchmarks on the website](https://vettalon.dudustudio.monster/#benchmarks)).

```bash
# Default heuristic (zero network)
vettalon scan . --profile deep

# Rank with Jev (needs [jev] set in the config)
vettalon scan . --profile deep --rank jev
```

- **Only `--rank jev` goes online**; without this flag, scan stays zero-network.
- Before anything is sent, `assert_metadata_only` checks the payload against the source code file by file, and fails closed if any code content would leak.
- When Jev is unavailable (offline, timeout, error response), it falls back to the heuristic with a one-line notice and the scan isn't interrupted.
- Jev only ranks; it **does not replace** the finders or verifiers.

Key setup (two options; the config never stores the key itself):
```toml
[jev]
api_key_env = "TYPESAFE_API_KEY"                            # option 1: name of an environment variable
# api_key_file = "/home/you/.config/vettalon/typesafe.key" # option 2: a 0600 key file
```
Resolution order: the environment variable wins if it has a value, otherwise the key file is read. The key exists only for the duration of the call; it is never written to disk, to the report or to logs.

**For end customers**: Jev is off by default, and customers decide for themselves whether to turn it on. Every time `--rank jev` is used, the CLI prints a line saying it is sending metadata to <host>. Customers use **their own TypeSafe key** (BYOK), and billing and data processing are between the customer and TypeSafe. File paths alone can reveal internal project names; if nothing at all should leave the machine, use the heuristic ranker (the default). TypeSafe's data retention period depends on its terms (no fixed number of days on non-enterprise plans; zero data retention (ZDR) is available on enterprise plans only).

### Model configuration

Without a config file, vettalon uses only `claude`, because it is the only CLI whose tools can be turned off completely. Everything is then handled by the same model, and the report marks it as "same family, self-verified". To split the work across several models, copy [`vettalon.example.toml`](vettalon.example.toml) to `~/.vettalon/config.toml`, or point to a file with `--config`. A config file inside the scanned repo is rejected: the config decides which programs run and where keys are sent, so the code under review must not get to decide that.

```toml
[[model]]
id = "claude"
backend = "cli"
preset = "claude"

[[model]]
id = "qwen-local"
backend = "ollama"
family = "qwen"
model = "qwen2.5-coder:7b"
roles = ["finder"]

[[model]]
id = "deepseek"
backend = "openai"
family = "deepseek"
base_url = "https://api.deepseek.com/v1"
model = "deepseek-chat"
api_key_env = "DEEPSEEK_API_KEY"   # keys live only in environment variables; the config file doesn't accept keys
```

Config file rules:
- APIs must use `https://`; only localhost may use `http://`.
- `api_key_env` only accepts names ending in `_API_KEY`, `_KEY` or `_TOKEN`; `AWS_*` is not accepted.
- A custom CLI's `program` must be an absolute path.

## Security boundaries

The code under review is untrusted data and may hide instructions written for the model (prompt injection). vettalon has these layers of protection:

- Every CLI call runs in a fresh, empty temporary directory, and only allowlisted environment variables are passed through, such as `HOME`, `PATH` and the variables that CLI needs for authentication.
- Any path a model mentions is canonicalized first and read only if it is still inside the repo; symlinks pointing outside the repo are not read.
- Before reports and SARIF are written, secrets are masked in every free-text field, and the files have 0600 permissions from the moment they are created. SARIF contains no local absolute paths.
- Before the audit, the code is scanned for hidden instructions aimed at the model (see item 6 of "How it works"), so an injection telling the model to report the code as clean can't slip through unnoticed.

**Whether a CLI's tools can be turned off differs by CLI (tested 2026-10-12):**

| CLI | Flag to disable tools | Result |
|---|---|---|
| claude | `--tools ""` | Works; the model has no tools at all |
| codex | `--sandbox read-only`, plus disabling user config, MCP, apps, hooks and plugins | the shell **can still read any file on the machine** |
| grok | `--tools ""` | **Doesn't work**; it can still read files and run commands |

So codex and grok **run in a container sandbox by default**:

- Run `vettalon agents build` once to build the image (pinned versions of codex and grok, plus an egress proxy).
- Each call starts a fresh container that holds only a copied-in auth file and an empty working directory; it can't see the host's filesystem or environment variables.
- The container is attached to an `--internal` Docker network with no outbound route. The only way out is the proxy, which allows only the model vendors' domains and refuses everything else.
- Tested: grok inside the container, asked to read a host file, replied that the file doesn't exist.

Residual risk: the model inside the container can still read the copied-in auth file, and in theory could send it to one of the allowlisted vendor domains.

If you are sure you only audit code you trust and want to skip the extra time the container adds, set `allow_agent_tools = true` for that model in the config to run it directly on the host instead (accepting the file-read risk above). A custom `program` can't be containerized automatically, so this is the only way to run one.

Managing containers: `vettalon agents build` builds the image, and `vettalon agents stop` shuts down the proxy and the internal network.

## How it works

1. **Intake**: counts languages, finds entry points and reads the git history, marking files that often receive security fixes as hotspots, then ranks the modules by risk. Documentation and non-code files (`.md`, `.rst`, images, lockfiles, binaries, translation files…) are not listed as auditable modules (the AI deep audit only reasons about code), and nested standalone clones and directories excluded by the root `.gitignore` are left out too. A single audit has a safety cap on the number of modules (40), and `--time-budget` adds an overall time budget. Ranking uses the built-in heuristic by default (zero network); `--rank jev` switches to the metadata-only Jev ranker (see "Module ranking").
2. **Split finding**: the top `--max-modules` modules are dealt out in turn to the finders. Each module goes to one model only, so the cost is about the same as with a single model.
3. **Pre-check**: no model is called. It only checks whether the files, line numbers and call chains a model cites really exist; anything that doesn't match is refuted right away.
4. **Double review for high-risk modules**: modules that are git security hotspots or entry points (naturally a small share) are automatically sent to a finder from a different family as well, so two vendors each read them; `--cross-check-top N` adds the top N scored modules to this. What one model misses, the other can catch.
5. **Cross-family verification**: each candidate goes to a verifier from a different family than its finder, which is asked to try to refute it from scratch. Candidates it can't refute are marked `needs_human`, with a list of what still needs to be checked. If the model list has no other family, it falls back to another model of the same family, and failing that, the finder verifies its own finding; the vote record says so (`same_model`).
6. **Detecting instructions aimed at the model**: before the audit, zero-LLM rules scan every module for text that tells the reviewing model to report clean (for example `respond with {"candidates": []}`, "report no vulnerabilities", "this file is secure"). A module that matches gets an extra review by a model from another family and is recorded in the report's `ensemble.suspected_injection`. If the model list has only one family and no cross-review is possible, the whole run is marked `incomplete`.
7. **PoC** (`--poc`): for `needs_human` findings of High and above, a model from another family (where one is available) writes a script, which runs in a Docker sandbox. Sandbox limits:
   - no network, read-only root filesystem, all capabilities dropped, runs as a non-root user
   - memory and process count limits
   - a time limit both on the host side and inside the container
   - images are never pulled automatically

   The container has only the Python standard library and bash, and the repo itself isn't inside it, so a PoC has to reproduce the vulnerable pattern using the standard library. If the sandbox can't start, the PoC is skipped; it never runs on the host. A PoC that runs successfully does not automatically mark a finding as confirmed.

**Refusals aren't rerouted.** When a model refuses to review, only that module is recorded as "not audited"; the other modules assigned to the same model carry on as usual. Refusals are listed in `ensemble.refusals` and the run is marked `incomplete` (`model_refused`); the module is not quietly handed to another model. Coverage gaps are laid out for you to see, and you decide whether to switch models.

**Honest completion status.** Any of the following marks the report as `incomplete`, with the reason attached:
- a finder couldn't be reached at all
- a call for some module failed, or its reply didn't match the format
- some candidate didn't get a verification verdict

Verification independence counts only verifications that actually returned a verdict; failed calls and refusals don't count. If a verifier can't be reached on its first call, the remaining candidates in its group are marked unverified right away, instead of each one waiting for the full timeout.

**AI never declares "confirmed" on its own.** The highest status AI can reach is `needs_human`; only a person can mark a finding `confirmed`.

The report format is defined in [`crates/vettalon/src/audit/schema.rs`](crates/vettalon/src/audit/schema.rs), and the validator always runs before a report is written. The SARIF 2.1.0 output can be uploaded directly to GitHub code scanning; refuted findings are marked as suppressed rather than deleted. Each result's properties also carry the CAPEC attack patterns for that finding (`vettalon.capec`) and an exploitability grade derived from its preconditions (`vettalon.exploitability`: direct/conditional/hard_to_reach). For findings with a CWE mapping, the report adds a section with an attack scenario and CAPEC reference links. `--trace` writes a separate JSON Lines file with one entry per model call (step, model, byte counts, latency and outcome only; no content).

## Known limitations

- An ordinary module is reviewed by one finder only; if that model misses something, it stays missed. High-risk modules (hotspots/entry points), modules with suspected injection, and the top N chosen by `--cross-check-top` are reviewed by two vendors; the rest still get one. In testing, grok missed the path traversal in `fixtures/demo-app` in one round after finding it in the round before, because model output is random. Run important code several times, or switch models with `--finders`.
- Severity is rated by the model itself. For the same vulnerability, claude rated it high and codex rated it medium, and PoCs only run for findings of High and above.
- `osv-scanner` needs network access, so it is deliberately not called.
- semgrep's built-in rules are few, and they haven't been validated against a real semgrep install yet.
- The Grok CLI sends a system prompt of about 37k tokens with every call (about US$0.027 per call, measured 2026-10), and it leaves session logs in `~/.grok` that contain the audited code.
- gitleaks and semgrep read the ignore files that ship with the repo (`.gitleaksignore`, `.semgrepignore`), so an audited repo can use them to hide scan results.

## Development

```bash
cargo build
cargo test                                            # unit + integration tests; no real model is called
cargo test -p vettalon --lib sandbox -- --ignored    # tests against the real Docker sandbox
cargo clippy --all-targets
```

`fixtures/demo-app` is a deliberately broken test project; the answer key is in its README.

## Vettalon Pro

This repo is the open-source core of Vettalon. Everything listed above (scanning, multi-model splitting and cross-family verification, the PoC sandbox, SARIF, disclosure drafts) is free, with no feature locks or usage limits.

There is also a paid Vettalon Pro. It provides a desktop app, a local dashboard (set a time budget, cancel a scan at any time, plus a "Supply chain" tab for viewing hunt results and generating upstream disclosure drafts), and an enterprise report generator that follows the conventions of Taiwanese security assessment reports (PDF/Word/HTML). Pro reads the same `scan --report` JSON, and the core does not depend on Pro.

Pro needs a license key; see the [website](https://vettalon.dudustudio.monster/#editions). The open-source core needs no license and never checks for one.

## License

Apache-2.0, see [LICENSE](LICENSE). Code provenance and the third-party MIT notice (Cloudflare security-audit-skill) are in [NOTICE](NOTICE).
