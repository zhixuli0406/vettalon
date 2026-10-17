# Data flow and network boundaries

Vettalon orchestrates scans on the operator's machine. **Deep review sends selected
source code and review context to the configured model provider.** A local process,
CLI subscription, local dashboard, or heuristic ranker does not make a cloud model
local. Choose providers and review their retention terms before scanning sensitive code.

## Mode and provider matrix

| Operation | Outbound data / destination | Offline prerequisites and limits |
|---|---|---|
| `scan` (quick) | Local scanner subprocesses; no Vettalon model or Jev request | Preinstall scanner binaries. Semgrep uses bundled rules, `--metrics=off` and `--disable-version-check`; cargo-audit uses `--no-fetch` and requires a cached RustSec DB. These flags are not an OS firewall or proof about every installed tool version. Baseline OSV scanner is deliberately disabled by source policy because it requires network; it is distinct from hunt OSV lookups. Missing engine/DB is a coverage gap. |
| `scan --profile deep --rank heuristic` + remote HTTP model | Selected source excerpts, paths, prompts, findings, verifier and PoC-generation context go to configured API base URL | Heuristic ranking itself makes no network requests. The model requests still leave the machine. Never infer scan privacy from rank strategy. |
| Deep + CLI provider | Prompt including source is passed to selected CLI via stdin/arguments/a temporary prompt file; the CLI may send it to its provider | Vettalon cannot establish the CLI's internal network/retention behavior. Agent container isolation limits filesystem access; it does not turn cloud inference into offline inference. |
| Deep + local Ollama / loopback HTTP | Same source-bearing prompts go to loopback endpoint | Preload model weights, scanners, rules/DB and Docker images. Keep Jev off, use local providers for **every** role; independently deny external egress. Loopback address does not prove the server itself has no outbound connections. |
| `--rank jev` (deep only, explicit opt-in) | Paths, extensions, sizes, entry-point flags, git touch counts and language/git metadata go to configured Jev endpoint | No source content in this ranking payload. Paths may disclose project names. Payload guard rejects source-like content. Missing credentials/config fail the request; unavailable/error ranking falls back with a notice to heuristic. Model requests remain a separate data flow. |
| `hunt` | Dependency identities to OSV; source archives from allowed registries; dependency source/context to selected deep-review models | Online operation. OSV requests/redirects stay on HTTPS `api.osv.dev:443`; registry requests/redirects stay on the HTTPS allowlist at port 443. Both limit redirects to three hops, use a 30-second request timeout, and disable retries; the per-dependency total timeout remains separate. The registry/OSV allowlist governs fetching/lookup, **not** model-provider egress. The host project's own source is not the dependency audit input; package identities can still reveal project composition. OSV miss means unlisted candidate, not proven novelty. |
| `disclose` | Draft files and local repository metadata | Does not submit or send messages. Human review, channel and disclosure authorization remain required. |
| `--poc` | Model receives selected source/context to generate a script; script runs in network-disabled Docker | Preload image. Existing sandbox reproduces a **pattern**, not the complete target application. Success never sets `confirmed`. |
| Report / SARIF | Local output files; integrations upload only if the operator does so | Source excerpts and findings can be sensitive despite secret masking. Reports are not proof that no source was sent during review. |
| Install / doctor / agent image build / trust tools | Package registries, model/image downloads, version probes, GitHub verification or explicitly requested inventory tools | Prepare separately. Their traffic must not be confused with a scan's observed traffic. |

## Consent, failure, and state

Model roster configuration is the operator's selection of destinations. Files under
review cannot supply the trusted configuration. `--rank jev` consents to that
additional metadata flow for that run; omitting it must not call Jev. No background
usage telemetry is introduced by the trust tooling. Third-party scanner/CLI
telemetry must be controlled and verified separately.

A transport/parse/read failure, cap or exhausted budget must remain visible as an
incomplete run/coverage gap. Empty findings are not a complete security assessment.
AI can leave a finding at `needs_human`; only an explicit human triage may set
`confirmed`. A successful pattern PoC and OSV non-match are different evidence types.

Secret-bearing filenames are excluded from AI context according to the maintained
list. Hard-coded secrets in ordinary source can still be sent; masking local report
output is not a preventive source-redaction guarantee.

Installed scanner execution failures and timeouts make the run incomplete. Cargo
empty/malformed output or a missing advisory DB cannot be a clean zero; Semgrep
partial errors retain usable candidates and an error record. Gitleaks must produce
a readable JSON report. Semgrep is invoked without `--error`, so nonzero exits are
errors even when candidates exist; its version check is explicitly disabled.
These choices follow the [official Semgrep CLI contract](https://docs.semgrep.dev/cli-reference).
A separate 2026-10-16 acceptance used Semgrep **1.181.0**, installed in an
isolated test venv, with an OS `network*` deny policy and a denied socket control.
Direct execution and the Vettalon adapter each scanned self-authored
Python/JavaScript/TypeScript fixtures: the positive case covered all six bundled
rule IDs (eight findings), and the selected safe case returned zero findings;
Semgrep `errors` was empty in both. The two Vettalon reports were complete for
that selected engine/scope and passed validation, with source hashes unchanged.
Raw version/argv/policy/results are in
`reports/evidence-acceptance/root/semgrep-live-20261016/{commands,result}.json`.
This establishes only that version, bundled rules, fixtures and OS configuration;
it does not establish all-scanner offline behavior, general detection quality or
arbitrary source safety. The isolated installation is acceptance setup, not an
automatic scanner installation feature. Earlier missing-binary runs remain
historical coverage gaps, not successful Semgrep executions.

On Unix, the scanner executor owns a private process group. It observes the
leader with `waitid(WNOWAIT)`, terminates the owned group before reaping that
leader, and bounds the final direct-child wait to one second. The group guard
also covers cancellation and early returns. A cancelled future cannot await:
its synchronous Drop guard signals the owned group, while direct-child reaping
then relies on Tokio's best-effort drop/orphan handling; it does not promise
that the entire tree is reaped within one second. A cleanup failure is a separate
execution diagnostic that makes the engine/run incomplete while retaining usable
candidates; it cannot become a clean zero. Capture caps bound saved bytes and do
not by themselves prove that a process exited.

Mac runtime tests cover timeout, cancellation, normal completion with background
children and early-return cleanup, using actual child-liveness checks. Linux
runtime and Windows native execution require their own acceptance; these Mac
results do not prove either platform. Process groups are
ownership cleanup, not a sandbox against `setsid`, group escapes, external
SIGCHLD reapers or a replacement for OS network/memory isolation. Private raw
records and exact test scope are in
`reports/evidence-acceptance/scanner-process-limits-20261016/`.

Windows has a separate runner using Windows-only pinned `process-wrap =10.0.1`:
suspended spawn, Job Object assignment, then resume; the outer kill-on-close
guard stays owned through cancellation and normal completion. It polls the
leader with `try_wait()`, terminates the job before draining inherited pipes,
and limits final leader/pipe cleanup to one second. It does not use the
library's blocking job wait or consuming unwrap. Reported cleanup failures
retain partial output and make the engine/run incomplete. Twelve test cases
and one subprocess helper passed Windows-target type checking in a private
offline harness; **no native Windows tests have run**. Synchronous spawn/Win32
calls cannot be preempted by the async deadline; job termination is not proof
that every descendant has already exited. This is ownership cleanup, not an
OS sandbox or a network policy.

`--fail-on none` can return exit 0 for an incomplete report: automation must read
`run_status`, `incomplete_reason` and engine records rather than treating process
success or empty findings as complete coverage. `cargo-audit --no-fetch` prevents
the advisory DB's git fetch; it does not establish an up-to-date DB or a successful
yanked-package/index check. The local cached-DB acceptance covers advisory lookup,
with missing index/yank diagnostics retained separately in private test evidence.

## Validation boundary

The opt-in [loopback probe](../scripts/trust/dataflow-probe.py) uses only a generated
source fixture and a local receiver returning `[]`. It permits one CLI attempt,
zero outer retries, at most 1 MiB stdout and 256 KiB stderr, and a shared admission
deadline of at most 90 seconds. Optional flags can only tighten these values.
It reuses the exported generic process-group capture helper; this does not run
its Go/Rust analysis paths. The child receives an environment allowlist with a
disposable HOME/TMPDIR, the OS default PATH, a fixed locale and loopback NO_PROXY.
Inherited provider keys and proxy settings are excluded; this alone is not an
OS network policy.

The receiver admits at most eight connections. Headers are limited to 16,384
bytes per connection and 65,536 bytes total; bodies to 2,000,000 bytes per request
and total. Each connection has an absolute 15-second deadline also constrained by
the global deadline. It handles one request per connection and responds with
`Connection: close`; it does not reject a keep-alive header itself. It rejects
Transfer-Encoding, missing/duplicate/invalid/oversized Content-Length, invalid
UTF-8, duplicate JSON keys and non-finite numbers. Shutdown closes owned listener/connections and joins its thread for at
most 0.5 seconds. Partial framing and capped raw HTTP bytes remain in
`http-events.json`; `requests.json` contains only parsed captures.

A transport `complete` record requires the source marker, valid CLI process/
capture/cleanup control, closed fixture sockets and a stopped thread, no HTTP
errors, and the observed deadline check. CLI exit 1 is the established findings
exit and may satisfy transport control; process success never establishes full
scan coverage. Without valid control, absence of a cleanup error leaves CLI
cleanup unknown and the probe incomplete. Timeout/start/capture/HTTP/cleanup
failure preserves partial evidence instead of becoming a clean empty result.
Receiver-thread startup failure records incomplete with zero CLI attempts. An
exclusive `cli-attempt.json` is written before process invocation; its debit is
not proof that the operating system spawned the CLI.

The CLI admission reserves 1.5 seconds for helper cleanup, receiver join and
recording. Blocking spawn/OS calls are not hard wall-clock guarantees; `setsid`
escape, CPU/RSS and report/HOME/other CLI disk writes are not bounded by these
capture caps. Deadline/wall observations are taken after capture files are
written and before final receipt serialization; final recording I/O is not a
hard wall bound. This receiver is not a general HTTP server or arbitrary-source
sandbox. It does not establish cloud retention, every provider/mode's data flow,
or an OS egress policy. See [probe usage and receipt fields](../scripts/trust/README.md#verification-and-tests).

Tests for payload construction, source-leak rejection and loopback HTTP capture
prove specific code paths. A real OS/container egress-denied run is needed to test
an offline configuration. That run must record binary revision, provider roster,
scanner versions, cached DB/rules/images, network policy and missing engines.
Third-party CLI internal networking remains **unknown** without independent capture.
A 2026-10-16 local acceptance run captured a fixture source marker in one real
HTTP POST. An OS `sandbox-exec` policy denying `network*` permitted a quick scan
with gitleaks; a separate socket probe was denied. This run had only gitleaks
available (Semgrep absent, cargo-audit had no lockfile, baseline OSV disabled),
so it does not establish all-scanner offline acceptance.

See [trust tools](../scripts/trust/README.md) for local probe and verification commands.


## Bounded Jev TLS and CLI transport checks

Two manual tests exercise real local transports with synthetic data. They are
ignored in ordinary Rust tests because Python 3 and, for TLS, OpenSSL must be
installed. They do not call a real Jev service, model API or subscription CLI.
No global CA/proxy settings are changed, and production certificate validation
stays enabled. No new provider CA option is introduced.

```bash
# Choose a fresh directory for each acceptance run; existing JSON is never overwritten.
mkdir /tmp/vettalon-transport-new-run
VETTALON_TRANSPORT_EVIDENCE_DIR=/tmp/vettalon-transport-new-run CARGO_BUILD_JOBS=2 \
  cargo test -p vettalon --lib tls_metadata_opt_in_and_explicit_fallback -- --ignored --nocapture
VETTALON_TRANSPORT_EVIDENCE_DIR=/tmp/vettalon-transport-new-run CARGO_BUILD_JOBS=2 \
  cargo test -p vettalon --lib trusted_cli_stub_captures_source_in_all_prompt_modes -- --ignored --nocapture
```

The TLS test creates a disposable CA and localhost server certificate. A private
in-module test client trusts only that CA. It captures three HTTPS POSTs
(success, HTTP 503 and malformed response), checks the exact file-metadata keys,
and rejects the presence of the synthetic source marker. Each test-client
request has a three-second timeout; no application retries occur. Certificate
generation is bounded, and the loopback receiver permits at most six connections
and sixty seconds. CA private keys remain temporary and are not evidence outputs.

The production audit-dispatch branch is also exercised: default and explicit
heuristic ranking cause zero receiver events; opting into Jev with the untrusted
test certificate produces a receiver-side TLS rejection, a visible fallback
notice and `rank_degraded=true`. A bounded wait allows the receiver to record
its rejection. If proxy/environment settings prevent that handshake, the test
fails instead of calling a generic transport error proof of CA rejection.
These dispatch checks omit scanner and model execution; they do not claim a full
CLI scan or all-scanner egress capture.

The CLI test executes a self-authored Python stub directly with `Command`, without
a shell, in three calls with a five-second timeout each. It captures the exact
source-bearing prompt via stdin, one argument and a temporary file, verifies an
isolated disposable working directory, and checks 0600 permissions for file
transport on Unix. Shell syntax in the synthetic prompt remains literal data.
Argument transport exposes prompt text in argv; stdin/file captures show that the
marker is absent from argv. The stub uses isolated Python startup without user
site initialization. This proves Vettalon-to-child transfer, not an audit of
Claude, Codex or Grok internals. Their networking, retention and tool behavior
remain unknown without separate evidence.

The optional `jev-tls.json` and `cli-subprocess.json` receipts contain synthetic
captures only and use create-new writes. A failed test or a receipt from an older
binary must not be counted as a passing run. These checks establish transport
properties for the tested paths, not a confidentiality guarantee for arbitrary
repository paths, providers or installed tools.

## Offline hunt intake scope (next-release preview)

Lockfile intake itself is offline. It records fixed relative input names, bounded reason codes, and byte counts / SHA-256 only after a complete read; parser error text and source lines are not persisted. Mixed inputs retain successfully resolved targets while marking the run incomplete. `total_targets` is the resolved subset, not an estimate of dependencies hidden by failed inputs. Unsupported requirements options / ranges / markers and unrecognised go.sum rows remain visible; intake does not execute package tools or follow includes. Unknown auxiliary-manifest directness is distinct from a known transitive dependency. The subsequent OSV, registry and selected-model traffic remains as described above. Old JSON without intake stays unknown; stored `complete` contradicting a present intake ledger is rejected by the saved-report reader.

### Rust API migration reference

This next-release preview is not fully Rust source-compatible: external `HuntReport` / `HuntPlan` struct literals must supply the new public `intake` field, and exhaustive `SkipReason` matches must handle `DirectnessUnknown`. The current reader still deserializes older JSON without `intake` as `None` / unknown; missing evidence must not be replaced with a fabricated complete ledger. `targets_from_dir(&Path) -> Result<Vec<DependencyTarget>, String>` retains its signature but now returns `Err` for incomplete intake. Call `intake_from_dir` to retain the usable `targets` together with their `evidence` when inputs are partial. This preview does not change the release version.

## Bounded hunt transport checks

The ignored `local_tls_hunt_transport_policies_and_osv_states` test uses a
disposable CA and local TLS receiver, with DNS overrides only in the test client.
Request URLs keep the real allowlisted hostnames and standard HTTPS port. The
client reuses production builders/redirect policies; it does not introduce a
production CA, endpoint or allowlist override. It checks same-origin OSV and
crates-to-static CDN redirects, blocks cross-host/downgrade/nonstandard-port/loop
cases, and observes synthetic matched/unmatched/failed OSV responses. These are
controlled local responses, not live advisory results.

The separate ignored `bounded_live_public_hunt_transport` probe runs only when
explicitly requested, using a fresh `VETTALON_HUNT_LIVE_OUTPUT` directory. It pins
Cargo `cfg-if@1.0.5` and npm `is-number@6.0.0` in complete self-authored manifests
and lockfiles, with exactly two direct targets. It permits one OSV batch and two
archive GET initiations, at most four redirects across the round, fifteen seconds
per request, a 120-second overall deadline, and two loopback fixed-`[]` mock
completions. It reuses production HTTP policies, applies a tighter test-only
2 MiB per-archive body cap (below the 5 MiB round limit), and checks the archives
against the pinned Cargo SHA256/npm SHA512 SRI before extraction. Production
archive caps and per-dependency timeouts remain in force.

This probe invokes the real `run_hunt`/`EngineAuditor` pipeline with at most one
module per dependency. It records compressed artifact digests, extracted file
hashes/bytes, actual OSV and fetch/audit states, child coverage, and mock prompt
captures. No downloaded source/build hooks or real model inference are run. The
one-module bound may leave child coverage and the hunt incomplete. An OSV
non-match and a fixed empty mock response do not establish novelty or clean code.
This is not a full CLI-parser or detection-quality test. A failed round retains
its receipt and must not be retried to obtain an expected advisory result.

```bash
# Local TLS only; requires Python 3 and OpenSSL. Use a fresh evidence directory.
VETTALON_HUNT_TRANSPORT_EVIDENCE_DIR=/tmp/vettalon-hunt-tls-new CARGO_BUILD_JOBS=2 \
  cargo test -p vettalon --lib local_tls_hunt_transport_policies_and_osv_states -- --ignored --nocapture
# Live public registries/OSV: run only for an explicitly approved bounded round.
# The output directory must not exist; this probe creates it and refuses reuse.
VETTALON_HUNT_LIVE_OUTPUT=/tmp/vettalon-hunt-live-new CARGO_BUILD_JOBS=2 \
  cargo test -p vettalon --lib bounded_live_public_hunt_transport -- --ignored --nocapture
```

## One-call local offline diagnostic (preview)

The opt-in [offline diagnostic](../scripts/trust/README.md#one-call-local-offline-diagnostic-macos-preview)
creates a separate local Ollama daemon and a one-attempt forwarding adapter under
macOS `sandbox-exec`. It first requires the supervisor and a child to observe
external-socket `EPERM`, successful loopback connections and a denied dummy write.
The policy also denies writes beneath the existing model directory. Proxy and
credential environment variables are not inherited; only child processes receive
an isolated `HOME`/temp. The real home, firewall, CA and existing daemon on port
11434 are not changed.

Seatbelt permits `localhost:*` for Ollama's dynamic runner IPC. The helper binds
its endpoints to `127.0.0.1`; the policy's localhost exception can include IPv6
loopback as well. This is an external-egress diagnostic, **not an airgap or a
localhost-relay defense**. A failure blocks inference; the helper does not relax
read-only cache policy or download another model to get a passing result.

One explicitly authorized call uses the preloaded 7B model, one harmless synthetic
marker file, 4,096 context and 256 output-token request limits. The CLI's OpenAI
request is adapted to native `/api/chat` to set `num_ctx`, `num_predict` and
`keep_alive` explicitly; this does not establish native `/v1` behavior. Reservation,
upstream attempt and received/validated response are distinct counters. Every
original/transformed payload and raw content is retained with hashes. Model
manifest digest and layer sizes are checked; full weight blobs are not rehashed.

No verifier, PoC or real repository is selected. Extra core requests are rejected
without a second upstream attempt. Parse failure, native incomplete/length reply,
output-token overflow, startup/timeout or cleanup failure stays incomplete, with
logs/raw or bounded partial evidence preserved. A successful local diagnostic
still does not prove all scanners were available or establish detection quality,
cloud retention or third-party CLI internal networking. The helper is a next-release
preview; no real model success is claimed by adding this documentation or its tests.
