# Trust tooling

These helpers generate local evidence and verify downloaded CLI release assets.
They never create a release, sign with an identity, send a disclosure, or claim a
certification. Python 3.11+, `jsonschema`, and an official Syft binary are required.

Source-code test coverage uses a separate standard-library receipt wrapper,
which is not published in this repository. See the pinned
[line/branch reproduction and scope](../../docs/COVERAGE.md#source-code-test-coverage-is-a-separate-denominator).
Its source-tag receipt does not measure the published binary or customer-source
review coverage. The verifier compares every tracked file's bytes with the tag's
HEAD blob, then checks arithmetic consistency between LLVM's **summary-only**
per-file counts and aggregate. It cannot derive hits independently from detailed
execution counters because those were not saved. The receipt's original checkout
root maps absolute LLVM filenames when verifying from another path; traversal,
untracked files and changed scope fail. The runner checks source before and after
execution but cannot detect a modification restored between those snapshots.
New v2 runs retain at most 2 MiB of each stdout/stderr stream, hash all observed
bytes, stop the process group immediately at the limit, drain for at most five
seconds, and fail closed on truncation or missing EOF. JSON and log readback
opens each file once with `O_NOFOLLOW`, then uses `fstat`, a bounded read and a
stream hash to reject symlinks, oversized or changing files. Historical v1 logs have no
stream ledger. This does not replace release signature or attestation checks.
It requires the exact `--branch --json --summary-only --output-path ... -p ...
--locked` command for pinned nightly `2026-10-17` and `cargo-llvm-cov 0.9.1`.
The output path is bound to the original run directory, allowing a
byte-identical receipt copy to be verified elsewhere. The preserved v1 receipt
is accepted only at its pinned whole SHA-256; adding a v2 field to a changed v1
receipt does not bypass that check. New runner receipts use v2 and record the
original directory as self-asserted metadata. Changing just the command,
receipt and artifact digest together still fails this scope check. A wholly
forged unauthenticated v2 receipt remains possible, and the historical runner
bytes are unavailable.
For a release-specific readback, supply `verify` with
`--expected-receipt-sha256`, `--expected-source-sha` and `--expected-tag`
together. These caller-supplied values can be forged along with an unsigned
receipt; a match only checks equality. The verifier reports summary arithmetic
consistency, caller-anchor match, and `provenance_verified: false`. The
anchored v0.2.0 readback (kept in private acceptance records) includes relocated-receipt and negative checks. No whole-CLI or Desktop/Pro
line/branch denominator has been measured by this receipt.
This readback is local and unsigned. Substitution detection requires expected
values retained through an independent trusted channel; a digest stored next
to the receipt cannot authenticate that receipt by itself.

## Setup

```bash
python3 -m venv .venv-trust
.venv-trust/bin/python -m pip install -r scripts/trust/requirements.txt
python3 scripts/trust/install-syft.py /tmp/NEW_TRUST_DIRECTORY/syft
```

The installer supports macOS arm64/x64 and Linux x64 **hosts**. It downloads only
Syft 1.34.2 from the official Anchore GitHub release and verifies a pinned archive
SHA256 before extracting the single regular `syft` binary. Apache-2.0, local
inventory parser with filesystem read access, no install shell script, no sudo.
This is a reviewed reproducible version, not a claim to use the newest release.
Review upstream changes/checksums before bumping. The JSON Schema Draft 7 validator
uses the vendored official CycloneDX 1.6 schemas; see [source/license](schemas/SOURCE.md).

## Public release inventory

Generate from a **standalone public workspace**, not the private full workspace.
The adapter requires exactly the two public crate members. The local source slice
contains only Cargo manifests/lockfile. Syft parses components/relationships;
registry archives whose source matches the lockfile distribution reference and
whose SHA256 matches the lockfile checksum may enrich SPDX license expressions.
The exact archive member supplies the license; its manifest digest is recorded.
A same-name/version cache directory is insufficient. Git/local/uncached/ambiguous
origins retain unknown enrichment. Existing catalog license declarations remain
unchanged and are marked as not independently source-bound; a disagreement with a
verified archive fails instead of overwriting the declaration.
Missing license evidence remains explicit unknown. All lockfile optional/platform
packages are included; target label is build metadata, not per-target resolution.

```bash
.venv-trust/bin/python scripts/trust/trust.py release-sbom /path/to/public-tree \
  vettalon-darwin-arm64.tar.gz --output vettalon-darwin-arm64.tar.gz.cdx.json \
  --source-sha FULL_40_CHARACTER_SOURCE_SHA --target aarch64-apple-darwin \
  --dirty --syft /tmp/NEW_TRUST_DIRECTORY/syft
.venv-trust/bin/python scripts/trust/trust.py validate-sbom vettalon-darwin-arm64.tar.gz.cdx.json
```

Use `--dirty` for local uncommitted source; it must not pass release acceptance.
Output is a CycloneDX BOM plus **unsigned build record** next to the archive,
not a substitute for GitHub-issued provenance. A local test archive can contain a
fixture; do not call it a tested production binary. Release workflow uses the
actual packaged binary and attests the archive and BOM digests.

In the private development checkout, the open-core export script's
working-tree staging mode (`--stage-working-tree /tmp/NEW_PUBLIC_STAGE
--skip-build`) creates an allowlisted dirty-tree staging copy
without commit, push, destination overwrite or touching the public repository.
It still runs lock pruning, private-marker and gitleaks checks. The explicit skip
means build/test/clippy have **not** passed. Normal export continues to read only
committed HEAD and run all gates. This staging helper is not part of public export.

## Customer project inventory

```bash
.venv-trust/bin/python scripts/trust/trust.py customer-sbom /path/to/project \
  --output /tmp/customer.cdx.json --syft /tmp/NEW_TRUST_DIRECTORY/syft
.venv-trust/bin/python scripts/trust/trust.py validate-sbom /tmp/customer.cdx.json
```

This is an adapter to Syft's catalogs, **not a replacement SCA engine**. It scans a
local directory and reads files without running repository build scripts. Use a
minimal copy of required manifests/lockfiles to limit unrelated file reads. Syft
update checks and remote Go license/Java lookups are disabled. Do not upload the
BOM publicly without reviewing package names, paths and internal identifiers.
Missing tool or empty inventory is failure, never an empty successful BOM.

Representative Rust Cargo.lock, npm lock v3, pinned Python requirements and Go
module fixtures are in `fixtures/sbom/`. They test the selected catalog/version,
not every workspace, conditional dependency, package manager or ecosystem.
The optional `native.py` adapters reconcile npm lock v3, native `pip inspect`,
and Go `go mod edit -json` / `go mod graph` / `go list -m -json all` snapshots.
They preserve a source hash and direct/transitive role; add only source-established
edges. Components must match the source ecosystem and exact purl name/version;
unknown qualifiers or ambiguous identities fail. Go unknown graph endpoints and local/git/module replacements are rejected rather
than silently dropped or labeled as the original version. Explicit non-package
`go`/`toolchain` pseudo-nodes are excluded; unselected historical source-version
edges are omitted with the exact excluded lines recorded in adapter output.
Go MVS-selected modules missing from Syft are explicitly marked as native
inventory, with unknown licenses where no license evidence exists. They do not
execute builds or infer call reachability. npm workspace links/optional nodes,
pip requested extras/direct URLs and unresolved nodes are rejected pending a
separate resolution. These are bounded source-format adapters, not full ecosystem
coverage.

`pip-inspect` requires all eleven standard marker environment fields from the
saved inspect snapshot as nonempty strings, including valid Python/implementation
versions. Missing, partial or malformed environments fail; the analysis host must
not supply missing values. The adapter uses base installed scope (`extra=""`);
an environment `extra` override is not evidence of requested-extra activation.
Unsupported marker contexts fail instead of being treated as false. A reconciled
Python BOM records `vettalon:graph:marker-environment` and
`vettalon:graph:marker-exclusions` in metadata, alongside the existing input hash.
False-marker exclusions identify their source distribution and requirement; the
CLI summary also emits `excluded_marker_requirements`. These are source snapshot
decisions, not evidence for other platforms or optional features.

Python requirements lack dependency edges/license metadata; a flat lock inventory
cannot establish direct/transitive role alone. Go module/license evidence can be
partial. Do not infer missing package, unknown license, unobserved call path or
missing edge means safe/not-affected. Customer delivery needs source-specific
reconciliation; a schema-valid BOM alone is insufficient.

## Verification and tests

```bash
.venv-trust/bin/python -m unittest discover -s scripts/trust/tests -p 'test_*.py'
PYTHON=.venv-trust/bin/python scripts/trust/verify-release.sh ARCHIVE vX.Y.Z SOURCE_SHA
python3 scripts/trust/dataflow-probe.py /absolute/path/to/vettalon --output /tmp/NEW_PROBE_OUTPUT
```

The probe runs one deep module from a generated disposable fixture against a
loopback OpenAI-compatible receiver returning `[]`; it checks that the known
fixture source marker reaches that receiver. It makes one CLI attempt with zero
outer retries. `--timeout-seconds`, `--stdout-cap-bytes` and `--stderr-cap-bytes`
can only tighten the defaults: 90 seconds shared admission, 1 MiB stdout and
256 KiB stderr. The generic process-group capture helper and supervisor under
`benchmarks/reachability/` are required source dependencies, already included by
the public export; the probe does not invoke their Go/Rust scanner paths. The
child environment includes only the OS default PATH, disposable HOME/TMPDIR,
`LANG=C.UTF-8`, loopback `NO_PROXY` and `PYTHONDONTWRITEBYTECODE=1`. Provider keys
and proxy settings inherited from the parent are excluded.

The single-use receiver admits at most eight connections, with 16,384-byte
headers per connection/65,536 total and 2,000,000-byte bodies per request/total.
Reads and response writes share a 15-second absolute connection deadline and the
global deadline. Each connection handles one request and receives a
`Connection: close` response; a keep-alive header alone is accepted.
Transfer-Encoding and missing, duplicate, invalid or oversized Content-Length
are rejected. Strict JSON rejects invalid UTF-8,
duplicate keys and non-finite numbers. It closes owned sockets/listener and joins
the receiver thread for at most 0.5 seconds; it is not a general HTTP server.

Outputs are `stdout.txt`, `stderr.txt`, `requests.json` and `result.json`, plus
`http-events.json` with bounded partial HTTP raw bytes/base64, byte counts and
hashes. `cli-attempt.json` debits the single attempt before invocation and is
not proof of an actual spawn. Receiver-thread startup failure writes an
incomplete result with zero CLI attempts and no CLI-attempt ledger. The result binds the event file by SHA-256/length and exposes CLI capture
control, `fixture_cleanup`, `cli_cleanup_complete`, `global_deadline_met` and
limits. A `status: complete` requires marker observation, valid process/capture/
cleanup evidence, stopped receiver/closed sockets, no HTTP errors and the
observed deadline check. CLI exit 1 can be the normal findings exit; this status
covers the transport experiment, not product scan coverage. Missing CLI control
makes cleanup unknown (`null`) and the probe incomplete even without a reported
cleanup error. Failure retains partial evidence, never a clean empty scan.

The CLI admission reserves 1.5 seconds for helper cleanup, receiver join and
recording. Blocking spawn/OS calls, process-group escapes, CPU/RSS and report/
HOME/other disk writes have no hard guarantee here. Deadline/wall samples are
after capture-file writes and before final receipt serialization; final recording
I/O is not hard wall bounded. Tests in `tests/test_dataflow_probe.py` use
self-authored local process/socket fixtures; they do not call a real model or
prove cloud retention. Never point this receiver at customer source. Offline
acceptance separately needs an egress-denied environment and preloaded tools;
see [Data flow](../../docs/DATA-FLOW.md#validation-boundary). On 2026-10-17, one
real-CLI run verified source transport and cleanup for the fixed two-line fixture
against the loopback endpoint returning `[]`. No real or paid model service was
called. This result does not establish model judgment, full scan coverage or
cloud retention. Historical probe receipts retain their own source revisions.

`verify-assets` checks sidecar completeness, actual SHA256, target/name and
BOM/build-record bindings, plus official schema and graph-reference integrity.
It explicitly returns `signature_verified: false`: only `verify-release.sh` runs
cryptographic Cosign and GitHub verification with exact workflow/issuer/source
constraints. Fixtures cannot prove an actual GitHub/OIDC release was issued.

Scorecard: install an official checksum-verified `scorecard` binary, then use a
**separate read-only token** as `SCORECARD_READ_TOKEN` and run
`scripts/trust/scorecard.sh owner/repo NEW_RESULT.json`. It clears inherited
credentials, bounds execution to 180 seconds and does not publish. Missing token,
rate limiting or timeout is not a successful assessment. See
[Best Practices evidence/gaps](../../docs/TRUST-BEST-PRACTICES.md).

Registry alert: `registry_alert.py` checks that every npm version from 0.3.0 on
has a release, a successful `release.yml` run and provenance naming that run
(read-only; GitHub token sent to api.github.com only). The daily workflow is
`registry-alert.yml`; checks and scope are in
[TRUST.md](../../docs/TRUST.md#registry-alert). Its tests replay a recorded
fixture offline:

```bash
GH_TOKEN=$(gh auth token) python3 scripts/trust/registry_alert.py
python3 -B -I -S -m unittest discover -s scripts/trust/tests -p 'test_registry_alert.py'
```

## Cargo SBOM differential test

`sbom_diff.py collect` records one case; `report` recomputes metrics offline.
Collection needs the pinned venv (the adapter validates the schema), Syft,
Cargo with a warm registry cache, and optionally a nightly toolchain. It runs
`cargo metadata --locked --offline` and `cargo +<nightly> build --locked
--offline -Zsbom` with `CARGO_BUILD_SBOM=true` and a disposable
`CARGO_TARGET_DIR`; nothing is downloaded and no lockfile is written.

```bash
.venv-trust/bin/python scripts/trust/sbom_diff.py collect --source fixtures/sbom/rust \
  --case rust --syft /tmp/NEW_TRUST_DIRECTORY/syft --target aarch64-apple-darwin \
  --precursor-toolchain nightly-2026-10-17 --record-bom --output /tmp/NEW_SBOM_DIFF/rust
python3 scripts/trust/sbom_diff.py report fixtures/sbom/differential/rust/snapshot.json
```

Use `--lock-only` for a workspace: Syft then scans a staged copy holding only
`Cargo.toml`, `Cargo.lock` and `crates/*/Cargo.toml`, so other lockfiles in the
tree cannot leak in. `--features` is passed to `cargo metadata` (default features
otherwise). The precursor is a nightly-only oracle with known issues; a failed
precursor build is recorded, never substituted.

Each case keeps `snapshot.json` (oracle and observed inventories, tool versions,
lock hash, adapter outcome) and, with `--record-bom`, the raw Syft BOM with
absolute paths, timestamp and serial number removed. Verdicts are `refused`,
`matches-oracle`, `differs-from-oracle` or `accepted-invalid-input` (Cargo
itself rejects the input). Recorded cases live in `fixtures/sbom/differential/`;
`tests/test_sbom_diff.py` replays them without Syft or Cargo:

```bash
python3 -B -I -S -m unittest discover -s scripts/trust/tests -p 'test_sbom_diff.py'
```

Without `jsonschema` one full-adapter replay test is skipped; the graph replay
still runs. The stale-lock test is an expected failure (known limitation, see
[Trust](../../docs/TRUST.md#how-accurate-is-the-cargo-inventory)).

## Native graph reconciliation examples

```bash
.venv-trust/bin/python scripts/trust/native.py npm-lock-v3 \
  --bom /tmp/npm.cdx.json --source fixtures/sbom/npm/package-lock.json --output /tmp/NEW_npm_graph.cdx.json
# Prepare a disposable Python install using official wheels only (no setup.py/build hooks),
# with requirements.in as direct and requirements.txt as constraints. Then:
python3 -m pip inspect --path /tmp/disposable-site-packages > /tmp/pip-inspect.json
.venv-trust/bin/python scripts/trust/native.py pip-inspect \
  --bom /tmp/python-installed.cdx.json --source /tmp/pip-inspect.json --output /tmp/NEW_python_graph.cdx.json
# In a cached disposable Go fixture, native tooling emits module metadata (no build):
go -C fixtures/sbom/go mod edit -json > /tmp/go-manifest.json
go -C fixtures/sbom/go mod graph > /tmp/go-graph.txt
go -C fixtures/sbom/go list -m -json all > /tmp/go-selected.json
.venv-trust/bin/python scripts/trust/native.py go-native \
  --bom /tmp/go.cdx.json --source /tmp/go-manifest.json --go-graph /tmp/go-graph.txt \
  --go-selected /tmp/go-selected.json --output /tmp/NEW_go_graph.cdx.json
```

Go may download modules/toolchains while preparing metadata. Set `GOTOOLCHAIN=local`
and `GOPROXY=off` for an already cached disconnected run; missing cache must fail.
Syft's Go cached-license search is disabled by the default adapter. If an operator
explicitly enables `SYFT_GOLANG_SEARCH_LOCAL_MOD_CACHE_LICENSES=true` in a separate
Syft invocation, license evidence comes from local module cache, not registry
inference; record that cache/tool configuration. Native Go module graph can include
test-only modules and uses MVS-selected versions, not function reachability.

## One-call local offline diagnostic (macOS preview)

`offline-probe.py` is an **opt-in diagnostic**, not a benchmark or general firewall.
Without an explicit action it starts no process. Policy-only diagnostics start no
Ollama daemon and make no model call:

```bash
python3 scripts/trust/offline-probe.py --diagnose-policy --output /tmp/NEW_OFFLINE_POLICY_OUTPUT
```

The diagnostic requires macOS `sandbox-exec` and Python 3.11+. It checks actual
`EPERM` on an external numeric-IP socket from both the supervisor and a child,
loopback connections from both, and denied writes to a dedicated dummy directory.
The sandbox denies external networking and model-cache writes. Seatbelt's
`localhost:*` exception permits loopback on dynamic ports required by Ollama
runner IPC; endpoints themselves bind `127.0.0.1`. This is not an airgap or a defense
against another localhost service acting as a relay. No global firewall/CA change
is made. A failed policy probe blocks daemon startup.

The separately authorized one-call action needs an existing CLI binary, official
installed Ollama and the already present `qwen2.5-coder:7b` manifest digest
`dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`:

```bash
python3 scripts/trust/offline-probe.py --allow-one-model-call \
  --binary /absolute/path/to/vettalon --output /tmp/NEW_OFFLINE_ONE_CALL_OUTPUT
```

Do not run the one-call action as part of normal setup or documentation checks.
It starts a separate loopback Ollama daemon with an isolated child `HOME`/temp,
`OLLAMA_NOPRUNE=true`, existing read-only model storage, 4,096 context, one loaded
model, one parallel request and keep-alive zero. It does not contact, reconfigure
or stop the existing service on port 11434, and does not download models.
Manifest digest and selected blob sizes/mtimes are checked; the 4.7 GB model blobs
are not independently rehashed.

A counting adapter receives the CLI's OpenAI-compatible `max_tokens=256` request
and makes at most one upstream `/api/chat` attempt with explicit
`num_ctx=4096`, `num_predict=256`, `keep_alive=0`. It changes only the protocol
envelope on return; original request, native request, raw response and model
content are saved with hashes. This does **not** verify Ollama's native `/v1`
behavior. Reservation, upstream attempt and received/validated response are separate
fields; an unsuccessful connection is not proof of a completed model call.

The CLI audits one self-authored harmless marker file: deep, heuristic ranking,
`--max-modules 1`, `--no-prior`, `--time-budget 120`, finder-only configuration,
no PoC, verifier or real repository. Any core parse retry is rejected at the proxy
and never forwarded. A retry attempt, parse failure, native `done=false`, length
termination, invalid/excessive `eval_count`, timeout, startup or cleanup error leaves
the diagnostic **incomplete**. Oversized responses retain only a bounded 2 MiB
partial with an explicit truncation record. No retry is used to improve results.
The supervisor waits at most 160 seconds, with bounded cleanup inside a 180-second
outer wall budget. Outer process-group cleanup covers the newly created daemon
and its runner descendants.

Use a new output directory outside model/executable inputs. Outputs include policy,
limits, binary/helper hashes, model metadata, policy probes, proxy counts/payloads,
raw/partial responses, CLI/daemon/supervisor logs and terminal status. These are
private diagnostic artifacts until reviewed. A transport/policy success does not
prove all scanners ran, that a finding is correct, cloud retention behavior or
third-party CLI networking.

```bash
python3 -m unittest discover -s scripts/trust/tests -p 'test_offline_probe.py'
```

Tests use temporary inputs, mocks and a local fake HTTP receiver; they make no
real model calls. A policy-only OS run is separate evidence. A real one-call run
must be explicitly authorized and evaluated from its own current output.
