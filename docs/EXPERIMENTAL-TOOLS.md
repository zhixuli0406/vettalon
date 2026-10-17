# Experimental tools — preview for the next release

These source tools are independent experiments. They are **not enabled in the
scanner's default path**, and this guide is not a code-review approval or evidence
that a public release has shipped. Use a reviewed source revision and retain its
hash with every result.

繁中摘要：本文件說明自建合成樣本、離線 dry-run 與有限原型的重現方式。
這些工具沒有證明模型效能優勢、真實漏洞命中率或競品領先；候選未經獨立人工
裁定，不能當成 confirmed。以下輸出由使用者在本機建立，不隨公開原始碼附帶。

## What each experiment can establish

| Tool | Current purpose | What a successful run does not establish |
|---|---|---|
| [Claude Code plugin lifecycle](../integrations/claude-code/README.md) and [local helper](../integrations/claude-code/tests/verify_local_install.py) | Disposable local installation/update observations, owned source/version readback and offline mock checks | Hosted marketplace cache upgrades, a running session loading a skill, provider authentication, model controls or public directory listing |
| [Blind twins](../benchmarks/blind-twins/protocol.py) | Ten self-built vulnerable/patched pairs: five families with two naming variants each; separate anonymous payload and oracle bookkeeping | Ten independent root causes, third-party OSS findings, freedom from training contamination, or production detection quality |
| [Synthetic identity views](../benchmarks/blind-twins/identity_views.py) | Pure anonymous/identified payload pairing with explicit self-authored synthetic attribution and source/hash declarations | Recovered upstream identity, filesystem verification by the pure builder, authenticated provenance, contamination effects or a second model-execution budget |
| [Bounded model runner](../benchmarks/blind-twins/run.py) and [rehearsal](../benchmarks/blind-twins/rehearse.py) | Finder-only/same-family/cross-family scheduling, fixed scope, raw lineage, failure and budget accounting | A real three-arm effectiveness/cost/variance comparison; mock replies are scheduling evidence only |
| [Context selection](../benchmarks/context-selection/selection.py) | Opt-in Python AST selection: baseline, functions, callchain; original ranges/hashes and explicit omissions | Taint proof, complete call graphs, whole-repository recall, token savings or a production integration |
| [Context comparison](../benchmarks/context-selection/compare.py) | Same-snapshot baseline/functions/callchain manifests, bounded selector subprocesses and explicit mock delivery | Real finder results, equal input-token use, whole-repository effectiveness or provider integration |
| [Differential summary](../benchmarks/differential-poc/evidence.py) | Check fresh-container canonical controls and vulnerable/patched effects from the self-built twins | A model-written exploit, execution of a complete target repository, or confirmation of a scanner finding |
| [Fresh synthetic proof linkage](../benchmarks/differential-poc/link.py) | Launch fixed canonical twins with a new nonce, reconcile raw Docker receipts with declared synthetic candidate hashes, and generate attachable source/execution/control manifests | Trusted execution attestation, arbitrary target semantics, actual scanner discovery, a model-written PoC, or human confirmation |
| [Legacy observation readers](../benchmarks/legacy-readers/README.md) | Normalize explicitly supplied recall reports, paired OWASP booleans and ranker rows with fixed registry slots, raw lineage and unknown costs | A new benchmark run, human adjudication, verified false negatives/true negatives, historical resource measurements or detection effectiveness |
| [Formal transport preparation](../benchmarks/formal-transport/README.md) | Versioned prepare/dispatch/report boundaries, purpose-ledger accounting and separate requested/enforced/observed controls | Provider readiness, effective token caps, a completed three-arm comparison or permission to replace the selected provider/model |
| [Formal stage review](../benchmarks/formal-transport/review_v1.py) and [cost estimates](../benchmarks/formal-transport/cost_v1.py) | Default report replays artifact-bound derived fields; optional stage overlays and versioned operator prices/allocated effort retain raw and attachment hashes | Human identity, independent adjudication, changed metrics, differential proof, verified billing or whole-project effort |
| [Refute taxonomy](../benchmarks/refute-corpus/refute.py) | Replay a self-built ownership contract with known/unknown context and controls | A human-adjudicated counterexample corpus or permission to refute unknown deployment assumptions |
| [Counterexample RAG](../benchmarks/counterexample-rag/rag.py) | Offline baseline/random/retrieval payload construction with disjoint synthetic families | Human-approved retrieval evidence, an external holdout, improved model output, or readiness to change default prompts |
| [Bounded fuzz](../benchmarks/bounded-fuzz/fuzz.py) | Finite mutation/replay/minimization of one self-built C ownership contract in Docker | General fuzzing coverage, third-party vulnerability discovery, an absence-of-bugs proof, or validated performance gains |
| [Query refinement public V2](../benchmarks/query-refinement/PUBLIC-V2.md) | Explicit runtime/approved-lock bindings and a finite Python query revision, holdout, replay and minimization protocol | Reproduction of the historical private eight-call batch, tool authenticity/full dependency attestation, real OSS effectiveness, a hard resource sandbox or production adoption |
| [Loopback source transport probe](../scripts/trust/dataflow-probe.py) | One CLI attempt on a generated disposable source fixture, bounded process captures and local HTTP framing/cleanup evidence | Complete scan coverage, every provider/mode, cloud retention, hard OS wall/resource containment or permission to use customer source |
| [Go reachability](../benchmarks/reachability/adapter.py) | Optional official-tool adapter, two self-authored hosts, one fixed public advisory subset | Exploitability, comprehensive SCA, runtime unreachability, Rust support or a basis to suppress an alert |

A candidate without independent adjudication remains **U**. Category/label matches
are synthetic proxies, not adjudicated precision or root-cause recall. Detection,
surfaced and exploit-validated recall are different measurements. Build/read/parse
failures, timeouts, missing rows and exhausted budgets remain in their declared
denominators. No model-proposed PoC execution means exploit recall is not measured.
Insufficient samples cannot justify p50/p95 or general variance claims. Local
inference is not a complete accounting of CPU, electricity, memory or human cost.

## Current preparation boundary

At the 2026-10-17 source preparation checkpoint, these additions are navigation
and implementation previews. The identity builder declares self-authored synthetic
attribution; callers must separately verify materialized files before treating a
source binding as observed. Identified views do not establish contamination or
model-quality effects, and do not receive another execution budget.

The [differential process contract](../benchmarks/differential-poc/PROCESS-CONTRACT.md)
describes bounded subprocess captures and cleanup evidence. The local differential
checkpoint recorded 27 unique methods and one socket-case environment block;
the whole suite is **not green**. This does not establish Docker or
arbitrary-target containment. The legacy reader passed 32 self-contained synthetic
unit methods locally. A separate local-only integration read nine existing pinned
files into seven cohorts and 739 observation slots; the nine source hashes stayed
unchanged. These are reader checks, not new scans, independent cases or historical
effectiveness re-certification. Unreviewed recall/ranking reports, phase outputs
and denominator manifests are not exported with these sources.

The earlier formal transport checkpoint passed 31 local offline unit methods
using fake connections and fixtures. Its three-arm scheduling test retained 50 fake client debits and 51,200
reserved tokens in one shared ledger; these are test observations, not provider
traffic, generated tokens or billing. All production provider-readiness states
remain **unknown-disabled**, with zero real provider calls and zero formal
three-arm effectiveness runs. Fake connections and scheduling assertions do not
verify installed provider/model controls, billing, upstream cancellation or
effective token limits. Existing pilot debits and stopped attempts remain
recorded; neither new output paths nor these previews reset them. Public-stage
delivery, its test receipts and independent acceptance remain separate.

New default-report/review/cost integration passed 87 local offline methods
(the original 31 plus 56 new methods). The earlier 86-pass/one-failure attempt
remains recorded: only a case-sensitive wording assertion changed before the
fresh successful run. Repeated runs are not added to unique method counts.
Root also exercised three CLI entries with self-authored fixtures: two valid
reports exited 0, and one tampered input exited 1 without an output. Metrics
were unchanged by annotations. Synthetic partial costs/allocated effort retained
known subtotals and unknown totals; this is neither real-model effectiveness nor
human/billing verification. The accepted 251-source package remains historical.
Stage delivery is assessed against its corresponding source manifest and test
receipts; that historical package does not establish release of these sources.

Formal raw, attempt artifacts and optional attachments use bounded ordinary-file
POSIX reads without following symbolic ancestors, plus strict JSON and readback.
Unbound human/differential claims and mutable derived-field changes are rejected.
Worksheet/review-overlay options support twins only; context/RAG support default
derived replay and cost attachments, without worksheets.
Stage annotations leave metrics/raw unchanged. Prices and effort are operator
declarations; missing entries or partial usage retain unknown totals and known
subtotals. The legacy branch accepts no new review/cost attachments. See the
[formal guide](../benchmarks/formal-transport/README.md) for schemas and limits.

## Dependencies and data flow

Use Python 3.11+ for these examples. The Python prototypes use the standard
library. Run commands from the repository root, choose new output paths, and keep
generated outputs outside fixture/source trees. The examples below create local
files; they do not refer to historical results included in a release.

| Operation | Additional prerequisites | Data or execution boundary |
|---|---|---|
| Context/refute/RAG dry-run | None beyond Python | Reads self-built source locally; refute replays an in-memory toy function. RAG constructs payloads and makes no model request. |
| Twins canonical oracle | Running Docker and preloaded `python:3.12-slim` image | Twenty fresh containers, no network or host bind mounts; resolved image ID, source/harness hashes, controls and resource settings recorded. No automatic image pull. |
| Twins `--mock` / rehearsal | Locally generated canonical baseline and fixed subset | No model calls. It still requires a frozen oracle baseline; mock is not a shortcut around denominator preparation. |
| Real local-model runner | Reviewed local Ollama installation and preloaded model(s) with recorded digests | Sends anonymous **source code** and candidate context to `127.0.0.1:11434`; no cloud-provider option here. A loopback server may have its own network behavior. |
| Native fuzz prototype | Running Docker and preloaded `rust:1.94-bookworm` image containing `cc` | Compiles only the self-built C fixture in container tmpfs; no host mount/credentials/network. It requires executable tmpfs for this fixture. |
| Query refinement public V2 | Existing reviewed macOS Semgrep 1.181.0 runtime, explicit profile/lock hashes, separate sealed holdout | No scanner installation/download/fallback; offline tests use self-authored fake CLI replies. Real scanning is a separate opt-in action with new run artifacts. |
| Go experiment | Go 1.25+, official `govulncheck@v1.4.0`, explicit pinned advisory subset | Tool installation/setup can contact the official Go proxy/sumdb. Analysis uses local dependencies/DB with `GOPROXY=off`, cgo off and no inherited credentials. |

Review image/tool downloads separately before preloading them. These limited
fixtures are not a sandbox service for arbitrary untrusted repositories. For
normal product model/ranker/scanner traffic, see [Data flow](DATA-FLOW.md).

## Query refinement public V2

Use the [public V2 guide](../benchmarks/query-refinement/PUBLIC-V2.md),
[profile template](../benchmarks/query-refinement/runtime-profile.example.json)
and [finite oracle contract](../benchmarks/query-refinement/ORACLE-CONTRACT.md).
The template contains placeholders and must fail closed until reviewed values
are supplied. The versioned controller requires explicit runtime-profile and
approved-lock paths plus the SHA-256 of their raw bytes; seal, holdout and fresh
run-directory paths are also required. It does not locate tools through PATH,
download them or substitute a different version.

This preview defines the complete finite dev revision, sealed holdout, replay
and minimization flow with at most 15 scanner attempts, 15 seconds per admission,
120 seconds shared admission, zero outer retries and bounded saved output. It
retains `budget-control-incomplete` and `adoption_eligible=false`; blocking spawn,
OS cleanup, CPU/RSS and writes outside managed artifacts lack hard guarantees.
File hashes bind reviewed bytes, not tool authenticity or all dependencies.
Launcher Python layout/version declarations are not a runtime probe; the
controller's actual Python version is checked separately. No real scanner or
model run is claimed for this public V2 phase. Offline parser/fake-CLI and clean
public-stage checks concern the source/runtime binding and delivery contracts;
they do not establish scanner effectiveness. The frozen historical helper is a source
reference, not a promise to reproduce the private historical eight-call batch.

## Loopback source transport probe

Use an existing reviewed CLI binary and a fresh output directory:

```bash
python3 scripts/trust/dataflow-probe.py /absolute/path/to/vettalon --output /tmp/NEW_PROBE_OUTPUT
```

This command runs one deep module of a generated fixture against a receiver bound
to `127.0.0.1`, returning `[]`; it does not select a real repository or cloud
model. It permits one CLI attempt/zero outer retries, at most 1 MiB stdout,
256 KiB stderr and a 90-second shared admission deadline. Optional flags only
tighten those defaults. HTTP admits at most eight connections, bounds per-request
and aggregate headers/bodies, and uses absolute connection/global deadlines;
malformed framing/JSON or unproven cleanup stays incomplete. The child uses a
disposable HOME/TMPDIR and an environment allowlist excluding inherited provider
keys/proxies. Receiver-thread startup failure retains an incomplete result with
zero CLI attempts. See the
[exact caps, output files and control contract](../scripts/trust/README.md#verification-and-tests).

The exported generic adapter/supervisor are source dependencies, not requests to
run Go/Rust analysis. Deadline sampling excludes final receipt serialization;
blocking spawn/OS termination, process-group escapes, CPU/RSS and CLI disk writes
are not hard bounded. A successful transport record proves only the marker
reached this local fixture receiver, not full scanner coverage, cloud-provider
retention or the complete mode matrix. Tests use self-authored process/socket
fixtures. On 2026-10-17, one real-CLI run verified source transport and cleanup
for the fixed two-line fixture against the loopback endpoint returning `[]`. No
real or paid model service was called; model judgment, full scan coverage and
cloud retention remain outside this result. Historical receipts and test counts
below retain their own revisions. Generated requests/raw stay local and are
never exported with source. For network/privacy scope see
[Data flow](DATA-FLOW.md#validation-boundary).

## First offline dry-runs

These examples do not call a model or run Docker. Create a new output directory
before writing outputs. Do not reuse a directory holding earlier evidence.

```bash
mkdir /tmp/vettalon-experiment-preview
python3 benchmarks/context-selection/selection.py benchmarks/context-selection/fixtures/positive \
  --mode callchain --output /tmp/vettalon-experiment-preview/context-positive.json
python3 benchmarks/context-selection/selection.py benchmarks/context-selection/fixtures/safe \
  --mode callchain --output /tmp/vettalon-experiment-preview/context-safe.json
python3 benchmarks/context-selection/compare.py benchmarks/context-selection/fixtures/positive \
  --mock --output /tmp/vettalon-experiment-preview/context-comparison.json
python3 benchmarks/refute-corpus/refute.py --output /tmp/vettalon-experiment-preview/refute.json
python3 benchmarks/counterexample-rag/rag.py --output /tmp/vettalon-experiment-preview/rag.json
```

Context selection retains unknown calls and reports parser/read/time/byte omissions;
it does not execute the positive/safe file-read examples. Its current defaults are
40 modules, 64 KiB per source file, 16 KiB payload, two seconds and depth three,
with additional hard upper bounds. A selected syntax path is not a confirmed
security path. RAG payloads have a 4,096-byte cap and reserve 1,024 output tokens;
the dry-run does not consume those model tokens.

Comparison defaults to dry-run; `--mock` delivers fixed local replies only. It
freezes one bounded source snapshot, retains omissions and unknown inventory,
and rejects comparison across different scope/snapshot hashes. Common caps include
16 KiB selected source, 32 KiB UTF-8 prompts, 256 response bytes, three calls and
two seconds per selector child. Bytes are not tokens. See its
[full contract and tests](../benchmarks/context-selection/README.md).

## Prepare twins before running mock or real inference

Generated anonymous files, oracle bookkeeping, subset manifests and raw outputs
are deliberately absent from the public source allowlist. Recreate them locally
from the self-authored protocol. Keep oracle bookkeeping out of model prompts.
Because the protocol is public synthetic source, transport separation alone does
not establish an independent hidden benchmark or protection from memorization.

In a fresh source checkout, with the Docker image already loaded:

```bash
python3 benchmarks/blind-twins/protocol.py generate
python3 benchmarks/blind-twins/protocol.py canonical
```

`generate` materializes the synthetic source set, bookkeeping and the deterministic
five-pair subset. `canonical` creates a local baseline at the runner's current
fixed working-artifact convention:
`reports/evidence-acceptance/experiments/canonical-oracle.json` and
`denominator.json`. These paths are **newly generated local outputs**, not required
private files shipped with the project. The runner checks both baseline digests
before executing any mock or model arm.

Canonical execution compiles/runs each specimen's function and oracle in a fresh
container. It checks the principal/object/operation/state security effect plus a
normal control. Exit zero alone is insufficient. Defaults include read-only root,
UID 65534, network none, cap-drop ALL, no-new-privileges, 32 PIDs, 128 MiB, 0.5 CPU,
an 8 MiB tmpfs and a 20-second execution bound per specimen.

Existing canonical/raw artifacts must be preserved. A separate canonical rebuild
can use `--output /tmp/NEW_DIRECTORY/new-canonical.json` after creating its parent;
its denominator is saved alongside under the derived filename. That alternate
file does **not** silently replace the runner's baseline. Freeze/version a new
baseline before model tests; do not discard failed cases after seeing results.

Run a bounded mock subset and recompute from that exact raw file:

```bash
python3 benchmarks/blind-twins/run.py --mock \
  --subset-path benchmarks/blind-twins/fixed-five-pair-subset.json \
  --output /tmp/vettalon-experiment-preview/mock-subset.json
python3 benchmarks/blind-twins/aggregate.py \
  --raw /tmp/vettalon-experiment-preview/mock-subset.json \
  --output /tmp/vettalon-experiment-preview/recomputed.json
python3 benchmarks/blind-twins/rehearse.py \
  --output-dir /tmp/vettalon-experiment-preview/rehearsal
```

Rehearsal schedules three arms × five repeats on the same five-pair subset:
250 **mock transport invocations**, zero real-model calls. A genuine repetition
study requires a predeclared budget, selected distinct model families, equal
scope/context limits and independent adjudication. Same-family review is an
experiment arm; it does not change the product's cross-family review policy.

Real inference is opt-in: omitting `--mock` calls the local model. Current hard
limits are 20 calls per run, 90 seconds per call, 1,024 output tokens, 1,200 seconds
wall time, one inflight request, no automatic retries and repeat index 0–4. Finder
and verifier share that call budget. A full 20-specimen two-stage run cannot fit
40 calls into the 20-call cap; use the fixed five-pair subset to fit both stages.
Insufficient budget remains incomplete; it must not shrink the denominator.
Do not start a real model experiment from this document without choosing its
models and total resource budget first.

New runner records include process-only `RUSAGE_SELF` CPU intervals with source
bindings. RSS is a process-lifetime high-water-mark observation: it cannot be
reset per run, so `peak_memory_bytes` remains unknown. Model servers, child
processes, GPU, electricity, USD and human review are excluded; historical raw
records receive no invented measurements. See the [measurement scope](../benchmarks/blind-twins/README.md).

The formal-v1 report exposes the same validated recorded observations in
`resource_summary` for twins, context selection and RAG, plus the raw recorded
`wall_seconds`. Missing/null values remain unknown; malformed resource records
and non-finite, negative or non-numeric wall observations (including booleans)
are rejected. This reader does not sample current resources or expand the
runner-process-only scope. Its RSS observation remains a process lifetime
high-water mark, not a per-run peak. Effectiveness, existing metrics, cost
attachments, provider readiness and the legacy reader contract are unchanged.

## Differential oracle and finite fuzz reproduction

After canonical baseline preparation, verify the selected five synthetic pairs:

```bash
python3 benchmarks/differential-poc/evidence.py \
  --output /tmp/vettalon-experiment-preview/differential.json
```

The summary validates raw pointers, unique fresh containers, image/source/harness
hashes, isolation settings, normal control and vulnerable=true/patched=false
security effects. It does not convert any product finding to `confirmed`.

For the separate native toy fuzz prototype, preload its declared image and run:

```bash
python3 benchmarks/bounded-fuzz/fuzz.py --output /tmp/vettalon-experiment-preview/native-fuzz.json
```

This fixture searches at most 128 inputs, minimizes with at most 64 replays, and
bounds native execution to 30 seconds. “No counterexample within budget” is not
“proved safe.” Harness/build/control errors remain incomplete. The scanner does
not run this prototype by default.

## Two-host Go reachability experiment

This adapter supports the two self-authored Go fixtures and one advisory subset.
It is not a general customer-repository execution framework. Rust returns unknown
as unsupported. `not-observed` means this analysis configuration did not observe a
symbol path; it does not remove an alert. Reachable/unknown/not-observed retain
`under_investigation`. The policy record is not a complete OpenVEX document and
never issues `not_affected`.

Prepare the official pinned tool in a new tool directory:

```bash
mkdir /tmp/vettalon-reachability-tools-preview
GOBIN=/tmp/vettalon-reachability-tools-preview GOTOOLCHAIN=local \
  GOSUMDB=sum.golang.org GOPROXY=https://proxy.golang.org \
  go install golang.org/x/vuln/cmd/govulncheck@v1.4.0
```

Supply exactly the public advisory snapshot expected by this prototype. Download
and checksum verification are explicit; a changed upstream document must trigger
a review, not a skipped digest check. This is one advisory, not a full DB:

```bash
mkdir /tmp/vettalon-reachability-db-preview
curl --proto '=https' --max-time 30 -fsSL https://vuln.go.dev/ID/GO-2021-0113.json \
  -o /tmp/vettalon-reachability-db-preview/GO-2021-0113.json
python3 -c 'from pathlib import Path; import hashlib; p=Path("/tmp/vettalon-reachability-db-preview/GO-2021-0113.json"); assert hashlib.sha256(p.read_bytes()).hexdigest() == "24896a2df144d2497bad35b949f6f7409d6755d36ce854ad8ad7d9232538f622"'
python3 benchmarks/reachability/run_experiment.py \
  --tool /tmp/vettalon-reachability-tools-preview/govulncheck \
  --db /tmp/vettalon-reachability-db-preview \
  --output /tmp/vettalon-reachability-preview-output
```

The runner supports POSIX macOS/Linux and at most two self-authored hosts, one
analysis at a time. Its fixed Python supervisor retains group ownership through
normal target exit as well as failure, reports target status over a private pipe
not inherited by the target, then cleans the same process group before reaping
the supervisor. Each invoke has an execution deadline of at most 120 seconds,
followed by one shared one-second cleanup budget for kill/reap/pipe draining.
The retained stdout/stderr prefixes are capped independently at 4 MiB/1 MiB.
Capture records retain byte counts, hashes and truncation/strict UTF-8 flags;
invalid UTF-8 also retains the bounded byte prefix as base64. These are retained
byte limits, not a promise that the process emitted no more bytes.

Only exit zero with complete versioned status, no timeout/error/truncation/decode
or cleanup failure and consistent capture bytes/hashes can enter successful
classification or cache. Any such failure, missing source/module/symbol or source
change becomes `unknown`; no findings is insufficient to infer not-observed.
Cache implementation binding includes both adapter and supervisor source hashes;
legacy observations missing the new control contract cannot be accepted as new
successful cache hits. Other dimensions still bind host/dependency source,
toolchain/tool, tags/features/target and DB digests. A cache hit is not signed
attestation or protection from a same-user cache editor.

This is process-group ownership, not containment: a child that calls setsid can
escape the group; inherited pipes may instead cause bounded cleanup failure.
Process spawn, OS scheduling and file I/O are not universally preemptible, so
120 seconds plus cleanup is not an absolute all-CLI wall bound. The runner checks
its 30-minute analysis budget between hosts; setup downloads have separate
limits. It does not execute the host application or exploit a vulnerability.
The maker reports 47 tests for the current process-control subset; independent
runtime diff review approved that implementation. Root runtime and public-stage
acceptance must be checked against their own source-bound receipts.
Earlier two-host/cache results belong to their recorded source checkpoint.

## Tests and interpretation

After preparing the local canonical baseline required by the twins runner:

```bash
python3 -m unittest discover -s benchmarks/blind-twins -p 'test_*.py'
python3 -m unittest discover -s benchmarks/context-selection -p 'test_*.py'
python3 -m unittest discover -s benchmarks/differential-poc -p 'test_*.py'
python3 -m unittest discover -s benchmarks/refute-corpus -p 'test_*.py'
python3 -m unittest discover -s benchmarks/counterexample-rag -p 'test_*.py'
python3 -m unittest discover -s benchmarks/bounded-fuzz -p 'test_*.py'
python3 -m unittest discover -s benchmarks/reachability -p 'test_*.py'
```

Unit/mocked boundary checks prove their exercised contracts. They do not replace
fresh-container execution, actual native tool runs, model experiments, independent
human adjudication or a final public-source/release review. Preserve raw failures,
record exact command/revision/digests and keep generated source/oracle/raw model
outputs private until their publication scope has been separately reviewed.

See [Trust](TRUST.md) for artifact verification limits. This preview makes no
accuracy, cost, recall, certification or competitive-performance claim.

## Fresh synthetic runner-to-finding linkage

This opt-in adapter accepts only the first naming variant of the five self-built
families. It does not import historical canonical receipts. The fixture builder
creates five **declared synthetic candidates**, source files and exact pair
bindings; no scanner or model discovers these candidates. Its report deliberately
remains `incomplete` / `scope_not_fully_reviewed`.

Use a new directory beneath a non-symlink parent. On systems where `/tmp` is a
symlink, select its resolved directory or use a directory beneath the checkout:

```bash
python3 benchmarks/differential-poc/link.py fixture --output ./synthetic-link-input
./target/debug/vettalon validate ./synthetic-link-input/report.json
python3 benchmarks/differential-poc/link.py run \
  --report ./synthetic-link-input/report.json \
  --bindings ./synthetic-link-input/bindings.json \
  --vettalon ./target/debug/vettalon \
  --docker-socket /absolute/path/to/local/docker.sock --output ./synthetic-link-run
```

`run` snapshots and validates the exact input with the explicitly selected trusted
local Vettalon executable before starting Docker. Missing `file_hash`, a wrong
finding/pair/path, changed source, old nonce, reused container, contradictory
stdout/inspect, missing control, timeout or cleanup failure cannot produce a
matched bundle. The launcher creates a 256-bit run nonce, embeds it in the
harness, stdout and Docker labels, verifies the create-before-start state and
executed command, and retains bounded raw command receipts. All receipts remain
local, unsigned, **operator-supplied data**, not a trusted attestation service.

The Docker endpoint must be an explicitly selected existing local Unix socket.
The launcher resolves it, records the socket and requested-entry identity, pins
every Docker command with `--host unix://...`, clears Docker routing environment
overrides and rechecks the socket identity before producing bundles. This does
not establish a host OS egress firewall or trusted-daemon attestation.

One invocation runs at most ten sequential containers using an already loaded
pinned image ID, `--pull never`, no network, no bind mounts, non-root, read-only
root, dropped capabilities and fixed memory/CPU/PID/tmpfs limits. The execution
budget is 300 seconds; a final cleanup command has its own 15-second allowance.
Each command has at most 256 KiB combined stdout/stderr, drained while running;
timeout/overflow kills the local command process group and records incomplete.
Docker create gets a deterministic nonce-derived name so failure before receiving
a container ID still triggers bounded cleanup by name. Cleanup failure remains
explicit and needs operator attention. There is no host-code fallback or retry.

A successful `checks.json` says `synthetic_contract_matched`, not confirmed.
Its manifest entries identify each artifact directory and the five mandatory
source/execution/control roles. Import each into a **new** report with the existing
`vettalon evidence attach` command and validate/export the resulting report. The
adapter generates manifests; it does not perform attachment itself. The CLI
checks artifact hashes and shape; it does not independently execute or establish
the security semantics claimed by a supplied artifact. Finding status, run
status and human decision remain unchanged. Keep input, runner hashes, raw
receipts and output hashes with the result; a copied or edited bundle cannot
establish freshness merely by containing a nonce.

## Recorded local engineering checkpoint (2026-10-16)

The root reviewer independently ran the fixed five-family synthetic linkage:
ten fresh containers, five generated manifests, five successful CLI attachments
and six successful validations. A separate export through the actual production
library produced five SARIF results with the same proof records as JSON. Findings
remained `candidate`, the report remained `incomplete`, artifact origin remained
`operator_supplied`, and human decisions remained null. This checks the declared
synthetic contract and report transport; it is not arbitrary-target execution
semantics, trusted-daemon attestation, human acceptance or model effectiveness.

At the recorded source checkpoint, the public runtime passed 107 experimental
tests plus 27 reachability tests (134 total); the separate trust suite passed 63.
It also rebuilt twenty distinct canonical containers with zero real-model calls.
Preparation failures were retained: tests first lacked the canonical baseline,
and a later fixture command lacked its output parent. Successful runs followed
explicit preparation and did not overwrite those failures. These are root-run
checkpoint results, not fresh executions caused by this documentation update.
Historical counts and line-coverage percentages do not establish coverage of a
later source revision. Internal raw, oracle labels and review records are not
shipped as public evidence links; use the commands above to create new local
artifacts. No real three-arm model study or release is claimed.
