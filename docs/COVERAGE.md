# Coverage and proof records

Preview for the next release. A clean result applies only to the recorded scope. Complete execution is not a guarantee that source code is safe.

## OSS experiment harness tests (2026-10-19 local run)

The Python context-selection adapter passed 39 unit tests and the formal
transport passed 99 in the prior local run. The separate v3 multi-language
capture, range, source-scope, and isolated syntax suite passed 43 on macOS in
this follow-up. These counts verify their fixtures and fail-closed contracts,
including forged selector envelopes, over-budget byte ranges, and swapped
directory/snapshot metadata. They are **test-case counts**, not measured line
or branch coverage, vulnerability recall, target execution, or provider-model
results. No line/branch coverage was collected for these Python components in
this run. The v3 syntax parser does not resolve cross-file reachability or
select model context, and none of these tests admits an E1 specimen; the
formal E1 denominator remains 0/45 executed pairs.

## Source-code test coverage is a separate denominator

The scan-report `coverage[]` below describes which customer source ranges entered
review. It is not the test suite's line or branch coverage. A bounded test
coverage receipt for the **public CLI v0.2.0 source tag** is kept in the
maintainer's local acceptance records. The receipt, its readbacks and the
receipt wrapper are not part of this repository; this section records what
they contain and how they were produced.
It records commit `e3493f620487d23dbbd6a13021c216f415974585`, a clean tracked-file
content manifest, Rust nightly `2026-10-17`, and `cargo-llvm-cov 0.9.1`. The
`vettalon-contract` package's 45 unit tests measured 1,246/1,274 source lines
(97.8022%) and 149/160 branches (93.125%) across six reported `src/*.rs` files.
`src/lib.rs` is listed as unmeasured in the receipt. This is neither whole-CLI,
Desktop/Pro, nor published-binary coverage. The published binary's test coverage
is **unknown**; the source tag match alone does not instrument that binary.

The wrapper runs against a fresh checkout with the reviewed, pinned Rust
toolchain and coverage helper, and takes new output and target paths outside
the checkout. The wrapper refuses a dirty tree, tracked bytes differing from
the tag's HEAD blobs (including `assume-unchanged` files), wrong full source commit/tag,
missing or zero line/branch denominator, failed tests, extra/untracked LLVM
source files, and source differences observed in the post-run snapshot. It
cannot detect a file modified and restored between snapshots. New v2 runs
retain at most 2 MiB of each stdout/stderr stream, hash all observed bytes,
immediately stop the process group when either limit is exceeded, drain for at
most five seconds, and fail closed on truncation or missing EOF. JSON and log
readback uses a single `O_NOFOLLOW` descriptor per file with bounded reads,
file identity checks and a stream hash; symlinks, oversized files and files
changed or replaced during read are rejected. The preserved v1 logs predate
this stream ledger. The LLVM export is **summary-only**: the verifier sums
per-file `count` and `covered` values and compares them with LLVM's aggregate.
It does not independently derive hits from detailed execution counters.
The receipt records the original checkout root; verification maps LLVM's
absolute raw filenames into a different clean checkout only when the path is
canonical, inside the recorded package source directory, and tracked at the
same tag. The pre-amendment receipt was kept as a
separate copy with SHA-256 `dab756aa0c182789514f555392f185bbb25611b587b5e49629bd6c9c14505331`;
the amended receipt has SHA-256 `8efe858bd230a14e2c423a88ca597b42e65e624c74e4de9ce7657f2c080fc4b7`.
Only the recorded source-root and test-scope wording changed. The receipt's
`runner_sha256` describes the historical execution code, whose original bytes
are unavailable here; subsequent verifier versions have different SHA-256
values and only revalidate the unchanged raw artifacts. The original
verification readback is retained with its original verifier hash. The
historical schema-v2 readback records that verifier version's hash, matching results after copying the
byte-identical receipt directory to a new location, and rejection of a
modified legacy receipt.

The verifier also requires the exact recorded command shape: `cargo
+nightly-2026-10-17 llvm-cov --branch --json --summary-only --output-path
<original-output-dir>/llvm-summary.json -p <receipt package> --locked`, with no
extra or reordered flags, `cargo-llvm-cov 0.9.1`, and the recorded nightly Rust
release. The existing `vettalon-rust-coverage-v1` receipt is accepted only at
its pinned full SHA-256, which also pins its original output path. New runner
receipts use `vettalon-rust-coverage-v2` and record `scope.original_output_dir`,
so byte-identical receipt copies can be verified from another directory.
It rejects synchronized changes to `command.json`, its artifact digest and the
receipt when they remove branch instrumentation or change scope. A changed v1
receipt cannot become valid by adding the v2 field. This checks internal
arithmetic consistency of LLVM summary counts; a wholly forged, unauthenticated v2
receipt remains possible. The unavailable historical runner bytes cannot be
reconstructed from its hash.

For a review tied to this particular release source, pass all three caller
anchors to `verify`: the preserved receipt SHA-256, full source commit and tag.
The verifier rejects a partial set or mismatch before it reads coverage
percentages. These values can be forged together with an unsigned local
receipt, so a match alone is **not provenance verification**. Substitution
detection requires expected values from an independently trusted channel,
not from the receipt or readback being checked.
The anchored readback
records a successful original and relocated verification plus five failing
negative cases. It checks the historical package-scoped result only; it does
not authenticate a new v2 receipt without an independently retained digest.
The readback and receipt are local, unsigned files. Their results separately
report LLVM summary arithmetic consistency, caller-anchor match, and
`provenance_verified: false`. A hash printed beside its own receipt is not
proof of origin or release authenticity.
The readback also observed the remote `v0.2.0` tag resolving to the expected
source commit and a published GitHub release at that time. That observation
does not establish that a shipped executable was built from or instrumented at
that commit.

The commands below record the maintainer's run. `COVERAGE_RECEIPT` stands
for the receipt wrapper, which is not published in this repository.

```bash
git clone --depth 1 --branch v0.2.0 --single-branch \
  https://github.com/zhixuli0406/vettalon.git /tmp/vettalon-v020-source
rustup toolchain install nightly-2026-10-17 --profile minimal --component llvm-tools-preview
cargo install --root /tmp/vettalon-cov-tools --version 0.9.1 --locked cargo-llvm-cov
python3 "$COVERAGE_RECEIPT" \
  --source-root /tmp/vettalon-v020-source \
  --expected-source-sha e3493f620487d23dbbd6a13021c216f415974585 \
  --expected-tag v0.2.0 --package vettalon-contract \
  --cov-bin /tmp/vettalon-cov-tools/bin/cargo-llvm-cov \
  --expected-cov-version 'cargo-llvm-cov 0.9.1' \
  --toolchain nightly-2026-10-17 \
  --output-dir /tmp/NEW-vettalon-cov-receipt \
  --target-dir /tmp/NEW-vettalon-cov-target
python3 "$COVERAGE_RECEIPT" verify \
  --receipt-dir /tmp/NEW-vettalon-cov-receipt \
  --source-root /tmp/vettalon-v020-source \
  --expected-receipt-sha256 EXPECTED_NEW_RECEIPT_SHA256 \
  --expected-source-sha e3493f620487d23dbbd6a13021c216f415974585 \
  --expected-tag v0.2.0
```

Replace `EXPECTED_NEW_RECEIPT_SHA256` with a digest retained independently
before review; do not copy it from the receipt under test at verification time.
To verify the existing historical receipt, use its pinned SHA-256
`8efe858bd230a14e2c423a88ca597b42e65e624c74e4de9ce7657f2c080fc4b7`.
Available disk at the latest readback was approximately 13 GiB. No new whole-CLI
instrumented build was attempted, so whole-CLI and Desktop/Pro line/branch
coverage remain unmeasured.

The `--branch` instrumentation is unstable. The older `cargo-llvm-cov 0.8.5`
failed on stable Rust and did not collect objects on the pinned nightly; those
failed attempts are retained beside the accepted receipt. Do not substitute a
test count, a zero-branch JSON, or an unsigned local build record for this
source-bound line/branch result.

## Reproduce the public examples

```bash
cargo build -p vettalon
python3 fixtures/coverage/generate.py --binary target/debug/vettalon --output /tmp/vettalon-coverage-new
vettalon validate /tmp/vettalon-coverage-new/complete.json
vettalon validate /tmp/vettalon-coverage-new/module-cap.json
```

The output directory must not exist. The tool creates disposable, self-authored source and a fixed loopback mock provider, runs ten bounded CLI scans, sanitizes environment diagnostics, and validates every resulting report. No customer source, paid model, target exploit or automatic PoC is used. Optional static scanners can have their own database/network requirements; this is not a whole-machine offline guarantee.

Checked-in examples: [index](../fixtures/coverage/samples/index.json), [complete](../fixtures/coverage/samples/complete.json), [module cap](../fixtures/coverage/samples/module-cap.json). The other cases cover byte truncation, UTF-8 truncation, malformed replies, non-UTF-8 reads, wall-clock budget, engine errors, empty content and candidate caps. These are engineering fixtures, not a detection benchmark or public vulnerability discoveries.

## Read the denominator

`coverage[]` accounts for every ranked module/page after the existing code-file filters. `scope_paths` includes omitted files. `selected` means the module entered the module allowance; `attempts` retains every scheduled finder, including a failed finder beside a successful one.

Each file records read status, known source byte/line counts, actual submitted source bytes, 1-based submitted line range and truncation. Prompt wrapping is excluded from submitted byte counts. A truncated final line may be partial. Successful disk reads, refused calls and malformed replies do not establish model review.

`summary.coverage.scanned` requires a valid reply containing nonzero source content with a nonempty, unique scope; `scanned + skipped = modules_total` for modern records. `covered` requires every scheduled finder to finish its complete scope without candidates. `candidate` is a finding state, not proof of complete source coverage. Always inspect `partial`, per-file omissions and per-finder attempts.

Missing attempts, empty denominators, all-empty files and failed attempts cannot become complete coverage. Modern records mixed with historical covered rows lacking evidence are incomplete. A wholly historical JSON without the ledger remains readable; absent evidence stays unknown rather than being reconstructed as a verified run.

The 40-module safety ceiling, six pages per parent module and 48 KiB source-text budget per prompt remain. Overflow stays in the final page's denominator and is marked budget-excluded when omitted. A deadline can stop an in-flight finder or correction call. Missing/failed/truncated scope is retained as incomplete, including in SARIF properties.

## Structured proof categories

Findings optionally carry `proof_evidence[]`. An absent historical field means `unknown`, even when an older transcript says exit 0.

| Level | Meaning and limits |
| --- | --- |
| `pattern_demo` | The existing explicit sandbox step executed a standalone reconstruction. The target repository is not mounted or executed; this is not target exploit validation. |
| `target_execution` | An operator declares target source/execution artifacts. Attachment checks local hashes and sizes, not whether the security claim is true. |
| `differential_oracle` | An operator declares paired vulnerable/patched source, execution and normal-control artifacts. Attachment checks structural completeness and hashes, not the oracle's semantics or independence. |

A record includes origin, run id, manifest SHA-256, artifact roles/relative paths/SHA-256/bytes, optional differential pair id, and optional operator-supplied human-decision data. None of these fields changes a finding's status, authorizes disclosure, or constitutes trusted build provenance. Links, hashes and exit 0 do not automatically confirm a vulnerability. Existing generated PoCs remain pattern demonstrations.

The Ammonia 4.2.3/4.2.4 standalone paired run is an external library-policy regression with raw outputs and an offline readback verifier, both kept in private acceptance records. It is not a Vettalon finding attachment or a product detection score. Its verifier checks the archived bytes and declared container policy for internal consistency; it cannot independently attest the Docker daemon, crates.io response, or unpublished pinned dependency payload.

The aiohttp 3.9.1/3.9.2 local paired case (case files and receipts kept in
private acceptance records) has a bounded run-08 four-cell receipt bound to the current runner and checked by offline raw HTTP readback. Run-06 and run-07 remain incomplete historical attempts. This case has not been attached to a Vettalon finding or used to calculate product detection performance. Its no-symlink fixture cannot establish a general containment guarantee for `follow_symlinks=True`.

## Attach local evidence without executing it

```bash
vettalon evidence attach --report scan.json --finding FINDING_ID \
  --manifest proof-manifest.json --artifact-root ./local-artifacts \
  --output scan-with-proof.json
vettalon validate scan-with-proof.json
```

The output must be new. The input report is validated before and after attachment. The manifest is at most 128 KiB; at most 16 unique artifact paths/roles are accepted, each at most 4 MiB and at most 16 MiB total. Paths must be safe local relative paths; symlink artifacts/ancestors, missing files, wrong digests/sizes, duplicate run ids, wrong finding ids and unknown fields are rejected. The importer reads bytes only; it does not execute scripts, expand commands, contact services or fetch URLs. If the scan has a file hash, the submitted source artifact must match it.

Manifest shape (replace all values with actual locally computed values; this is not a usable proof by itself):

```json
{
  "schema": "vettalon-evidence-v1",
  "finding_id": "FINDING_ID",
  "level": "target_execution",
  "run_id": "operator-run-unique-id",
  "pair_id": null,
  "artifacts": [
    {"role":"target_source","path":"source.py","sha256":"64 lowercase hexadecimal characters","bytes":123},
    {"role":"target_execution","path":"execution.json","sha256":"64 lowercase hexadecimal characters","bytes":456}
  ],
  "human_decision": null
}
```

For differential records, set `level` to `differential_oracle`, supply a nonempty `pair_id`, and use the five required roles `vulnerable_source`, `patched_source`, `vulnerable_execution`, `patched_execution`, `normal_control`; the two source hashes must differ. An optional `patch` artifact can link the patch itself. For a canonical runner that stores rows together, first export separate local artifact files for the corresponding run/control records and compute their exact hashes; the importer does not interpret runner output or certify isolation/freshness. Keep the original source run record and digest for independent review.

Optional `human_decision` has `actor`, `decision` and RFC3339 `recorded_at`. It records supplied text only. A decision string such as confirmed does not perform the product's operator confirmation workflow.
