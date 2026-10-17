# Coverage and proof records

Preview for the next release. A clean result applies only to the recorded scope. Complete execution is not a guarantee that source code is safe.

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
