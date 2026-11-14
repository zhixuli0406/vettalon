# retest_package: A retest delivery package built from verified receipts

## What it means

`vettalon receipt package` turns machine evidence into a folder (or zip) a tester can hand to a client or auditor as a retest record. Inputs are a `retest` report, `reproduce` receipts, `fix check` receipts, optionally the old scan report, the TargetCall plans and A5 signature bundles. Every input is validated again before anything is written. If any rule fails, the whole package is refused; there is no partial package.

```sh
vettalon receipt engagement-template --lang zh-TW > engagement.toml
vettalon receipt package --retest retest.json --reproduce reproduce.json \
  --fix-check fix.json --report old-report.json --include-report \
  --targets plans.json --engagement engagement.toml --lang both --out delivery
vettalon receipt verify-package delivery
```

For optional hybrid signatures, `receipt package` accepts repeatable `--pq-sig SIDECAR` inputs and `--pq-pub mldsa.pub`. With `--pq-pub`, `--key cosign.pub` is also required and every bundle must have a matching sidecar; both signature layers must verify. Without `--pq-pub`, sidecars can be included and their content bindings checked without claiming cryptographic PQ verification.

```sh
vettalon receipt package --retest retest.json --bundle retest.json.sigstore.json \
  --pq-sig retest.json.mldsa.json --key cosign.pub --pq-pub mldsa.pub --out delivery
vettalon receipt verify-package delivery --key cosign.pub --pq-pub mldsa.pub
```

`verify-package` reads the packaged sidecars, so it takes `--pq-pub` rather than a separate `--pq-sig` input. With `--pq-pub`, every bundle needs a sidecar and `--key` is required. A stored PQ verification claim is refused without the verifier-supplied PQ key; that key must match the packaged public key byte for byte. Obtain both trusted public keys out of band. `verify-package` accepts any cosign v3.x release; it need not match the producer's exact v3.x release. Tool trust requirements and signature limits are described in [receipt_signing](receipt_signing.md) (`vettalon explain receipt_signing`).

The package contains:

- `receipts/`: exact copies of the validated receipts, plans and bundles.
- `record.json`: the record view model. Machine fields come only from receipts. Attack inputs (「測試語法」) are recovered from the fixed oracle input tables and variant sets, never copied from free text.
- `record.zh-TW.md` and/or `record.en.md`: the human record, laid out like the practitioner sample: basic information, summary, per-finding test syntax and results, environment, what the record does not show, field mapping, evidence appendix, how to verify. Each row cites short evidence ids (`E1`, `E2`, …) that resolve to a package path and SHA-256 in the appendix.
- `mapping.json` and `text.json`: the PCI DSS v4.0.1 11.4.4 and 共契 retest field mapping and every display string, as data.
- `engagement.json` when `--engagement` is given, and `report/` when `--include-report` is given.
- `manifest.json`: size and SHA-256 of every other file. The package id is the SHA-256 of the canonical manifest.

The same inputs and the same Vettalon version always produce the same bytes.

`--engagement` takes a closed-schema TOML file (`vettalon receipt engagement-template` prints one with every key blank) for facts the tool cannot know: client, engagement id, scope, scope approval reference, dates of the original test and the retest, tester, reviewer, contracted unit, method note, and per-finding notes. Unknown keys, invalid dates, control, bidi and other invisible characters are refused. Blank values stay blank and render as 「未記錄」/"not recorded"; nothing is filled from the clock, git or the OS user. An optional tester conclusion is printed verbatim under a heading that says it is the tester's own judgement, not checked by the tool.

`vettalon receipt verify-package <dir|zip>` refuses extra, duplicate, traversing or symlinked entries, recomputes every SHA-256, validates the packaged receipts again and re-renders `record.json` and the Markdown files to compare bytes. A stored "signature verified" claim is accepted only when `--key` is given and cosign verifies the bundles again with that key in this run. Exit codes: 0 verified, 1 content mismatch, 2 refused or invalid input, 3 produced by a different Vettalon version (hashes and file set checked, re-render skipped).

## Why you see it

You ran `vettalon receipt package` or `vettalon receipt verify-package`, or a refusal token from them sent you here. A package is refused, and `verify-package` does not pass, when one of these rules does not hold:

1. A `still_observed` or `not_observed` retest result must carry its reproduce receipt. The retest status, reason and replay count must follow from the embedded receipts or a recognized receipt-less failure. Every embedded receipt must carry a verification event whose finding id matches the result and whose target file and function match the receipt; legacy event-less reproduce receipts cannot be embedded. Duplicate result finding ids are refused.
2. Each new file hash must equal its embedded receipt's target file hash. With no new hash, `rebound` must be false; otherwise it must equal whether the recorded old and new hashes differ, using the generator's verbatim comparison. When the scan report is supplied, the old hash, title and CWE must match its finding.
3. When a report is supplied, its SHA-256 must match the one the retest recorded, and with a scan report the old commit must equal its `repo_commit`.
4. Each reproduce and fix-check receipt must bind to exactly one finding (file, hash, function and oracle class); ambiguous or conflicting bindings are refused.
5. Each signature bundle must match the receipt bytes it names; with `--key`, cosign must verify it.
6. Any refusal refuses the whole package.
7. Report text (finding names, paths, function names) is marked as report text not checked by receipts, and control, bidi and zero-width characters are made visible.

Signing and packaging share all report-independent retest checks, including field formats, receipt validation, hashes, rebound and finding identity. The `/retest/v2` signing predicate includes each embedded receipt's target file and function. Normal Python and Node runs carry events; the generator records failures without an event as receipt-less results, preserving environment/deadline failure statuses and otherwise using `inconclusive` / `unbound_receipt`. These rows do not claim execution evidence.

Input files must be regular files with a single link, read without following symlinks, within a 64 MiB total budget counted while reading. Outputs are created new (an existing `--out` is refused), through a temporary sibling directory that is bound by identity, with modes 0700 for directories and 0600 for files.

## What it does not show

- It is a record of tool re-runs, not a manual penetration retest.
- The field mapping is not a statement of compliance with PCI DSS, 共契 or any other standard, and the mapping text has not yet been checked against the source standards (`source_checked: false`; the record says so).
- Operator fields (client, tester, dates, conclusion) are the operator's statements.
- Results hold only for the recorded revision, inputs and variants.
- Per-variant results on the original copy, the retest start time and raw transcripts are not recorded by the receipts; the record says "not recorded" rather than inferring them.
- Without a trusted key delivered over a trusted channel, hashes and signatures show internal consistency, not that the runs happened.

## Known limits

- When `--report` is given, `--include-report` is required, because the record's report-derived fields cannot be re-rendered without it.
- On Windows the output inherits the parent directory's ACL (no owner-only DACL), and the staging directory is checked for reparse points but tracked by path, not by file ID.

## What to do

- Refused at package time: the token names the rule. Re-run the step that produced the inconsistent input (`retest`, `reproduce`, `fix check`) instead of editing receipts by hand, then package again into a new `--out`.
- `verify-package` exit 1: the package changed after it was built. Get a fresh copy from the tester, or rebuild it from the original inputs and compare the package id (the manifest SHA-256) over a trusted channel.
- Exit 3: verify with the Vettalon version recorded in the manifest.
- A stored signature claim refused without `--key`: pass the signer's public key, obtained out of band.
- Fill operator facts in the engagement file before packaging; blank fields are printed as not recorded.

## Related

- [retest](retest.md)
- [receipt_signing](receipt_signing.md)
- [fix_check](fix_check.md)
- [node_exec](node_exec.md)
