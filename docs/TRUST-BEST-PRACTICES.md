# OpenSSF checks: evidence and gaps

This is a repository self-assessment, not a Best Practices badge, certification,
audit opinion or SOC 2 report. Scorecard and Best Practices are different programs.
A Scorecard number is a repository snapshot, not evidence of detection precision.

| Practice | Repository evidence | Current gap / required external evidence |
|---|---|---|
| License and contribution rules | `LICENSE`, `NOTICE`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` | Human review still needed for third-party/license compatibility. |
| Vulnerability reporting | `SECURITY.md`; private GitHub reporting route | Response targets are policy, not measured response performance. Confirm repository feature settings separately. |
| Tests and static checks | `.github/workflows/ci.yml`; Rust fmt/test/clippy and trust unit tests | A workflow file does not prove the latest run passed. No unsupported full-code coverage claim. |
| Signed release and provenance | `.github/workflows/release.yml`; [verification guide](TRUST.md); [public CLI v0.2.0 readback](../reports/evidence-acceptance/cli-v020-public-trust-readback-20261019/README.md) | The dated public readback freshly downloaded and checked four CLI archives and 24 sidecars, with four current verifier passes. Its sanitized receipt omits raw external verifier output and has no independent signature; repeat the checks independently. Current worktree and Desktop/Pro releases need their own execution and verification. No SLSA level claimed. |
| Dependency inventory | Syft adapter, official CycloneDX schema validation and a Cargo source-lock graph comparator in the current tooling | No public execution receipt links a release asset to a fresh graph comparison here. All-locked graph equality alone does not establish target resolution, linked composition, complete licensing, malware detection or reachability. |
| Token permissions | CI/release default `contents: read`; job-specific OIDC/attestation writes; `.github/workflows/scorecard.yml` is `read-all` with job-level `security-events`/`id-token` writes for publishing | Release job needs publishing rights. The Scorecard workflow uses the default `GITHUB_TOKEN`; the local `scorecard.sh` wrapper still accepts only a separately supplied read-only token. |
| Branch protection / review | Pull-request template and review process | Repository settings, required reviewers/statuses and actual review history require live verification. Do not infer enforcement from a document. |
| Dependency pinning | `Cargo.lock`, `--locked` trust/release commands; Scorecard workflow actions pinned to commit SHAs | CI and release workflows still use version tags; commit pinning there remains an explicit gap. |
| Security.txt | Security reporting linked from repository; [public security.txt](https://vettalon.dudustudio.monster/.well-known/security.txt) returned HTTP 200 in a 2026-10-18 readback | Availability does not establish mailbox response, repository private-reporting settings or policy performance. |
| Assurance / certification | Local test and verification evidence | No SOC 2 certification, government eligibility determination or external Best Practices submission. |

Run `scripts/trust/scorecard.sh owner/repo new-result.json` with an installed,
checksum-verified official Scorecard release. The wrapper clears inherited
credentials and never publishes results. Inspect tool version, returned repository
commit, individual check errors and unexecuted checks before interpreting results.
An unauthenticated run can be partial due to API limits; record that result instead
of inventing a score. Public-repository checks describe the public commit, not an
uncommitted private working tree.

References: [Scorecard](https://github.com/ossf/scorecard),
[Best Practices criteria](https://www.bestpractices.dev/en/criteria/0).
