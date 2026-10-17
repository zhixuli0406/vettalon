# OpenSSF checks: evidence and gaps

This is a repository self-assessment, not a Best Practices badge, certification,
audit opinion or SOC 2 report. Scorecard and Best Practices are different programs.
A Scorecard number is a repository snapshot, not evidence of detection precision.

| Practice | Repository evidence | Current gap / required external evidence |
|---|---|---|
| License and contribution rules | `LICENSE`, `NOTICE`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` | Human review still needed for third-party/license compatibility. |
| Vulnerability reporting | `SECURITY.md`; private GitHub reporting route | Response targets are policy, not measured response performance. Confirm repository feature settings separately. |
| Tests and static checks | `.github/workflows/ci.yml`; Rust fmt/test/clippy and trust unit tests | A workflow file does not prove the latest run passed. No unsupported full-code coverage claim. |
| Signed release and provenance | `.github/workflows/release.yml`; [verification guide](TRUST.md) | New artifacts need an actual release run and downloaded-asset verification. No SLSA level claimed. |
| Dependency inventory | Syft adapter and official CycloneDX schema validation | Source lock inventory has conditional/target uncertainty. No complete malware detection or reachability claim. |
| Token permissions | CI/release default `contents: read`; job-specific OIDC/attestation writes | Release job needs publishing rights. Scorecard command accepts only a separately supplied read-only token. |
| Branch protection / review | Pull-request template and review process | Repository settings, required reviewers/statuses and actual review history require live verification. Do not infer enforcement from a document. |
| Dependency pinning | `Cargo.lock`, `--locked` trust/release commands | Existing third-party Actions use version tags; commit pinning remains an explicit gap. |
| Security.txt | Security reporting linked from repository | No claim that a website `/.well-known/security.txt` has been deployed or validated. |
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
