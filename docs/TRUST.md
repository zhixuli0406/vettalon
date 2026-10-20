# Verify a release and understand its evidence

Vettalon release evidence is separate from vulnerability detection evidence. A
valid signature identifies a publisher and binds bytes; it does not establish
that the scanner is vulnerability-free, that every dependency is reachable, or
that any finding is correct. No SOC 2 certification or OpenSSF badge is claimed.

## Evidence supplied by the release workflow

| File / service | What it proves when verified | Limit |
|---|---|---|
| `*.tar.gz.sha256` | Downloaded bytes match the stated digest | An unauthenticated checksum alone does not identify the publisher. |
| `*.tar.gz.sig`, `.pem`, `.sigstore.json` | Cosign keyless signature, exact workflow/tag identity and GitHub OIDC issuer, bundle inclusion evidence | Verify cryptographically; sidecar presence alone is insufficient. |
| `*.tar.gz.cdx.json` | CycloneDX 1.6 source-lock inventory from Syft, source commit, public lock hash, target and archive digest | All locked optional/platform dependencies may appear; this is not a binary-linked or reachable inventory. License data may be unavailable; Cargo license enrichment requires the lockfile registry source and checksum-verified archive member, never just a same-name/version cache directory. |
| `*.tar.gz.build-record.json` | Unsigned local record linking asset digest, source commit, lock digest and target | Anyone can edit it. It is **not signed provenance**. Dirty records are unsuitable for release acceptance. |
| GitHub artifact attestation | GitHub-signed SLSA build provenance for actual archive/BOM subjects | Requires actual workflow execution and verification. Adding workflow YAML is not an issued attestation or a SLSA certification. |
| Optional `.minisig` | Signature against a separately trusted minisign key | Optional; do not infer it exists or replace mandatory keyless verification with it. |

The public CLI **[v0.2.0 release](https://github.com/zhixuli0406/vettalon/releases/tag/v0.2.0)**
has a [2026-10-19 public readback](../reports/evidence-acceptance/cli-v020-public-trust-readback-20261019/README.md):
four macOS/Linux archives and 24 mandatory sidecars were freshly downloaded and
matched GitHub release asset digests. Four runs of the current verifier passed
Cosign identity checks and eight GitHub archive/BOM attestation subject checks
for source `e3493f620487d23dbbd6a13021c216f415974585`. The
[sanitized receipt](../reports/evidence-acceptance/cli-v020-public-trust-readback-20261019/receipt.json)
records the verifier source/schema snapshot and results, but omits raw CLI output
and has no independent signature; repeat the checks below to verify them independently.
An older internal readback remains separate from this fresh public run.
It does not attest this private worktree, a future release, Desktop/Pro assets,
complete licenses, or a linked/reachable dependency inventory.
The additional offline Cargo lock-graph comparator in the current tooling was
not used to produce that historical release and does not reissue its attestations.
Later source changes are not retroactively part of those signed assets.
Current Cargo source-lock verification rejects symlinked in-tree source files and
member parents; it needs a platform with no-follow file opening. A local release
sidecar write failure cleans up newly created partial output. Neither behavior
changes historical release assets or establishes binary dependency reachability.

Manual dispatch for another release must run against its actual tag ref, for example
`gh workflow run release.yml --ref vX.Y.Z -f tag=vX.Y.Z`; dispatch from `main`
fails before building/signing. Checkout resolves the same reviewed tag.

Historical releases may lack these artifacts; do not claim they have passed the
new trust gate. The desktop application uses a separate release/signing workflow;
this CLI trust pack does not prove Windows signatures or Apple notarization.
Desktop updater payloads use the application's embedded Minisign public key,
while installer digests, macOS notarization, and native installation need their
own checks. A valid Desktop updater signature is not a CLI Cosign signature,
GitHub attestation, or CycloneDX BOM. A draft release remains a candidate until
its own version-specific readback and native acceptance are complete.

## npm packages: trusted publishing, staged

From the release after 0.2.1, the `npm-publish` job holds no npm token. It uses
[npm trusted publishing](https://docs.npmjs.com/trusted-publishers): the job's
GitHub OIDC token (`id-token: write`) is exchanged for a short-lived credential,
and npm attaches a provenance attestation because the repository and packages
are public. The trusted publisher for each of the five packages (`vettalon`,
`@vettalon/darwin-arm64`, `@vettalon/darwin-x64`, `@vettalon/linux-x64`,
`@vettalon/linux-arm64`) is bound to `zhixuli0406/vettalon` and
`release.yml`, and allows only `npm stage publish`. A staged version is not
installable until a maintainer approves it with 2FA:

```bash
npm stage list vettalon          # and each @vettalon/* package
npm stage approve <stage-id>     # platform packages first, then vettalon
```

Check a published version's provenance with `npm audit signatures` in a project
that installs it, or on the package page on npmjs.com. Provenance shows which
workflow run built the package; it does not prove the source is safe, and a
compromised workflow could still produce valid provenance.

## Verify a downloaded CLI archive

Install `cosign`, GitHub CLI (`gh` with attestation support), Python 3.11+ and the
pinned validator in a virtual environment. Obtain all sidecars from the same release.
Choose the expected tag and **full source SHA independently** from the reviewed tag.

```bash
python3 -m venv .venv-trust
.venv-trust/bin/python -m pip install -r scripts/trust/requirements.txt
PYTHON=.venv-trust/bin/python scripts/trust/verify-release.sh \
  vettalon-linux-x64.tar.gz v0.2.0 e3493f620487d23dbbd6a13021c216f415974585
```

The example names an existing reviewed CLI release; obtain its assets and sidecars
from the same GitHub release. For any later tag, substitute its independently
reviewed full source SHA. The verifier:

1. Requires checksum, signature, certificate, bundle, BOM and unsigned build record;
   checks the archive digest/name and official CycloneDX schema.
2. Uses `cosign verify-blob` with exact
   `https://github.com/zhixuli0406/vettalon/.github/workflows/release.yml@refs/tags/<tag>`
   identity and `https://token.actions.githubusercontent.com` issuer.
3. Uses `gh attestation verify` with repository, exact certificate identity
   (workflow path and tag), OIDC issuer, expected source ref/SHA and GitHub-hosted
   runner requirement. It uses one identity selector because current `gh` treats
   `--cert-identity` and `--signer-workflow` as mutually exclusive. GitHub verification hashes the
   actual downloaded archive and checks the attestation subject.

Wrong identity, issuer, source, missing proof or modified archive must fail. No
`--insecure-ignore-tlog`, wildcard identity, hand-authored provenance substitute,
or local JSON-only verification is accepted. Use GitHub's documented bundle and
trusted-root process for disconnected verification; this wrapper uses GitHub online.

## How accurate is the Cargo inventory?

The release BOM lists every package in `Cargo.lock`. That is more than the build
uses: locks keep optional and platform-specific packages. A differential test
([`sbom_diff.py`](../scripts/trust/sbom_diff.py)) measures the gap against two
oracles: `cargo metadata --locked --offline --filter-platform <target>` (normal
and build edges from the workspace members, default features) and, as a test
oracle only, the nightly-only Cargo SBOM precursor (`-Zsbom`). Neither oracle
feeds the release BOM.

Component precision and recall are on exact name@version. Version accuracy is
per package name present on both sides. License accuracy is reported separately,
only over matched packages whose manifest declares a license.

| Case (aarch64-apple-darwin, 2026-10-20) | Oracle size | Syft size | Precision | Recall | Version accuracy | License accuracy: raw Syft / adapter |
|---|---|---|---|---|---|---|
| `fixtures/sbom/rust` vs `cargo metadata` | 7 | 12 | 0.58 | 1.00 | 1.00 | 0/7 / 6/7 |
| `fixtures/sbom/rust` vs precursor | 7 | 12 | 0.58 | 1.00 | 1.00 | not in precursor |
| Public workspace lock vs `cargo metadata` | 179 | 225 | 0.80 | 1.00 | 0.99 | 0/179 / 177/179 |
| Public workspace lock vs precursor | 169 | 225 | 0.75 | 1.00 | 0.99 | not in precursor |

The public-workspace row uses a working-tree export stage (lock SHA-256
`a560c05f…`), Syft scanning only the manifests and lock. Its 46 extra packages
are platform or optional entries (Windows, wasm, Android and similar crates).
`cpufeatures` and `syn` appear in the lock at two versions while the build uses
one, which is the version-accuracy miss. `cargo metadata` lists 10 packages the
nightly build did not compile (the `quinn` and `rand` 0.10 families, `chacha20`,
`foldhash`, `lru-slab`, `rustc-hash`), so the two oracles disagree there too.

The five extra fixture packages (`serde_derive`, `syn`, `quote`, `proc-macro2`,
`unicode-ident`) sit behind a `cfg(any())` dependency that never builds. The
adapter's missing license is the local root crate, which it does not enrich.
Raw Syft 1.34.2 output carries no Cargo licenses; the adapter adds them only from
checksum-verified registry archives in the local Cargo cache, so license accuracy
depends on that cache.

Parser-confusion fixtures (`fixtures/sbom/confusion/`) check that a crafted tree
cannot change the inventory without the adapter noticing:

| Case | Cargo `--locked` | Raw Syft 1.34.2 | Vettalon adapter |
|---|---|---|---|
| dependency in a comment | ok | matches | matches |
| package table inside a multi-line string | ok | matches | matches |
| stray CycloneDX file in the tree | ok | matches | matches |
| duplicate key in `Cargo.lock` | rejects | exit 0, empty inventory | refuses |
| duplicate key in `Cargo.toml` | rejects | lists the lock packages | refuses |
| unrelated nested project with its own lock | ok | merges 3 extra packages | refuses |
| stale lock (manifest dropped a dependency) | rejects | lists the stale package | **accepts (known limitation)** |

The stale-lock case is a known limitation: the adapter compares the BOM with the
lock graph and root identities, not with each manifest's dependency tables. Its
test is marked as an expected failure until that check exists. Run Cargo with
`--locked` in the release build to catch it.

Output remains CycloneDX 1.6, aligned with the minimum format version named in
BSI TR-03183-2 v2.1.0 (CycloneDX 1.6 or later). This document does not assess the
other fields of that guideline.

## Build or inspect a local trust pack

See [tool how-to](../scripts/trust/README.md) for Syft setup, public-tree staging,
SBOM generation, customer inventory, negative tests and data-flow probes. Local
fixtures and unsigned build records demonstrate local behavior only. Do not upload
customer BOMs, private raw findings, credentials or source to a public evidence wall.

[Data flow](DATA-FLOW.md) describes model/ranker/registry traffic.
[Best Practices self-assessment](TRUST-BEST-PRACTICES.md) lists evidence and gaps.
Report vulnerabilities according to [SECURITY.md](../SECURITY.md).

References: [Sigstore blob verification](https://docs.sigstore.dev/cosign/verifying/verify_blob/),
[GitHub attestation verification](https://cli.github.com/manual/gh_attestation_verify),
[CycloneDX specification](https://github.com/CycloneDX/specification/tree/1.6),
[Syft output formats](https://oss.anchore.com/docs/guides/sbom/formats/).
