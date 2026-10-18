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
