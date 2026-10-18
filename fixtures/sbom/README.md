# Representative SBOM fixtures

Small pinned source inventories for the trust adapter, not vulnerability or
malware benchmarks. Rust source is self-authored; package/module metadata comes
from official registries through native package managers with build/install hooks
disabled. Python direct requirements and the pinned transitive constraint set are
separate. Go includes explicit indirect requirements and checksum metadata.

Verify each actual generated BOM against its source: direct and transitive
component name/version/purl, available license evidence and dependency relation.
Run `python3 fixtures/sbom/verify.py /path/to/private/trust-output` after the
commands in `scripts/trust/README.md`. The verifier expects Rust inventory plus
npm/Python/Go reconciled artifacts. Missing artifacts/relationships/licenses fail.

A successful fixture test covers these exact snapshots. It does not claim support
for every lockfile variant, optional feature, workspace, platform, malformed input,
installed artifact or package ecosystem. Customer BOMs and caches are private until
reviewed; public export includes only these self-contained fixture sources.

The `npm-negative-*` lock snapshots are negative controls copied byte-for-byte
from the private R14 workspace, local-file and git-file receipt inputs. They
exercise explicit unsupported outcomes in both private and public trust tests.
The git-file snapshot names a fixed disposable `/tmp` path as data; running the
tests does not fetch or execute that dependency.
