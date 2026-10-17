#!/usr/bin/env bash
# Verify identities, source and digest. Never signs, publishes or trusts JSON alone.
set -euo pipefail
[[ $# == 3 ]] || { echo 'usage: verify-release.sh <archive> <vX.Y.Z> <full-source-sha>' >&2; exit 2; }
asset=$1; tag=$2; source_sha=$3
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ && "$source_sha" =~ ^[0-9a-f]{40}$ ]] || exit 2
for tool in cosign gh; do command -v "$tool" >/dev/null || { echo "missing required verifier: $tool" >&2; exit 1; }; done
script_dir=$(cd "$(dirname "$0")" && pwd)
"${PYTHON:-python3}" "$script_dir/trust.py" verify-assets "$asset"
"${PYTHON:-python3}" - "$asset.build-record.json" "$source_sha" <<'PY_RECORD'
import json, sys
record = json.load(open(sys.argv[1]))
if record['source']['commit'] != sys.argv[2] or record['source']['dirty'] is not False:
    raise SystemExit('wrong expected source or dirty build-record; refusing release acceptance')
PY_RECORD
identity="https://github.com/zhixuli0406/vettalon/.github/workflows/release.yml@refs/tags/$tag"
cosign verify-blob --bundle "$asset.sigstore.json" \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com "$asset"
gh attestation verify "$asset" --repo zhixuli0406/vettalon \
  --cert-identity "$identity" --cert-oidc-issuer https://token.actions.githubusercontent.com \
  --signer-workflow zhixuli0406/vettalon/.github/workflows/release.yml \
  --source-ref "refs/tags/$tag" --source-digest "$source_sha" \
  --deny-self-hosted-runners --format json

# The BOM must itself be attested, so editing its license/graph cannot be hidden
# merely by preserving the archive digest property.
gh attestation verify "$asset.cdx.json" --repo zhixuli0406/vettalon \
  --cert-identity "$identity" --cert-oidc-issuer https://token.actions.githubusercontent.com \
  --signer-workflow zhixuli0406/vettalon/.github/workflows/release.yml \
  --source-ref "refs/tags/$tag" --source-digest "$source_sha" \
  --deny-self-hosted-runners --format json
