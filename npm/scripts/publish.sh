#!/usr/bin/env bash
set -euo pipefail
# Publish vettalon to npm. Usage: ./npm/scripts/publish.sh <version> [--dry-run]
# Prereqs: GitHub release artifacts in ./artifacts/, npm auth with @vettalon access.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NPM_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION="${1:?Usage: publish.sh <version> [--dry-run]}"
DRY_RUN="${2:-}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-./artifacts}"

declare -A PLATFORM_MAP=(
  [vettalon-darwin-arm64]=darwin-arm64
  [vettalon-darwin-x64]=darwin-x64
  [vettalon-linux-x64]=linux-x64
  [vettalon-linux-arm64]=linux-arm64
)

echo "=== vettalon npm publish v${VERSION} ==="
for dir in vettalon darwin-arm64 darwin-x64 linux-x64 linux-arm64; do
  pkg="${NPM_DIR}/${dir}/package.json"
  node -e "const fs=require('fs');const p=JSON.parse(fs.readFileSync('${pkg}','utf8'));p.version='${VERSION}';if(p.optionalDependencies)for(const k of Object.keys(p.optionalDependencies))p.optionalDependencies[k]='${VERSION}';fs.writeFileSync('${pkg}',JSON.stringify(p,null,2)+'\n');"
done

for artifact in "${!PLATFORM_MAP[@]}"; do
  tarball="${ARTIFACTS_DIR}/${artifact}.tar.gz"
  [ -f "$tarball" ] || { echo "  SKIP: ${tarball} not found"; continue; }
  bin_dir="${NPM_DIR}/${PLATFORM_MAP[$artifact]}/bin"
  mkdir -p "$bin_dir"
  # Release archives store the binary as ./vettalon; extract everything to a
  # scratch dir instead of naming the member, which depends on that prefix.
  unpack="$(mktemp -d)"
  tar xzf "$tarball" -C "$unpack"
  [ -f "$unpack/vettalon" ] || { echo "  ERROR: no vettalon binary in ${tarball}"; exit 1; }
  cp "$unpack/vettalon" "$bin_dir/vettalon"
  rm -rf "$unpack"
  chmod +x "${bin_dir}/vettalon"
done

already_published() { [ -z "${DRY_RUN}" ] || return 1; [ "$(npm view "$1@$2" version 2>/dev/null || true)" = "$2" ]; }
publish_pkg() {
  if already_published "$1" "$VERSION"; then echo "  SKIP: $1@$VERSION already on registry"; return 0; fi
  echo "  Publishing $1..."; npm publish "$2" --access public ${DRY_RUN}
}

for dir in darwin-arm64 darwin-x64 linux-x64 linux-arm64; do
  [ -f "${NPM_DIR}/${dir}/bin/vettalon" ] && publish_pkg "@vettalon/${dir}" "${NPM_DIR}/${dir}" || echo "  SKIP: ${dir} (no binary)"
done
publish_pkg "vettalon" "${NPM_DIR}/vettalon"
echo "=== Done === npm install -g vettalon"
