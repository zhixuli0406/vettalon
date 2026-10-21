#!/usr/bin/env python3
"""Gather the corresponding source of a published container image.

For every platform of an image (pulled by digest), read the package database
out of the image without running it, then download the exact sources:

- egress (Alpine): the aports directory at the commit each package was built
  from (`c:` in /lib/apk/db/installed) plus every file its APKBUILD lists,
  checked against the APKBUILD's sha512sums. Upstream URL first, then the
  Alpine distfiles mirror.
- agents-base (Debian + codex): every Debian source package
  (`apt-get source` equivalent, exact versions from snapshot.debian.org,
  fetched from deb.debian.org when still there, checked against snapshot's
  SHA-1 and the .dsc checksums); the codex source tree at the release tag
  (bubblewrap, the voice build scripts); and the upstream archives codex's
  voice/sources.json lists, checked against its SHA-256.

Anything that cannot be fetched and checked fails the run: an image is not
published without its source. Writes <out>/SOURCES.json and one directory
per source kind. Standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

USER_AGENT = "vettalon-image-sources/1 (+https://github.com/zhixuli0406/vettalon)"
PLATFORMS = ("linux/amd64", "linux/arm64")
# codex npm platform package directory and vendor triple per platform.
CODEX_PLATFORM = {
    "linux/amd64": ("codex-linux-x64", "x86_64-unknown-linux-musl"),
    "linux/arm64": ("codex-linux-arm64", "aarch64-unknown-linux-musl"),
}
CODEX_NODE_MODULES = "/usr/local/lib/node_modules/@openai/codex"
APORTS = "https://gitlab.alpinelinux.org/alpine/aports/-/archive/{c}/aports-{c}.tar.gz?path={repo}/{origin}"
DISTFILES = "https://distfiles.alpinelinux.org/distfiles/v{branch}/{name}"
SNAPSHOT_MR = "https://snapshot.debian.org/mr/package/{src}/{ver}/srcfiles?fileinfo=1"
SNAPSHOT_FILE = "https://snapshot.debian.org/file/{sha1}"
DEB_MIRROR = {"debian": "https://deb.debian.org/debian", "debian-security": "https://deb.debian.org/debian-security"}
CODEX_ARCHIVE = "https://github.com/openai/codex/archive/{ref}.tar.gz"


class SourceError(RuntimeError):
    pass


# ---------------------------------------------------------------- parsing

def parse_apk_installed(text: str) -> list[dict]:
    """Packages from /lib/apk/db/installed: name, version, origin, commit, license."""
    out = []
    for stanza in re.split(r"\n\s*\n", text.strip()):
        f = {}
        for line in stanza.splitlines():
            if len(line) > 2 and line[1] == ":" and line[0] in "PVocL":
                f.setdefault(line[0], line[2:])
        if "P" in f:
            if not f.get("o") or not f.get("c"):
                raise SourceError(f"apk package {f['P']} has no origin/commit")
            out.append({"name": f["P"], "version": f.get("V", ""), "origin": f["o"],
                        "commit": f["c"], "license": f.get("L", "")})
    return out


def strip_binnmu(version: str) -> str:
    return re.sub(r"\+b\d+$", "", version)


def parse_dpkg_status(text: str) -> list[dict]:
    """Installed packages from /var/lib/dpkg/status with their source package."""
    out = []
    for stanza in re.split(r"\n\s*\n", text.strip()):
        f = {}
        for line in stanza.splitlines():
            m = re.match(r"^([A-Za-z-]+): ?(.*)$", line)
            if m:
                f[m.group(1)] = m.group(2)
        if not f.get("Package") or not f.get("Status", "").endswith(" installed"):
            continue
        src, src_ver = f["Package"], strip_binnmu(f["Version"])
        if f.get("Source"):
            m = re.match(r"^(\S+)(?: \((\S+)\))?$", f["Source"])
            if not m:
                raise SourceError(f"bad Source field {f['Source']!r}")
            src = m.group(1)
            if m.group(2):
                src_ver = m.group(2)
        out.append({"name": f["Package"], "version": f["Version"], "source": src, "source_version": src_ver})
    return out


def parse_source_entry(entry: str) -> tuple[str, str | None]:
    """An APKBUILD source= entry -> (file name, url or None for a local file)."""
    if "::" in entry:
        name, url = entry.split("::", 1)
        return name, url
    if "://" in entry:
        return urllib.parse.urlparse(entry).path.rsplit("/", 1)[-1], entry
    return entry, None


def parse_sums(text: str) -> dict[str, str]:
    sums = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2:
            sums[parts[1]] = parts[0].lower()
    return sums


def parse_dsc_sha256(text: str) -> dict[str, str]:
    """Checksums-Sha256 of a .dsc: file name -> sha256."""
    out, inside = {}, False
    for line in text.splitlines():
        if line.startswith("Checksums-Sha256:"):
            inside = True
            continue
        if inside:
            if not line.startswith(" "):
                break
            parts = line.split()
            if len(parts) == 3:
                out[parts[2]] = parts[0].lower()
    return out


def archive_name(name: str, version: str, url: str) -> str:
    """`<name>-<version><ext>` for an upstream archive URL."""
    path = urllib.parse.urlparse(url).path
    for ext in (".tar.gz", ".tar.xz", ".tar.bz2", ".tgz", ".zip"):
        if path.endswith(ext):
            break
    else:
        ext = ".tar.gz" if "/tar.gz/" in path else ""
    return f"{name}-{version}{ext}"


def safe_name(name: str) -> str:
    if not name or "/" in name or name in (".", "..") or "\x00" in name:
        raise SourceError(f"unsafe file name {name!r}")
    return name


# ---------------------------------------------------------------- I/O

def digest(path: Path, algo: str) -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url: str, dest: Path, tries: int = 5) -> None:
    if not url.startswith("https://"):
        raise SourceError(f"refusing non-https source {url}")
    last = None
    for attempt in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=300) as r, open(dest, "wb") as fh:
                shutil.copyfileobj(r, fh, 1 << 20)
            return
        except urllib.error.HTTPError as e:
            last = e
            if e.code in (404, 410):
                break
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last = e
        time.sleep(min(60, 5 * 2 ** attempt))
    dest.unlink(missing_ok=True)
    raise SourceError(f"GET {url}: {last}")


def fetch_checked(urls: list[str], dest: Path, algo: str, want: str) -> str:
    """Download from the first URL whose content matches; returns that URL."""
    errors = []
    for url in urls:
        try:
            download(url, dest)
        except SourceError as e:
            errors.append(str(e))
            continue
        got = digest(dest, algo)
        if got == want:
            return url
        errors.append(f"{url}: {algo} {got} != {want}")
        dest.unlink(missing_ok=True)
    raise SourceError(f"{dest.name}: no checked copy ({'; '.join(errors)})")


def buildx(dockerfile: str, context: Path, dest: Path, platform: str | None = None) -> None:
    """Run a BuildKit build whose result is files in `dest` (no image is
    stored, nothing touches the local image store)."""
    (context / "Dockerfile").write_text(dockerfile)
    cmd = ["docker", "buildx", "build", "--quiet", "--output", f"type=local,dest={dest}"]
    if platform:
        cmd += ["--platform", platform]
    subprocess.run([*cmd, str(context)], check=True, stdout=subprocess.DEVNULL)


def extract(image: str, platform: str, paths: list[str], dest: Path) -> None:
    """Copy files out of one platform of an image without running it."""
    lines = [f"FROM {image} AS src", "FROM scratch"]
    lines += [f"COPY --from=src {p} {p}" for p in paths]
    with tempfile.TemporaryDirectory(prefix="extract-") as ctx:
        buildx("\n".join(lines) + "\n", Path(ctx), dest, platform)


# ---------------------------------------------------------------- Alpine

APKBUILD_EVAL = r'''
cd /tmp/aport || exit 1
for CARCH in x86_64 aarch64; do
  export CARCH
  ( . ./APKBUILD >/dev/null || exit 1
    printf '%s\n' "@@source"; for s in $source; do printf '%s\n' "$s"; done
    printf '%s\n' "@@sums"; printf '%s\n' "$sha512sums" ) || exit 1
done
'''


def apkbuild_sources(image: str, aport: Path) -> tuple[dict[str, str | None], dict[str, str]]:
    """Evaluate an APKBUILD with the image's own busybox sh, offline, the
    way abuild reads it (sourced by /bin/sh)."""
    with tempfile.TemporaryDirectory(prefix="apkbuild-") as tmp:
        ctx, dest = Path(tmp) / "ctx", Path(tmp) / "out"
        shutil.copytree(aport, ctx / "aport")
        (ctx / "eval.sh").write_text(APKBUILD_EVAL)
        buildx("\n".join([
            f"FROM {image}",
            "COPY aport /tmp/aport",
            "COPY eval.sh /tmp/eval.sh",
            "RUN --network=none sh /tmp/eval.sh > /tmp/eval.txt",
            "FROM scratch",
            "COPY --from=0 /tmp/eval.txt /eval.txt",
        ]) + "\n", ctx, dest)
        text = (dest / "eval.txt").read_text()
    sources, sums, mode = {}, {}, None
    for line in text.splitlines():
        if line in ("@@source", "@@sums"):
            mode = line
            continue
        if not line.strip():
            continue
        if mode == "@@source":
            name, url = parse_source_entry(line.strip())
            sources[safe_name(name)] = url
        elif mode == "@@sums":
            sums.update(parse_sums(line))
    return check_apkbuild(sources, sums, aport.name)


def check_apkbuild(sources: dict, sums: dict, origin: str) -> tuple[dict, dict]:
    """Every source needs a checksum and every checksum a source; an APKBUILD
    that lists checksums but yields no sources did not evaluate."""
    if set(sums) != set(sources):
        raise SourceError(f"{origin}: source= and sha512sums disagree: "
                          f"{sorted(set(sources) ^ set(sums))}")
    return sources, sums


def collect_alpine(image: str, work: Path, out: Path) -> list[dict]:
    pkgs, branch = {}, None
    for platform in PLATFORMS:
        d = work / platform.replace("/", "-")
        extract(image, platform, ["/lib/apk/db/installed", "/etc/alpine-release"], d)
        for p in parse_apk_installed((d / "lib/apk/db/installed").read_text()):
            pkgs.setdefault((p["origin"], p["commit"]), []).append(p)
        rel = (d / "etc/alpine-release").read_text().strip()
        b = ".".join(rel.split(".")[:2])
        if branch and branch != b:
            raise SourceError(f"platforms disagree on the Alpine release: {branch} vs {b}")
        branch = b
    components = []
    for (origin, commit), binaries in sorted(pkgs.items()):
        aport, misses = None, []
        for repo in ("main", "community"):
            tgz = work / f"{origin}-{commit}-{repo}.tar.gz"
            try:
                download(APORTS.format(c=commit, repo=repo, origin=origin), tgz)
            except SourceError as e:
                misses.append(str(e))
                continue
            unpack = work / f"aport-{origin}-{commit}-{repo}"
            with tarfile.open(tgz) as t:
                t.extractall(unpack, filter="data")
            found = list(unpack.glob(f"*/{repo}/{origin}/APKBUILD"))
            if found:
                aport = found[0].parent
                break
        if aport is None:
            raise SourceError(f"aport {origin} not found at {commit}: {'; '.join(misses)}")
        version = sorted({b["version"] for b in binaries})
        target = out / "alpine" / f"{origin}-{version[0]}-{commit[:12]}"
        shutil.copytree(aport, target)
        sources, sums = apkbuild_sources(image, aport)
        files = []
        for name, url in sorted(sources.items()):
            want = sums.get(name)
            if not want:
                raise SourceError(f"{origin}: no sha512 for {name}")
            path = target / name
            if url is None:
                if digest(path, "sha512") != want:
                    raise SourceError(f"{origin}: local file {name} does not match its sha512")
                used = f"aports@{commit}"
            else:
                used = fetch_checked([url, DISTFILES.format(branch=branch, name=name)], path, "sha512", want)
            files.append({"name": name, "sha512": want, "from": used})
        components.append({
            "kind": "alpine", "origin": origin, "aports_commit": commit, "versions": version,
            "binary_packages": sorted({b["name"] for b in binaries}),
            "licenses": sorted({b["license"] for b in binaries}),
            "dir": str(target.relative_to(out)), "files": files,
        })
    return components


# ---------------------------------------------------------------- Debian

def debian_source(src: str, ver: str, out: Path) -> dict:
    meta_path = out / ".meta.json"
    download(SNAPSHOT_MR.format(src=urllib.parse.quote(src), ver=urllib.parse.quote(ver)), meta_path)
    info = json.loads(meta_path.read_text())["fileinfo"]
    meta_path.unlink()
    files, by_name = [], {}
    for sha1, seen in sorted(info.items()):
        names = {s["name"] for s in seen}
        if len(names) != 1:
            raise SourceError(f"{src} {ver}: one hash, several names {names}")
        name = safe_name(names.pop())
        mirrors = [f"{DEB_MIRROR[s['archive_name']]}{s['path']}/{name}"
                   for s in seen if s["archive_name"] in DEB_MIRROR]
        used = fetch_checked(sorted(set(mirrors)) + [SNAPSHOT_FILE.format(sha1=sha1)],
                             out / name, "sha1", sha1)
        by_name[name] = out / name
        files.append({"name": name, "sha1": sha1, "from": used})
    dscs = [n for n in by_name if n.endswith(".dsc")]
    if len(dscs) != 1:
        raise SourceError(f"{src} {ver}: expected one .dsc, got {dscs}")
    listed = parse_dsc_sha256(by_name[dscs[0]].read_text(errors="replace"))
    if not listed:
        raise SourceError(f"{src} {ver}: .dsc lists no files")
    for name, want in listed.items():
        if name not in by_name or digest(by_name[name], "sha256") != want:
            raise SourceError(f"{src} {ver}: {name} missing or does not match the .dsc")
    return {"kind": "debian", "source": src, "version": ver, "files": files}


def collect_agents_base(image: str, work: Path, out: Path) -> list[dict]:
    srcs, codex_meta = set(), {}
    for platform in PLATFORMS:
        d = work / platform.replace("/", "-")
        pkg_dir, triple = CODEX_PLATFORM[platform]
        vendor = f"{CODEX_NODE_MODULES}/node_modules/@openai/{pkg_dir}/vendor/{triple}"
        extract(image, platform, [
            "/var/lib/dpkg/status",
            f"{vendor}/codex-package.json",
            f"{vendor}/codex-resources/voice/sources.json",
            f"{vendor}/codex-resources/voice/manifest.json",
        ], d)
        for p in parse_dpkg_status((d / "var/lib/dpkg/status").read_text()):
            srcs.add((p["source"], p["source_version"]))
        v = d / vendor.lstrip("/")
        codex_meta[platform] = {
            "version": json.loads((v / "codex-package.json").read_text())["version"],
            "sources": json.loads((v / "codex-resources/voice/sources.json").read_text())["sources"],
            "build_commit": json.loads((v / "codex-resources/voice/manifest.json").read_text())["buildCommit"],
        }
    components = []
    for src, ver in sorted(srcs):
        target = out / "debian" / f"{src}_{ver.replace(':', '%3a')}"
        target.mkdir(parents=True)
        components.append({**debian_source(src, ver, target), "dir": str(target.relative_to(out))})
    components.extend(collect_codex(codex_meta, out))
    return components


def collect_codex(meta: dict, out: Path) -> list[dict]:
    versions = {m["version"] for m in meta.values()}
    commits = {m["build_commit"] for m in meta.values()}
    if len(versions) != 1 or len(commits) != 1:
        raise SourceError(f"codex platforms disagree: {versions} {commits}")
    version, commit = versions.pop(), commits.pop()
    target = out / "codex"
    target.mkdir(parents=True)
    # The codex tree at the commit the native parts were built from:
    # bubblewrap (codex-rs/vendor/bubblewrap), the voice build scripts
    # (third_party/voice) and the zsh patch.
    tree = target / f"codex-{commit}.tar.gz"
    download(CODEX_ARCHIVE.format(ref=commit), tree)
    files = [{"name": tree.name, "sha256": digest(tree, "sha256"),
              "from": CODEX_ARCHIVE.format(ref=commit)}]
    seen = {}
    for m in meta.values():
        for s in m["sources"]:
            seen[(s["name"], s["version"], s["url"], s["sha256"])] = s
    for (name, ver, url, sha), s in sorted(seen.items()):
        fname = safe_name(archive_name(name, ver, url))
        used = fetch_checked([url], target / fname, "sha256", sha.lower())
        files.append({"name": fname, "sha256": sha.lower(), "from": used, "component": name,
                      "version": ver, "role": s.get("role")})
    return [{"kind": "codex", "version": version, "build_commit": commit, "dir": "codex", "files": files}]


# ---------------------------------------------------------------- main

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--image", required=True, help="image by digest: repo@sha256:...")
    ap.add_argument("--kind", required=True, choices=["egress", "agents-base"])
    ap.add_argument("--out", required=True, type=Path)
    a = ap.parse_args(argv)
    if not re.fullmatch(r"[a-z0-9./_-]+@sha256:[0-9a-f]{64}", a.image):
        raise SystemExit("--image must be pinned by digest")
    if a.out.exists() and any(a.out.iterdir()):
        raise SystemExit(f"{a.out} is not empty")
    a.out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="image-sources-") as tmp:
        work = Path(tmp)
        try:
            if a.kind == "egress":
                components = collect_alpine(a.image, work, a.out)
            else:
                components = collect_agents_base(a.image, work, a.out)
        except (SourceError, subprocess.CalledProcessError, OSError, KeyError, ValueError) as e:
            print(f"[sources] FAILED: {e}", file=sys.stderr)
            return 1
    manifest = {
        "schema": 1,
        "image": a.image,
        "platforms": list(PLATFORMS),
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "components": components,
    }
    (a.out / "SOURCES.json").write_text(json.dumps(manifest, indent=1) + "\n")
    print(f"[sources] {len(components)} components for {a.image}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
