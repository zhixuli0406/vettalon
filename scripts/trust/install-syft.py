#!/usr/bin/env python3
"""Install one reviewed official Syft release after checking a pinned SHA256."""

import argparse
import hashlib
import io
from pathlib import Path
import platform
import tarfile
import urllib.request

VERSION = "1.34.2"
HASHES = {
    ("Darwin", "arm64"): (
        "darwin_arm64",
        "17285aa74e1d698def8babc2dcab0f1b284113b77de6f56cf0b1123861e71b9c",
    ),
    ("Darwin", "x86_64"): (
        "darwin_amd64",
        "af60a138ad4c87bb835eca0b713d52e4005435335a483a33e8ef074c68412635",
    ),
    ("Linux", "x86_64"): (
        "linux_amd64",
        "b62a3d4167f9a04bc190a5e654b05711737527ed47b616dc398e541f903c2d72",
    ),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    if args.destination.exists():
        parser.error("destination must not exist")
    key = platform.system(), platform.machine()
    if key not in HASHES:
        parser.error("unsupported host; install official Syft independently")
    suffix, expected = HASHES[key]
    url = f"https://github.com/anchore/syft/releases/download/v{VERSION}/syft_{VERSION}_{suffix}.tar.gz"
    data = urllib.request.urlopen(url, timeout=60).read(100_000_001)
    if len(data) > 100_000_000 or hashlib.sha256(data).hexdigest() != expected:
        parser.error("archive checksum/size mismatch")
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        member = archive.getmember("syft")
        if not member.isfile():
            parser.error("binary member is not a regular file")
        binary = archive.extractfile(member).read()
    args.destination.parent.mkdir(parents=True, exist_ok=True)
    with args.destination.open("xb") as stream:
        stream.write(binary)
    args.destination.chmod(0o755)
    print(f"installed Syft {VERSION}; archive sha256 {expected}")


if __name__ == "__main__":
    main()
