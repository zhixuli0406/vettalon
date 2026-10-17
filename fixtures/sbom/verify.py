#!/usr/bin/env python3
"""Check representative direct/transitive inventories against pinned fixture sources."""

import json
from pathlib import Path
import sys

SAMPLES = [
    (
        "rust",
        "customer-rust.cdx.json",
        ("serde_json", "1.0.140", "pkg:cargo/serde_json@1.0.140"),
        ("memchr", "2.8.3", "pkg:cargo/memchr@2.8.3"),
    ),
    (
        "npm",
        "customer-npm-reconciled.cdx.json",
        ("is-odd", "3.0.1", "pkg:npm/is-odd@3.0.1"),
        ("is-number", "6.0.0", "pkg:npm/is-number@6.0.0"),
    ),
    (
        "python",
        "customer-python-reconciled.cdx.json",
        ("requests", "2.32.3", "pkg:pypi/requests@2.32.3"),
        ("idna", "3.10", "pkg:pypi/idna@3.10"),
    ),
    (
        "go",
        "customer-go-reconciled.cdx.json",
        (
            "github.com/sirupsen/logrus",
            "v1.9.3",
            "pkg:golang/github.com/sirupsen/logrus@v1.9.3",
        ),
        (
            "golang.org/x/sys",
            "v0.0.0-20220715151400-c0bba94af5f8",
            "pkg:golang/golang.org/x/sys@v0.0.0-20220715151400-c0bba94af5f8",
        ),
    ),
]


def main():
    root = Path(sys.argv[1])
    rows = []
    for ecosystem, filename, direct, transitive in SAMPLES:
        bom = json.loads((root / filename).read_text())
        chosen = []
        for name, version, purl in (direct, transitive):
            component = next(c for c in bom["components"] if c.get("purl") == purl)
            assert (component["name"], component["version"]) == (name, version)
            assert component.get("licenses"), (
                ecosystem,
                name,
                "missing license evidence",
            )
            chosen.append(component)
        assert any(
            edge["ref"] == chosen[0]["bom-ref"]
            and chosen[1]["bom-ref"] in edge.get("dependsOn", [])
            for edge in bom.get("dependencies", [])
        ), (ecosystem, "missing direct to transitive edge")
        for component in chosen:
            assert any(
                p["name"] == "vettalon:dependency:role"
                for p in component.get("properties", [])
            )
        rows.append(
            {
                "ecosystem": ecosystem,
                "direct": direct,
                "transitive": transitive,
                "license_evidence": "present; source inventory, not legal advice",
                "relation": "native source graph observed",
            }
        )
    print(
        json.dumps(
            {
                "status": "passed",
                "samples": rows,
                "scope": "four exact fixture snapshots only",
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
