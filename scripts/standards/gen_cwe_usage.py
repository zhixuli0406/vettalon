#!/usr/bin/env python3
"""Generate crates/vettalon/src/cwe_usage.json from a local MITRE CWE XML.

Offline by design: pass the catalogue you downloaded yourself, e.g.
    curl -LO https://cwe.mitre.org/data/xml/cwec_v4.20.xml.zip && unzip it
    python3 -I scripts/standards/gen_cwe_usage.py cwec_v4.20.xml \
        crates/vettalon/src/cwe_kb.json crates/vettalon/src/cwe_usage.json

What it writes (and nothing else):
- `entries`: full detail (name, abstraction, status, mapping usage) for the
  ids vettalon itself emits or may be handed: every id in cwe_kb.json, the
  2025 CWE Top 25, the CWE ids hard-coded in the scanners, every Pillar, and
  the AI-related ids the guidance calls out.
- `restricted`: every other id whose Mapping_Notes usage is not "Allowed"
  (categories, views, pillars, deprecated entries ...), as [abstraction,
  usage] only, so a model-supplied Category/View id is still flagged.
- `allowed`: the remaining (Allowed) ids as bare numbers, so an id absent
  from all three lists is known not to exist in this catalogue version.
- `suggest`: for each Discouraged/Prohibited weakness (not Category/View),
  the Allowed(-with-Review) cwe_kb.json entries that MITRE's Mapping_Notes
  suggest or that are descendants (ChildOf, View 1000), closest first.
  vettalon only swaps
  an id for one of these when the finding's own category maps to it;
  otherwise it just flags.
"""

import json
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict, deque

NS = {"c": "http://cwe.mitre.org/cwe-7"}

TOP25_2025 = [79, 89, 352, 862, 787, 22, 416, 125, 78, 94, 120, 434, 476, 121,
              502, 122, 863, 20, 284, 200, 306, 918, 77, 639, 770]
# Hard-coded by scanners (gitleaks) and AI-related ids named by the CWE
# mapping guidance and the CVE Program AI notes.
EXTRA = [798, 1426, 1427, 1434, 1039]


def usage_key(text: str | None) -> str:
    return (text or "").strip().lower().replace(" ", "-") or "unknown"


def main(xml_path: str, kb_path: str, out_path: str) -> None:
    root = ET.parse(xml_path).getroot()
    version = root.get("Version")
    date = root.get("Date")
    info = {}
    children = defaultdict(set)  # parent -> children (ChildOf, view 1000)
    members = defaultdict(set)  # category -> members
    mitre_suggest = defaultdict(list)

    def notes(el: ET.Element, n: int) -> str:
        mn = el.find("c:Mapping_Notes", NS)
        if mn is None:
            return "unknown"
        for s in mn.findall("c:Suggestions/c:Suggestion", NS):
            mitre_suggest[n].append(int(s.get("CWE_ID")))
        return usage_key(mn.findtext("c:Usage", default="", namespaces=NS))

    for w in root.findall("c:Weaknesses/c:Weakness", NS):
        n = int(w.get("ID"))
        info[n] = {
            "name": w.get("Name"),
            "abstraction": w.get("Abstraction"),
            "status": w.get("Status"),
            "usage": notes(w, n),
        }
        for rel in w.findall("c:Related_Weaknesses/c:Related_Weakness", NS):
            if rel.get("Nature") == "ChildOf" and rel.get("View_ID") == "1000":
                children[int(rel.get("CWE_ID"))].add(n)
    for c in root.findall("c:Categories/c:Category", NS):
        n = int(c.get("ID"))
        info[n] = {
            "name": c.get("Name"),
            "abstraction": "Category",
            "status": c.get("Status"),
            "usage": notes(c, n),
        }
        for m in c.findall("c:Relationships/c:Has_Member", NS):
            members[n].add(int(m.get("CWE_ID")))
    for v in root.findall("c:Views/c:View", NS):
        n = int(v.get("ID"))
        info[n] = {
            "name": v.get("Name"),
            "abstraction": "View",
            "status": v.get("Status"),
            "usage": notes(v, n),
        }

    kb_ids = [int(e["id"].split("-")[1]) for e in json.load(open(kb_path, encoding="utf-8"))]
    kb_set = set(kb_ids)
    pillars = [n for n, i in info.items() if i["abstraction"] == "Pillar"]
    emitted = sorted(set(kb_ids) | set(TOP25_2025) | set(EXTRA) | set(pillars))
    missing = [n for n in emitted if n not in info]
    if missing:
        sys.exit(f"ids not in the catalogue: {missing}")

    def kb_descendants(n: int) -> list[int]:
        out, seen, q = [], {n}, deque([(n, 0)])
        while q:
            cur, depth = q.popleft()
            nxt = children.get(cur, set()) | members.get(cur, set())
            for c in sorted(nxt):
                if c in seen:
                    continue
                seen.add(c)
                if c in kb_set:
                    out.append((depth + 1, c))
                if info.get(c, {}).get("abstraction") != "View":
                    q.append((c, depth + 1))
        return [c for _, c in sorted(out)]

    suggest = {}
    for n, i in sorted(info.items()):
        # Views and Categories are navigation groupings: their members are
        # not "more specific variants" of one weakness, so no suggestion.
        if i["usage"] not in ("discouraged", "prohibited") or i["abstraction"] in ("View", "Category"):
            continue
        ids = []
        for c in mitre_suggest.get(n, []) + kb_descendants(n):
            usable = info.get(c, {}).get("usage") in ("allowed", "allowed-with-review")
            if c != n and c in kb_set and usable and c not in ids:
                ids.append(c)
        if ids:
            suggest[f"CWE-{n}"] = [f"CWE-{c}" for c in ids]

    entries = [
        {"id": f"CWE-{n}", **{k: info[n][k] for k in ("name", "abstraction", "status", "usage")}}
        for n in emitted
    ]
    restricted = {
        f"CWE-{n}": [i["abstraction"], i["usage"]]
        for n, i in sorted(info.items())
        if n not in emitted and i["usage"] != "allowed"
    }
    allowed = [n for n, i in sorted(info.items()) if n not in emitted and i["usage"] == "allowed"]
    out = {
        "source": f"MITRE CWE List {version} (cwec_v{version}.xml, https://cwe.mitre.org/data/xml/cwec_v{version}.xml.zip)",
        "cwe_version": version,
        "catalog_date": date,
        "generated": "2026-10-20",
        "generator": "scripts/standards/gen_cwe_usage.py",
        "entries": entries,
        "restricted": restricted,
        "allowed": allowed,
        "suggest": suggest,
    }
    # One record per line: reviewable diffs, small file.
    head = {k: out[k] for k in ("source", "cwe_version", "catalog_date", "generated", "generator")}
    lines = ["{"]
    for k, v in head.items():
        lines.append(f"  {json.dumps(k)}: {json.dumps(v, ensure_ascii=False)},")
    lines.append('  "entries": [')
    lines.append(",\n".join("    " + json.dumps(e, ensure_ascii=False) for e in entries))
    lines.append("  ],")
    lines.append('  "restricted": {')
    lines.append(",\n".join(f"    {json.dumps(k)}: {json.dumps(v)}" for k, v in restricted.items()))
    lines.append("  },")
    lines.append(f'  "allowed": {json.dumps(allowed)},')
    lines.append('  "suggest": {')
    lines.append(",\n".join(f"    {json.dumps(k)}: {json.dumps(v)}" for k, v in suggest.items()))
    lines.append("  }")
    lines.append("}")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"entries={len(entries)} restricted={len(restricted)} suggest={len(suggest)}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(*sys.argv[1:])
