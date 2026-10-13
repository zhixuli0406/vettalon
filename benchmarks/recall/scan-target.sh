#!/usr/bin/env bash
# Scan one already-cloned repo at its (vulnerable) ref and report whether the
# known-vulnerable file was audited and flagged. Separates a ranking/coverage
# miss (file not audited) from a model miss (audited, not flagged).
#
#   scan-target.sh <vettalon-bin> <config.toml> <id> <repo_dir> <vuln_files_csv> [max_modules] [subdir]
set -u
BIN="$1"; CFG="$2"; ID="$3"; DIR="$4"; VULN="$5"; MAXM="${6:-12}"; SUB="${7:-}"
TARGET="$DIR${SUB:+/$SUB}"; OUT=$(mktemp -d)/$ID.json
echo "[$ID] HEAD=$(git -C "$DIR" rev-parse --short HEAD 2>/dev/null) target=$TARGET"
"$BIN" scan "$TARGET" --profile deep --config "$CFG" --max-modules "$MAXM" \
  --cross-check-top "$MAXM" --report "$OUT" --no-prior >/dev/null 2>&1
python3 - "$OUT" "$VULN" "$ID" <<'PY'
import sys, json, os
rep, vuln, rid = sys.argv[1], sys.argv[2], sys.argv[3]
if not os.path.exists(rep): print(f"[{rid}] NO REPORT"); sys.exit(0)
r = json.load(open(rep)); pats=[p.strip() for p in vuln.split(",")]
m=lambda path: any(p in path or p.split("/")[-1] in path for p in pats)
aud=[c for c in r.get("coverage",[]) if any(m(p) for p in c.get("reviewed_paths",[]))]
hits=[f for f in r.get("findings",[]) if f.get("source_engine")=="ai_audit" and m(f.get("file",""))]
for f in hits:
    v=";".join(f"{x['model']}:{x['verdict']}" for x in f.get("verification",[]))
    print(f"[{rid}] {f['severity']:>8} {f['status']:>11} {f['file']}:{f.get('line')} by[{','.join(f.get('found_by',[]))}] [{v}] {f['rule_id']}")
print(f"[{rid}] vuln-file audited: {'yes' if aud else 'NO'} | recall: {'FOUND' if hits else 'MISS'}")
PY
