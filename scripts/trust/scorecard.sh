#!/usr/bin/env bash
# Read-only public repository assessment. No token is implicitly inherited.
set -euo pipefail
[[ $# == 2 ]] || { echo 'usage: scorecard.sh <owner/repo> <new-output.json>' >&2; exit 2; }
[[ "$1" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || exit 2
[[ ! -e "$2" ]] || { echo 'refusing output overwrite' >&2; exit 1; }
scorecard_bin=${SCORECARD_BIN:-scorecard}
command -v "$scorecard_bin" >/dev/null || { echo 'Scorecard missing; install a checksum-verified official release' >&2; exit 1; }
# If the operator supplies SCORECARD_READ_TOKEN, it must be a separate read-only
# token. Never reuse a publishing token; never print its value.
[[ -n "${SCORECARD_READ_TOKEN:-}" ]] || { echo 'SCORECARD_READ_TOKEN required (separate read-only token); no implicit credential reuse' >&2; exit 1; }
python3 - "$scorecard_bin" "$1" "$2" <<'PY_SCORECARD'
import os, subprocess, sys
binary, repo, output = sys.argv[1:]
env = {'PATH':os.environ['PATH'], 'HOME':os.environ.get('HOME', '/tmp'), 'GITHUB_AUTH_TOKEN':os.environ['SCORECARD_READ_TOKEN']}
try:
    result = subprocess.run([binary, '--repo=https://github.com/'+repo, '--format=json'], env=env, capture_output=True, timeout=180)
except subprocess.TimeoutExpired:
    raise SystemExit('Scorecard timed out after 180 seconds; no successful assessment emitted')
if result.returncode:
    sys.stderr.buffer.write(result.stderr)
    raise SystemExit(result.returncode)
import json
record = json.loads(result.stdout)
with open(output, 'x') as stream: json.dump(record, stream, indent=2)
PY_SCORECARD
