#!/usr/bin/env python3
"""Create an explicitly synthetic, pinned CLI input report for fixture review.

This report is test input, not scanner output or evidence of a vulnerability.
"""
import hashlib
import json
import pathlib
import subprocess
import sys

repo = pathlib.Path(sys.argv[1]).resolve()
output = pathlib.Path(sys.argv[2])
call = json.loads((repo / 'target.json').read_text())
source = (repo / call['file']).read_bytes()
cwe = {'cjs-command': 78, 'esm-path': 22, 'ts-sqlite': 89, 'pg-reach': 89,
       'esm-ssrf': 918, 'cjs-ssrf-get': 918}[repo.name]
try:
    commit = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
except subprocess.CalledProcessError:
    commit = None
report = {
    'schema_version': 3,
    'repo': str(repo),
    'repo_commit': commit,
    'started_at': '2026-11-12T00:00:00Z',
    'profile': {'mode': 'quick'},
    'engines_run': [],
    'engines_missing': [],
    'findings': [{
        'id': 'node-e2e', 'source_engine': 'fixture', 'kind': 'other',
        'severity': 'high', 'severity_basis': 'scanner_rule',
        'title': 'Synthetic Node CLI fixture', 'file': call['file'], 'line': 1,
        'snippet': source.decode(), 'rule_id': 'node-e2e', 'evidence': [],
        'status': 'candidate', 'root_fingerprint': 'fixture/node-e2e',
        'file_hash': hashlib.sha256(source).hexdigest(), 'cwe': f'CWE-{cwe}',
    }],
    'summary': {
        'total_findings': 1,
        'by_severity': {'critical': 0, 'high': 1, 'medium': 0, 'low': 0, 'info': 0},
        'engines_run_count': 0, 'engines_missing_count': 0,
    },
}
with output.open('x') as handle:
    json.dump(report, handle, indent=2)
