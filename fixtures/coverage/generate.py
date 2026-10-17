#!/usr/bin/env python3
"""Bounded self-built coverage cases using a loopback mock model; never customer code."""
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time

CASES = ('complete', 'module-cap', 'truncation', 'utf8-truncation', 'parse-failure',
         'read-failure', 'time-budget', 'engine-error', 'empty-content', 'candidate-cap')

def sanitize_missing_reason(reason):
    """Preserve consumer classification without publishing environment details."""
    for classification in ('not applicable', 'not installed'):
        if reason.startswith(classification):
            return f'{classification}: fixture environment; raw diagnostics not published.'
    return 'Fixture-environment engine unavailable; raw diagnostics not published.'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    binary, output = args.binary.resolve(strict=True), args.output.resolve()
    if output.exists(): parser.error('output must not already exist')
    output.mkdir(parents=True)
    observations = []
    with tempfile.TemporaryDirectory(prefix='vettalon-public-fixture-') as temp:
        root = Path(temp)
        for case in CASES:
            calls = []
            class Handler(BaseHTTPRequestHandler):
                def do_POST(self):
                    length = int(self.headers.get('Content-Length', '0'))
                    if length > 2_000_000: self.send_error(413); return
                    self.rfile.read(length)
                    calls.append(1)
                    if case == 'engine-error': self.send_error(503); return
                    if case == 'time-budget': time.sleep(1.2)
                    content = 'not-json' if case == 'parse-failure' else '[]'
                    if case == 'candidate-cap':
                        content = json.dumps([dict(kind=f'synthetic_{i}', severity='high', title='Synthetic candidate',
                            file='a/util.py', line=1, reasoning='Self-built fixture, not a vulnerability claim',
                            threat_model=dict(principal='fixture', input='fixture', control='fixture', boundary='fixture', affected='fixture', result='fixture'),
                            trace=[dict(kind='entrypoint', file='a/util.py', line=1, scope='demo', description='fixture'),
                                   dict(kind='sink', file='a/util.py', line=1, scope='demo', description='fixture')], conditions=[])
                            for i in range(10)])
                    payload = json.dumps({'choices':[{'message':{'content':content}, 'finish_reason':'stop'}]}).encode()
                    self.send_response(200); self.send_header('Content-Type','application/json')
                    self.send_header('Content-Length',str(len(payload))); self.end_headers()
                    try: self.wfile.write(payload)
                    except (BrokenPipeError, ConnectionResetError): pass
                def log_message(self, *args): pass
            server = HTTPServer(('127.0.0.1', 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            try:
                scope = root/case; (scope/'a').mkdir(parents=True)
                source = b'def demo(value):\n    return value\n'
                if case == 'truncation': source += b'#'*(48*1024)
                if case == 'utf8-truncation': source += ('#界'*20000).encode()
                if case == 'read-failure': source = b'\xff\xfe'
                if case == 'empty-content': source = b''
                (scope/'a'/'util.py').write_bytes(source)
                if case in ('module-cap','time-budget'):
                    (scope/'b').mkdir(); (scope/'b'/'util.py').write_text('def helper():\n    return 1\n')
                roster = root/f'{case}.toml'
                roster.write_text(f'[[model]]\nid="public-mock"\nbackend="openai"\nfamily="fixture"\nmodel="fixture"\nroles=["finder"]\nbase_url="http://127.0.0.1:{server.server_port}/v1"\ntimeout_secs=5\n')
                raw = root/f'{case}.json'
                command = [str(binary),'scan',str(scope),'--profile','deep','--config',str(roster),'--max-modules',
                           '1' if case == 'module-cap' else '2','--fail-on','none','--no-prior','--report',str(raw)]
                if case == 'time-budget': command += ['--time-budget','1']
                env = dict(os.environ, VETTALON_HOME=str(root/'home'), VETTALON_LANG='en')
                result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=30)
                if result.returncode not in (0,1) or not raw.is_file(): raise RuntimeError(f'{case}: CLI failed ({result.returncode})')
                report = json.loads(raw.read_text())
                # Public artifacts contain only self-built data and stable scope names.
                # Environment diagnostics are deliberately redacted, not relabelled success.
                report['repo'] = f'synthetic-coverage-{case}'
                for run in report['engines_run']:
                    if run['parse_error'] is not None: run['parse_error'] = 'Fixture environment engine error; raw diagnostics not published.'
                for missing in report['engines_missing']:
                    missing['reason'] = sanitize_missing_reason(missing['reason'])
                destination = output/f'{case}.json'; destination.write_text(json.dumps(report, indent=2)+'\n')
                validation = subprocess.run([str(binary),'validate',str(destination)],capture_output=True,text=True,timeout=10)
                if validation.returncode: raise RuntimeError(f'{case}: sanitized report failed validation')
                expected = 'complete' if case == 'complete' else 'incomplete'
                if report['run_status'] != expected: raise RuntimeError(f'{case}: unexpected run status {report["run_status"]}')
                coverage = report['summary']['coverage']
                if coverage['modules_total'] != len(report['coverage']): raise RuntimeError('module denominator mismatch')
                if coverage['scanned'] + coverage['skipped'] != coverage['modules_total']: raise RuntimeError('scanned/skipped mismatch')
                observations.append(dict(case=case, cli_exit=result.returncode, validate_exit=validation.returncode,
                    model_requests=len(calls), run_status=report['run_status'], incomplete_reason=report['incomplete_reason'], coverage=coverage))
            finally:
                server.shutdown(); server.server_close(); thread.join()
    record = dict(schema='public-coverage-fixtures-v1', kind='self-built-engineering-mock', observations=observations,
        command='python3 fixtures/coverage/generate.py --binary <local-vettalon> --output <new-directory>',
        limitations='Loopback fixed mock replies and synthetic source only. External scanners depend on the local installation. Not a detection benchmark, target exploit, production acceptance, or new vulnerability discovery.')
    (output/'index.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({'cases':len(observations),'status':'complete','kind':record['kind']}))

if __name__ == '__main__': main()
