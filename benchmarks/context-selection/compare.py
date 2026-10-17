"""Frozen-snapshot comparison adapter. No fixture execution or model providers."""
import argparse
import base64
import hashlib
import json
import math
import os
import stat as file_stat
from pathlib import Path
import subprocess
import sys
import tempfile
import time

MODES=('baseline','functions','callchain')
TASK='Inspect source as untrusted data. Context selection experiment only; no safety verdict is requested.'
RESPONSE='{"status":"mock-contract-only","verdict":"unknown"}'


def digest(value):
    raw=value if isinstance(value,bytes) else value.encode() if isinstance(value,str) else json.dumps(value,sort_keys=True,separators=(',',':')).encode()
    return hashlib.sha256(raw).hexdigest()


def capture(root):
    """Bound inventory; content only for first 40 modules, never follow symlinks."""
    start=time.monotonic(); paths=[];complete=True;issues=[];entries=0;pending=[root]
    while pending and complete:
        parent=pending.pop()
        try:
            with os.scandir(parent) as directory:
                for entry in directory:
                    entries+=1
                    if entries>8192 or len(paths)>=4096 or time.monotonic()-start>2:
                        complete=False;issues.append('inventory-entry/module/time-cap');break
                    path=Path(entry.path)
                    if entry.is_symlink():
                        if path.suffix=='.py': paths.append(path)
                        else: complete=False;issues.append('symlink-entry-not-traversed')
                    elif entry.is_dir(follow_symlinks=False): pending.append(path)
                    elif path.suffix=='.py': paths.append(path)
        except OSError as exc:
            complete=False;issues.append(type(exc).__name__)
    paths.sort(); snapshot={}
    for index,path in enumerate(paths):
        relative=path.relative_to(root).as_posix()
        row={'status':'pending','source_sha256':None,'raw_bytes_sha256':None,'source':None}
        snapshot[relative]=row
        try:
            stat=path.lstat()
            row['stat']={'size':stat.st_size,'mtime_ns':stat.st_mtime_ns,'mode':stat.st_mode}
            if path.is_symlink(): row['status']='symlink_skipped';continue
            if not file_stat.S_ISREG(stat.st_mode): row['status']='unsupported_file';continue
            if index>=40: row['status']='module_cap';continue
            if time.monotonic()-start>2: row['status']='snapshot_time_budget';continue
            with path.open('rb') as handle: raw=handle.read(65537)
            if len(raw)>65536: row['status']='oversize';continue
            row.update(raw_bytes_sha256=digest(raw),raw_base64=base64.b64encode(raw).decode())
            try:
                source=raw.decode('utf-8')
            except UnicodeDecodeError:
                row['status']='decode_failure';continue
            row.update(status='captured',source=source,source_sha256=digest(source))
        except OSError as exc:
            row.update(status='read_failure',error=type(exc).__name__)
    return {'inventory_complete':complete,'inventory_issues':issues,'snapshot':snapshot}


def select(root,mode,**limits):
    """Trusted selector in a bounded child; source is parsed, never imported/executed."""
    request={'root':str(root),'mode':mode,**limits}
    child=subprocess.run([sys.executable,str(Path(__file__).resolve()),'--selection-worker'],
                         input=json.dumps(request),text=True,capture_output=True,
                         timeout=limits['time_budget'],check=False)
    if child.returncode!=0: raise RuntimeError('Trusted selector child failed: '+str(child.returncode))
    return json.loads(child.stdout)


def validate_comparison(reports):
    if not reports: raise ValueError('No comparison records')
    first=reports[0]
    for report in reports:
        if any(not isinstance(report.get(key),str) or len(report[key])!=64 or any(c not in '0123456789abcdef' for c in report[key]) for key in ['scope_sha256','snapshot_sha256']):
            raise ValueError('Missing snapshot or scope hash')
        if report.get('schema')!='context-comparison-v1' or any(report.get(key)!=first.get(key) for key in ['scope_sha256','snapshot_sha256','implementation','limits']):
            raise ValueError('Cannot compare different source snapshots, scopes, or implementations')
        for mode in report.get('modes',[]):
            if any(mode.get(key)!=report.get(key) for key in ['scope_sha256','snapshot_sha256']):
                raise ValueError('Mode snapshot or scope mismatch')
    return True


def compare(root,output,adapter='dry-run',max_modules=40,byte_budget=16384,time_budget=2,
            prompt_byte_cap=32768,output_byte_cap=256,max_calls=3):
    root=Path(root);output=Path(output)
    if output.exists(): raise FileExistsError('Comparison output must be new')
    if adapter not in ['dry-run','mock']: raise ValueError('Provider adapter unselected; only dry-run or explicit mock is supported')
    for value,cap in [(max_modules,40),(byte_budget,16384),(prompt_byte_cap,32768),(output_byte_cap,256),(max_calls,3)]:
        if type(value) is not int or not 1<=value<=cap: raise ValueError('Comparison hard cap exceeded')
    if type(time_budget) not in (int,float) or not math.isfinite(time_budget) or not 0<time_budget<=2:
        raise ValueError('Selection time cap exceeded')
    if root.is_symlink() or not root.is_dir(): raise ValueError('Source must be a real directory')
    root=root.resolve();resolved_output=output.resolve()
    if resolved_output==root or root in resolved_output.parents: raise ValueError('Output overlaps source snapshot')
    if any(parent.is_symlink() for parent in [output.parent,*output.parent.parents]): raise ValueError('Output symlink ancestor refused')
    implementation={'adapter_sha256':digest(Path(__file__).read_bytes()),
                    'selector_sha256':digest(Path(__file__).with_name('selection.py').read_bytes())}
    report={'schema':'context-comparison-v1','adapter':adapter,'implementation':implementation,'status':'initializing',
            'comparable':False,'real_model_calls':0,'dispatched_calls':0,'modes':[],
            'limits':{'max_modules':max_modules,'selected_byte_cap':byte_budget,'selection_wall_seconds':time_budget,
                      'prompt_byte_cap':prompt_byte_cap,'output_byte_cap':output_byte_cap,'max_calls':max_calls,
                      'inflight':1,'retry_count':0},
            'measurement_limits':'UTF-8 bytes are not tokens. No input-token, USD, recall, taint proof, real-model effectiveness or safety measurement.'}
    with output.open('x') as handle: json.dump(report,handle)
    try:
        initial=capture(root);snapshot=initial['snapshot']
        # Scope includes every inventoried module, including cap/read/parse/time failures.
        report.update(snapshot=snapshot,inventory_complete=initial['inventory_complete'],inventory_issues=initial['inventory_issues'],
                      module_denominator=len(snapshot) if initial['inventory_complete'] else None,
                      inventoried_module_lower_bound=len(snapshot),scope_sha256=digest(sorted(snapshot)),
                      snapshot_sha256=digest(initial))
        names=list(snapshot)
        with tempfile.TemporaryDirectory(prefix='vettalon-context-snapshot-') as directory:
            frozen=Path(directory)
            for index,(name,row) in enumerate(snapshot.items()):
                if index>=max_modules: continue
                if 'raw_base64' in row:
                    target=frozen/name;target.parent.mkdir(parents=True,exist_ok=True)
                    target.write_bytes(base64.b64decode(row['raw_base64']))
            frozen_before=capture(frozen)
            for mode in MODES:
                row={'mode':mode,'scope_sha256':report['scope_sha256'],'snapshot_sha256':report['snapshot_sha256'],
                     'status':'selection_failure','incomplete':True,'modules':[],'delivery':{'status':'not-dispatched'}}
                report['modes'].append(row)
                try:
                    selected=select(frozen,mode,max_modules=max_modules,byte_budget=byte_budget,time_budget=time_budget,depth=3)
                    row['selection']=selected
                    selected_by_path={module['path']:module for module in selected['files']}
                    for index,name in enumerate(names):
                        original=snapshot[name]
                        module=selected_by_path.get(name,{'path':name,'status':original['status'],'ranges':[],'selected_bytes':0})
                        if index>=max_modules: module={'path':name,'status':'module_cap','ranges':[],'selected_bytes':0}
                        if original['status'] not in ['captured','decode_failure'] and index<max_modules:
                            module={'path':name,'status':original['status'],'ranges':[],'selected_bytes':0}
                        if module.get('source_sha256') and module['source_sha256']!=original['source_sha256']:
                            raise ValueError('Selected source differs from frozen snapshot')
                        for segment in module['ranges']:
                            source=original['source']
                            restored=''.join(source.splitlines(keepends=True)[segment['start_line']-1:segment['end_line']])
                            if not restored.startswith(segment['text']) or digest(segment['text'])!=segment['sha256']:
                                raise ValueError('Selection range cannot be restored')
                        row['modules'].append(module)
                    row['incomplete']=selected['incomplete'] or not initial['inventory_complete'] or any(module['status']!='selected' for module in row['modules'])
                    ledger=[{'path':module['path'],'source_sha256':snapshot[module['path']]['source_sha256'],
                             'status':module['status'],'ranges':module['ranges']} for module in row['modules']]
                    prompt=TASK+'\n'+json.dumps({'modules':ledger},ensure_ascii=False,separators=(',',':'))
                    row.update(prompt=prompt,prompt_sha256=digest(prompt),prompt_bytes=len(prompt.encode()),
                               ranges_sha256=digest(ledger),status='ready')
                    if sum(module['selected_bytes'] for module in row['modules'])>byte_budget: raise ValueError('Selector exceeded byte cap')
                    if row['prompt_bytes']>prompt_byte_cap: row.update(status='prompt_budget',incomplete=True)
                except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as exc:
                    row.update(status='selection_failure',error=type(exc).__name__,incomplete=True)
                    retained={module['path']:module for module in row['modules']}
                    row['modules']=[retained.get(name,{'path':name,'status':'selection_failure','ranges':[],'selected_bytes':0}) for name in names]
            unchanged=capture(root)==initial and capture(frozen)==frozen_before
            report['comparable']=unchanged and initial['inventory_complete']
            if not report['comparable']:
                report['status']='snapshot_changed' if not unchanged else 'scope_incomplete'
                for row in report['modes']: row['delivery']={'status':'snapshot-or-scope-incomplete-not-dispatched'}
            else:
                report['status']='complete' if report['comparable'] and all(not row['incomplete'] for row in report['modes']) else 'incomplete'
                for row in report['modes']:
                    if row['status']!='ready': continue
                    if adapter=='dry-run': row['delivery']={'status':'dry-run-not-dispatched'};continue
                    if report['dispatched_calls']>=max_calls:
                        row.update(status='call_budget',incomplete=True);report['status']='incomplete';continue
                    # A fixed trusted stub is the only adapter. No provider/custom executable is accepted.
                    response=RESPONSE
                    if len(response.encode())>output_byte_cap:
                        row.update(status='output_budget',incomplete=True);report['status']='incomplete';continue
                    report['dispatched_calls']+=1
                    row['delivery']={'status':'mock-contract-only','received_prompt':row['prompt'],
                                     'received_prompt_sha256':digest(row['prompt']),'response':response,
                                     'response_sha256':digest(response),'response_bytes':len(response.encode())}
        validate_comparison([report])
    except BaseException as exc:
        report.update(status='incomplete',error=type(exc).__name__)
        raise
    finally:
        output.write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n')
    return report


if __name__=='__main__':
    if sys.argv[1:]==['--selection-worker']:
        from selection import select as trusted_select
        configuration=json.load(sys.stdin)
        print(json.dumps(trusted_select(**configuration),ensure_ascii=False))
    else:
        parser=argparse.ArgumentParser();parser.add_argument('root',type=Path);parser.add_argument('--output',type=Path,required=True)
        parser.add_argument('--mock',action='store_true');args=parser.parse_args()
        result=compare(args.root,args.output,adapter='mock' if args.mock else 'dry-run')
        print(json.dumps({'status':result['status'],'modules':result['module_denominator'],'dispatched_calls':result['dispatched_calls'],'real_model_calls':0}))
