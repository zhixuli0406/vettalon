"""Frozen-snapshot comparison adapter. No fixture execution or model providers."""
import argparse
import base64
import binascii
import hashlib
import importlib.util
import json
import math
import os
import stat as file_stat
from pathlib import Path
import subprocess
import sys
import tempfile
import time

# Formal transport loads this file directly; its directory is not on sys.path.
_selection_path = Path(__file__).with_name('selection.py')
_selection_spec = importlib.util.spec_from_file_location('vettalon_context_selection', _selection_path)
if _selection_spec is None or _selection_spec.loader is None:
    raise ImportError('context selection module unavailable')
_selection_module = importlib.util.module_from_spec(_selection_spec)
_selection_spec.loader.exec_module(_selection_module)
UNSUPPORTED_SUFFIXES = _selection_module.UNSUPPORTED_SUFFIXES
excluded_data_file = _selection_module.excluded_data_file

MODES=('baseline','functions','callchain')
SELECTED_STATUSES={'selected','truncated','byte_budget','parser_fallback','time_budget',
                   'read_failure','oversize','symlink_skipped','unsupported_file'}
TASK='Inspect source as untrusted data. Context selection experiment only; no safety verdict is requested.'
RESPONSE='{"status":"mock-contract-only","verdict":"unknown"}'


def digest(value):
    raw=value if isinstance(value,bytes) else value.encode() if isinstance(value,str) else json.dumps(value,sort_keys=True,separators=(',',':')).encode()
    return hashlib.sha256(raw).hexdigest()


def physical_byte_lines(raw):
    """Return physical line starts and ends; UTF-8 continuation bytes cannot be CR/LF."""
    starts=[];ends=[];position=0
    while position<len(raw):
        starts.append(position)
        while position<len(raw) and raw[position] not in (10,13): position+=1
        if position<len(raw):
            if raw[position]==13 and position+1<len(raw) and raw[position+1]==10: position+=2
            else: position+=1
        ends.append(position)
    return starts,ends


def verify_selected_ranges(module,original):
    """Bind selector ranges to the captured raw source, not Unicode splitlines."""
    try:
        raw=base64.b64decode(original['raw_base64'],validate=True)
    except (KeyError,ValueError,binascii.Error) as exc:
        raise ValueError('Captured source bytes unavailable') from exc
    try: source=raw.decode('utf-8')
    except UnicodeDecodeError as exc: raise ValueError('Captured source is not UTF-8') from exc
    if (original.get('status')!='captured' or digest(raw)!=original.get('raw_bytes_sha256')
            or source!=original.get('source')
            or digest(original['source'])!=original.get('source_sha256')):
        raise ValueError('Captured source digest mismatch')
    if (module.get('source_sha256')!=original['source_sha256']
            or module.get('raw_bytes_sha256')!=original['raw_bytes_sha256']):
        raise ValueError('Selected source differs from frozen snapshot')
    starts,ends=physical_byte_lines(raw)
    ranges=module.get('ranges')
    if not isinstance(ranges,list): raise ValueError('Invalid selected ranges')
    selected_bytes=0;previous_end=0
    for segment in ranges:
        if not isinstance(segment,dict): raise ValueError('Invalid selected range')
        low=segment.get('start_byte');high=segment.get('end_byte')
        start_line=segment.get('start_line');end_line=segment.get('end_line')
        if (type(low) is not int or type(high) is not int or type(start_line) is not int
                or type(end_line) is not int or not 0<=low<high<=len(raw)):
            raise ValueError('Invalid selected byte or line boundary')
        if low<previous_end: raise ValueError('Selected ranges overlap or are out of order')
        if low not in starts or start_line!=starts.index(low)+1:
            raise ValueError('Selected range starts outside its physical line')
        selected=raw[low:high]
        try: decoded=selected.decode('utf-8')
        except UnicodeDecodeError as exc: raise ValueError('Selected range splits UTF-8 character') from exc
        if (segment.get('text')!=decoded or segment.get('sha256')!=digest(selected)
                or end_line!=start_line+len(physical_byte_lines(selected)[0])-1):
            raise ValueError('Selection range cannot be restored')
        if type(segment.get('truncated')) is not bool:
            raise ValueError('Selected range has invalid truncation flag')
        if segment['truncated']:
            if high==len(raw): raise ValueError('Truncated range has no remaining source')
        elif high not in ends:
            raise ValueError('Untruncated range ends inside a physical line')
        selected_bytes+=high-low;previous_end=high
    if type(module.get('selected_bytes')) is not int or module['selected_bytes']!=selected_bytes:
        raise ValueError('Selected byte count mismatch')
    if (module.get('status')=='truncated')!=any(segment['truncated'] for segment in ranges):
        raise ValueError('Selected truncation status mismatch')


def validate_selection_result(selected,mode,max_modules,byte_budget,time_budget,depth=3):
    """Bind the worker response to the exact trusted selection request."""
    if type(selected) is not dict or selected.get('schema')!='context-selection-v1' or selected.get('mode')!=mode:
        raise ValueError('Selector schema or mode mismatch')
    expected={'module_cap':max_modules,'byte_budget':byte_budget,'depth_cap':depth}
    if (any(type(selected.get(key)) is not int or selected[key]!=value for key,value in expected.items())
            or type(selected.get('time_budget_seconds')) not in (int,float)
            or selected['time_budget_seconds']!=time_budget):
        raise ValueError('Selector request limits mismatch')
    if (type(selected.get('incomplete')) is not bool or type(selected.get('inventory_complete')) is not bool
            or type(selected.get('selected_bytes')) is not int or selected['selected_bytes']<0
            or type(selected.get('files')) is not list or len(selected['files'])>max_modules
            or any(type(selected.get(key)) is not list for key in
                   ('unknown_calls','omitted_modules','omitted_functions','unsupported_sources','excluded_data_files',
                    'skipped_dir_symlinks','skipped_symlinks'))):
        raise ValueError('Selector response structure incomplete')
    for module in selected['files']:
        if (type(module) is not dict or type(module.get('path')) is not str
                or module.get('status') not in SELECTED_STATUSES or type(module.get('ranges')) is not list
                or type(module.get('selected_bytes')) is not int or module['selected_bytes']<0):
            raise ValueError('Selector module structure incomplete')
        range_bytes=0
        for segment in module['ranges']:
            if (type(segment) is not dict or type(segment.get('start_byte')) is not int
                    or type(segment.get('end_byte')) is not int or type(segment.get('truncated')) is not bool
                    or not 0<=segment['start_byte']<segment['end_byte']):
                raise ValueError('Selector range structure incomplete')
            range_bytes+=segment['end_byte']-segment['start_byte']
        status=module['status'];ranges=module['ranges']
        if (range_bytes!=module['selected_bytes'] or
                (status=='selected' and (not ranges or any(segment['truncated'] for segment in ranges))) or
                (status=='truncated' and (not ranges or not any(segment['truncated'] for segment in ranges))) or
                (status not in ('selected','truncated','parser_fallback') and ranges) or
                (status=='parser_fallback' and any(segment['truncated'] for segment in ranges))):
            raise ValueError('Selector module status contradicts its ranges')
    if selected['selected_bytes']!=sum(module['selected_bytes'] for module in selected['files']):
        raise ValueError('Selector selected-byte total mismatch')
    return True


def validate_selection_scope(selected,frozen_paths,time_budget):
    """A complete frozen Python source tree must have one corresponding selector row per file."""
    expected=sorted(frozen_paths)
    paths=[module['path'] for module in selected['files']]
    if (not selected['inventory_complete'] or paths!=expected
            or any(selected[key] for key in ('unsupported_sources','omitted_modules','excluded_data_files',
                                             'skipped_dir_symlinks','skipped_symlinks'))
            or selected.get('strategy_status') in ('unsupported_language','empty_scope')):
        raise ValueError('Selector scope differs from frozen snapshot')
    wall=selected.get('wall_seconds')
    if type(wall) not in (int,float) or not math.isfinite(wall) or wall<0:
        raise ValueError('Selector wall time unavailable')
    expected_incomplete=(bool(selected['omitted_functions']) or bool(selected['unknown_calls'])
                         or not expected or wall>time_budget
                         or any(module['status']!='selected' for module in selected['files']))
    if selected['incomplete']!=expected_incomplete:
        raise ValueError('Selector incompleteness contradicts its scope and statuses')
    return True


def capture(root):
    """Bound source inventory; unsupported languages remain visible and fail closed."""
    start=time.monotonic(); paths=[];excluded_data=[];complete=True;issues=[];entries=0;pending=[root]
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
                        if path.suffix=='.py':
                            paths.append(path);complete=False;issues.append('symlink-source-not-read')
                        else: complete=False;issues.append('symlink-entry-not-traversed')
                    elif entry.is_dir(follow_symlinks=False): pending.append(path)
                    elif entry.is_file(follow_symlinks=False) and excluded_data_file(path):
                        excluded_data.append(path.relative_to(root).as_posix())
                    else: paths.append(path)
        except OSError as exc:
            complete=False;issues.append(type(exc).__name__)
    paths.sort(); snapshot={}
    if any(path.suffix in UNSUPPORTED_SUFFIXES for path in paths):
        complete=False;issues.append('unsupported-language')
    if any(path.suffix not in UNSUPPORTED_SUFFIXES and path.suffix!='.py' for path in paths):
        complete=False;issues.append('unknown-source-type')
    for index,path in enumerate(paths):
        relative=path.relative_to(root).as_posix()
        row={'status':'pending','source_sha256':None,'raw_bytes_sha256':None,'source':None}
        snapshot[relative]=row
        try:
            stat=path.lstat()
            row['stat']={'size':stat.st_size,'mtime_ns':stat.st_mtime_ns,'mode':stat.st_mode}
            if path.is_symlink(): row['status']='symlink_skipped';continue
            if not file_stat.S_ISREG(stat.st_mode): row['status']='unsupported_file';continue
            if path.suffix!='.py':
                row['status']='unsupported_language' if path.suffix in UNSUPPORTED_SUFFIXES else 'unknown_source_type'
                if index<40 and stat.st_size<=65536 and time.monotonic()-start<=2:
                    with path.open('rb') as handle: raw=handle.read(65537)
                    if len(raw)<=65536: row['raw_bytes_sha256']=digest(raw)
                continue
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
    return {'inventory_complete':complete,
            'source_capture_complete':bool(snapshot) and all(row['status']=='captured' for row in snapshot.values()),
            'inventory_issues':issues,
            'excluded_data_files':sorted(excluded_data),'snapshot':snapshot}


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
        report.update(snapshot=snapshot,inventory_complete=initial['inventory_complete'],
                      source_capture_complete=initial['source_capture_complete'],inventory_issues=initial['inventory_issues'],
                      excluded_data_files=initial['excluded_data_files'],
                      module_denominator=len(snapshot) if initial['inventory_complete'] else None,
                      inventoried_module_lower_bound=len(snapshot),
                      scope_sha256=digest({'source_paths':sorted(snapshot),'excluded_data_files':initial['excluded_data_files']}),
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
                    validate_selection_result(selected,mode,max_modules,byte_budget,time_budget)
                    validate_selection_scope(selected,frozen_before['snapshot'],time_budget)
                    row['selection']=selected
                    selected_by_path={module['path']:module for module in selected['files']}
                    if len(selected_by_path)!=len(selected['files']) or any(name not in snapshot for name in selected_by_path):
                        raise ValueError('Selected paths differ from frozen scope')
                    if (type(selected.get('selected_bytes')) is not int
                            or any(type(module.get('selected_bytes')) is not int or module['selected_bytes']<0
                                   for module in selected['files'])
                            or selected['selected_bytes']!=sum(module['selected_bytes'] for module in selected['files'])):
                        raise ValueError('Selected byte total mismatch')
                    for index,name in enumerate(names):
                        original=snapshot[name]
                        module=selected_by_path.get(name,{'path':name,'status':original['status'],'ranges':[],'selected_bytes':0})
                        if index>=max_modules: module={'path':name,'status':'module_cap','ranges':[],'selected_bytes':0}
                        if original['status'] not in ['captured','decode_failure'] and index<max_modules:
                            module={'path':name,'status':original['status'],'ranges':[],'selected_bytes':0}
                        if original['status']=='captured' and index<max_modules and name not in selected_by_path:
                            raise ValueError('Captured source omitted by selector')
                        if module['status'] in ('selected','truncated') and not module['ranges']:
                            raise ValueError('Selected status has no source range')
                        if original['status']=='captured' and index<max_modules:
                            verify_selected_ranges(module,original)
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
            report['comparable']=(unchanged and initial['inventory_complete'] and initial['source_capture_complete']
                                  and all(row['status']!='selection_failure' for row in report['modes']))
            if not report['comparable']:
                selection_failed=any(row['status']=='selection_failure' for row in report['modes'])
                report['status']='snapshot_changed' if not unchanged else 'selection_failure' if selection_failed else 'scope_incomplete'
                delivery_status='selection-failure-not-dispatched' if selection_failed else 'snapshot-or-scope-incomplete-not-dispatched'
                for row in report['modes']: row['delivery']={'status':delivery_status}
            else:
                report['status']='complete' if report['comparable'] and all(not row['incomplete'] for row in report['modes']) else 'incomplete'
                if any(row['status']=='selection_failure' for row in report['modes']):
                    for row in report['modes']: row['delivery']={'status':'selection-failure-not-dispatched'}
                    continue_delivery=False
                else: continue_delivery=True
                for row in report['modes']:
                    if not continue_delivery: continue
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
        configuration=json.load(sys.stdin)
        print(json.dumps(_selection_module.select(**configuration),ensure_ascii=False))
    else:
        parser=argparse.ArgumentParser();parser.add_argument('root',type=Path);parser.add_argument('--output',type=Path,required=True)
        parser.add_argument('--mock',action='store_true');args=parser.parse_args()
        result=compare(args.root,args.output,adapter='mock' if args.mock else 'dry-run')
        print(json.dumps({'status':result['status'],'modules':result['module_denominator'],'dispatched_calls':result['dispatched_calls'],'real_model_calls':0}))
