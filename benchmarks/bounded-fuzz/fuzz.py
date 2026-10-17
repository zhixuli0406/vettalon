"""Finite mutation/replay/minimization over a dummy in-memory ownership contract."""
import argparse
import base64
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parents[1]/'blind-twins'))
from protocol import sandbox_flags,digest,error_details


def replay(token,patched):
    if not token or not token.isascii() or not token.isdigit() or len(token)>8: return False
    object_id=int(token)
    records=[(0,'dummy-own'),(1,'dummy-other'),(0,'dummy-extra')]
    if object_id>=len(records): return False
    owner,content=records[object_id]
    result=None if patched and owner!=0 else content
    return result=='dummy-other'


def bounded_search(max_cases=128):
    if not 1<=max_cases<=1000: raise ValueError('Finite case cap must be 1..1000')
    for index in range(max_cases):
        token='0' if index==0 else f'{index:04d}'
        if replay(token,False) and not replay(token,True):
            return {'status':'counterexample-found','attempts':index+1,'counterexample':token,'proved_safe':False}
    return {'status':'no-counterexample-within-budget','attempts':max_cases,'counterexample':None,'proved_safe':False}


def minimize(token,max_replays=64):
    if not 1<=max_replays<=64: raise ValueError('Replay cap must be 1..64')
    if not replay(token,False) or replay(token,True): raise ValueError('Initial input must show differential security effect')
    current=token;attempts=0;index=0
    while index<len(current) and attempts<max_replays:
        candidate=current[:index]+current[index+1:];attempts+=1
        if replay(candidate,False) and not replay(candidate,True): current=candidate
        else: index+=1
    return {'minimal':current,'replays':attempts,'minimality':'one-character-deletion fixed point within budget' if index==len(current) else 'budget-limited'}


def native_sandbox(output):
    if output.exists(): raise FileExistsError('Preserve native raw evidence')
    raw={'runner_sha256':digest(Path(__file__).read_text()),'kind':'self-built-native-fuzz-prototype',
         'max_cases':128,'max_minimize_replays':64,'wall_timeout_seconds':30,'external_targets':False,
         'human_labels':False,'production_enabled':False,'status':'incomplete','phase':'initializing'}
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open('x') as handle: json.dump(raw,handle)
    def persist(): output.write_text(json.dumps(raw,indent=2)+'\n')
    cid=None;began=time.monotonic()
    try:
        raw['phase']='source-read';persist()
        source=Path(__file__).with_name('fixture.c').read_text()
        raw.update(source_sha256=digest(source),phase='image-inspect');persist()
        info=json.loads(subprocess.check_output(['docker','image','inspect','rust:1.94-bookworm'],text=True,timeout=10))[0]
        raw.update(image_id=info['Id'],image_repo_digests=info.get('RepoDigests',[]))
        # Execution from tmpfs is required for this trusted self-built C binary.
        flags=[flag.replace('/tmp:rw,noexec,nosuid,nodev,size=8m,mode=1777','/tmp:rw,exec,nosuid,nodev,size=16m,mode=1777') for flag in sandbox_flags()]
        encoded=base64.b64encode(source.encode()).decode()
        command='set -eu\nprintf %s "$1" | base64 -d > /tmp/fixture.c\ncc --version\ncc -std=c11 -O1 -Wall -Wextra -Werror /tmp/fixture.c -o /tmp/fixture\nsha256sum /tmp/fixture.c /tmp/fixture\n/tmp/fixture --search 128\n'
        raw.update(limits=flags,command_sha256=digest(command),phase='container-create');persist()
        cid=subprocess.check_output(['docker','create',*flags,info['Id'],'sh','-c',command,'runner',encoded],text=True,timeout=10).strip()
        if not cid: raise ValueError('Empty container ID')
        raw.update(container_id=cid,phase='container-start');persist()
        proc=subprocess.run(['docker','start','-a',cid],text=True,capture_output=True,timeout=30)
        raw.update(stdout=proc.stdout,stderr=proc.stderr,client_returncode=proc.returncode,phase='container-inspect');persist()
        state=json.loads(subprocess.check_output(['docker','inspect',cid],text=True,timeout=10))[0]
        iso={'network':state['HostConfig']['NetworkMode'],'read_only':state['HostConfig']['ReadonlyRootfs'],
             'mounts':state['Mounts'],'user':state['Config']['User'],'cap_drop':state['HostConfig']['CapDrop'],
             'memory':state['HostConfig']['Memory'],'nano_cpus':state['HostConfig']['NanoCpus'],
             'pids_limit':state['HostConfig']['PidsLimit'],'security_opt':state['HostConfig']['SecurityOpt']}
        raw.update(exit_code=state['State']['ExitCode'],isolation=iso,phase='oracle-parse');persist()
        lines=proc.stdout.strip().splitlines()
        if not lines: raise ValueError('Empty stdout is not an oracle result')
        observed=json.loads(lines[-1])
        raw['observed']=observed
        if not isinstance(observed,dict): raise ValueError('Oracle result must be an object')
        strict=(type(observed.get('vulnerable_security_effect')) is bool and type(observed.get('patched_security_effect')) is bool
                and type(observed.get('normal_control')) is bool and type(observed.get('search_attempts')) is int
                and type(observed.get('minimize_replays')) is int)
        isolated=(iso['network']=='none' and iso['read_only'] is True and iso['mounts']==[] and iso['user']=='65534:65534'
                  and iso['cap_drop']==['ALL'] and iso['memory']==134217728 and iso['nano_cpus']==500000000
                  and iso['pids_limit']==32 and 'no-new-privileges' in iso['security_opt'])
        raw['isolation_verified']=isolated
        valid=(strict and isolated and type(raw['exit_code']) is int and raw['exit_code']==0
               and type(proc.returncode) is int and proc.returncode==0 and observed['vulnerable_security_effect'] is True
               and observed['patched_security_effect'] is False and observed['normal_control'] is True
               and 1<=observed['search_attempts']<=128 and 0<=observed['minimize_replays']<=64)
        raw['status']='complete' if valid else 'incomplete'
        if not valid: raw['reason']='oracle-type-effect-control-or-isolation-failure'
    except (OSError,subprocess.SubprocessError,ValueError,TypeError,KeyError,IndexError) as exc:
        raw.update(status='incomplete',reason='execution-failure',**error_details(exc))
    finally:
        if cid:
            try:
                cleanup=subprocess.run(['docker','rm','-f',cid],capture_output=True,timeout=10)
                if cleanup.returncode!=0: raw.update(status='incomplete',cleanup='failed')
                else: raw['cleanup']='removed'
            except (OSError,subprocess.SubprocessError) as exc:
                raw.update(status='incomplete',cleanup='failed',cleanup_error=error_details(exc))
    raw['wall_seconds']=time.monotonic()-began
    persist()
    return raw


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    result=native_sandbox(args.output)
    print(json.dumps({'status':result['status'],'wall_seconds':result['wall_seconds'],'observed':result.get('observed')}))
    sys.exit(0 if result['status']=='complete' else 1)
