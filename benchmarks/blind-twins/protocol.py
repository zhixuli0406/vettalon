"""Bounded synthetic evaluation protocol. No production policy changes."""
import argparse
import hashlib
import json
import math
import re
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ARTIFACTS = ROOT.parents[1] / 'reports/evidence-acceptance/experiments'
SCHEMA = 'vettalon-synthetic-twins-v1'

def digest(value):
    data = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    return hashlib.sha256(data.encode()).hexdigest()

def generate():
    payloads, labels = [], []
    for family in ['object', 'tenant', 'role', 'path', 'sql']:
        for variant in range(2):
            pair_id = digest(f'{family}:{variant}')[:12]
            for vulnerable in [True, False]:
                check = ''
                if family == 'object':
                    check = '' if vulnerable else "    if item['owner'] != actor: return None\n"
                    source = "def process(actor, item):\n" + check + "    return item['value']\n"
                elif family == 'tenant':
                    check = '' if vulnerable else "    if item['tenant'] != actor['tenant']: return None\n"
                    source = "def process(actor, item):\n" + check + "    result = item['value']\n    return result\n"
                elif family == 'role':
                    check = '' if vulnerable else "    if actor['role'] != 'admin': return False\n"
                    source = "def process(actor, item, value):\n" + check + "    item['value'] = value\n    return True\n"
                elif family == 'path':
                    check = '' if vulnerable else "    if root != target and root not in target.parents: return None\n"
                    source = "from pathlib import Path\ndef process(base, name):\n    root = Path(base).resolve()\n    target = (root / name).resolve()\n" + check + "    return target.read_text()\n"
                else:
                    query = 'db.execute("SELECT value FROM items WHERE owner = ?", (actor,)).fetchall()' if not vulnerable else 'db.execute("SELECT value FROM items WHERE owner = \'" + actor + "\'").fetchall()'
                    source = 'def process(db, actor):\n    return ' + query + '\n'
                if variant:
                    source = source.replace('item', 'entry').replace('actor', 'principal').replace('value', 'content').replace('base', 'directory').replace('name', 'segment')
                # Use a stable opaque identifier; no pair, family, or label is sent to models.
                case_id = 'c-' + digest(source)[:16]
                split = 'holdout' if family in ['path', 'sql'] else 'dev'
                payloads.append({'id':case_id, 'source':source, 'source_sha256':digest(source)})
                labels.append({'id':case_id,'pair_id':pair_id,'family':family,'variant':variant,
                               'vulnerable':vulnerable,'split':split,
                               'repository':f'synthetic-{family}-{variant}',
                               'snapshot_date':'2026-10-15' if split=='dev' else '2026-10-16',
                               'synthetic':True,'root_cause':family})
    return payloads, labels

def fixed_subset():
    payloads,labels=generate()
    selected={x['id'] for x in labels if x['variant']==0}
    chosen=sorted((x for x in payloads if x['id'] in selected),key=lambda x:x['id'])
    return {'schema':'fixed-subset-v1','case_ids':[x['id'] for x in chosen],
            'source_sha256':{x['id']:x['source_sha256'] for x in chosen}}


def select_scope(payloads,labels,manifest=None):
    if manifest is None: return payloads,labels
    if set(manifest)!={'schema','case_ids','source_sha256'} or manifest['schema']!='fixed-subset-v1':
        raise ValueError('Unsupported subset manifest')
    ids=manifest['case_ids']
    if not isinstance(ids,list) or not ids or len(ids)!=len(set(ids)): raise ValueError('Empty or duplicate subset ids')
    sources={x['id']:x for x in payloads}; targets={x['id']:x for x in labels}
    if set(ids)-set(sources) or set(manifest['source_sha256'])!=set(ids): raise ValueError('Unknown subset scope')
    if any(manifest['source_sha256'][case_id]!=sources[case_id]['source_sha256'] for case_id in ids):
        raise ValueError('Subset source hash mismatch')
    pairs={targets[case_id]['pair_id'] for case_id in ids}
    if any(sum(targets[case_id]['pair_id']==pair for case_id in ids)!=2 for pair in pairs):
        raise ValueError('Twins must be selected as complete pairs')
    return [sources[case_id] for case_id in ids],[targets[case_id] for case_id in ids]

def validate_payload(row):
    allowed = {'id','source','source_sha256'}
    if set(row)-allowed or re.search(r'cve-|vulnerable|patched|oracle|commit|holdout|ground.truth', json.dumps(row), re.I):
        raise ValueError('Label or identity leakage in anonymous payload')
    if 'source_sha256' in row and digest(row['source']) != row['source_sha256']:
        raise ValueError('Source hash mismatch')

def validate_arm(arm, finder_family, verifier_family=None):
    if arm not in ['finder-only','samefamily','crossfamily']:
        raise ValueError('Unknown experiment arm')
    if arm!='finder-only' and not verifier_family:
        raise ValueError('Verifier family required')
    if arm=='crossfamily' and finder_family==verifier_family:
        raise ValueError('Cross-family arm requires distinct families')
    if arm=='samefamily' and finder_family!=verifier_family:
        raise ValueError('Same-family arm requires same family')

def sandbox_flags():
    return ['--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
            '--user','65534:65534','--pids-limit','32','--memory','128m','--cpus','0.5',
            '--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=8m,mode=1777','--env','PYTHONDONTWRITEBYTECODE=1']

def harness(payload, label, run_identity=None):
    source = payload['source']
    variant, family = label['variant'], label['family']
    key = 'content' if variant else 'value'
    prefix = 'import json, sqlite3, pathlib, os\n' + 'exec(' + repr(source) + ')\n'
    if family=='object':
        body = f"a=process('alice',{{'owner':'bob','{key}':'record-other'}})\nn=process('alice',{{'owner':'alice','{key}':'record-own'}})\neffect=a=='record-other'\nnormal=n=='record-own'\n"
    elif family=='tenant':
        body = f"a=process({{'tenant':'a'}},{{'tenant':'b','{key}':'record-other'}})\nn=process({{'tenant':'a'}},{{'tenant':'a','{key}':'record-own'}})\neffect=a=='record-other'\nnormal=n=='record-own'\n"
    elif family=='role':
        body = f"item={{'{key}':'before'}}\nprocess({{'role':'viewer'}},item,'changed')\neffect=item['{key}']=='changed'\nnormal=process({{'role':'admin'}},item,'normal') is True and item['{key}']=='normal'\n"
    elif family=='path':
        body = "root=pathlib.Path('/tmp/data')\nroot.mkdir()\n(root/'own.txt').write_text('record-own')\npathlib.Path('/tmp/other.txt').write_text('record-other')\na=process(str(root),'../other.txt')\nn=process(str(root),'own.txt')\neffect=a=='record-other'\nnormal=n=='record-own'\n"
    else:
        body = f"db=sqlite3.connect(':memory:')\ndb.execute('CREATE TABLE {'entrys' if variant else 'items'} (owner TEXT, {key} TEXT)')\ndb.executemany('INSERT INTO {'entrys' if variant else 'items'} VALUES (?,?)',[('alice','record-own'),('bob','record-other')])\na=process(db,\"missing' OR 1=1 --\")\nn=process(db,'alice')\neffect=('record-other',) in a\nnormal=n==[('record-own',)]\n"
    identity_fields = ''
    if run_identity is not None:
        if not isinstance(run_identity, str) or not re.fullmatch(r'[0-9a-f]{64}', run_identity):
            raise ValueError('Invalid execution run identity')
        identity_fields = f",'run_identity':{run_identity!r},'case_id':{payload['id']!r},'source_sha256':{payload['source_sha256']!r}"
    return prefix + body + "print(json.dumps({'security_effect':effect,'normal_control':normal,'principal':'alice-or-viewer','object':'dummy-record','operation':'read-or-write','state':'synthetic-only','uid':os.getuid()" + identity_fields + "}))\n"

def evaluate_oracle(raw, vulnerable):
    try:
        observed=json.loads(raw['stdout'])
    except (ValueError, KeyError, TypeError):
        return {'status':'incomplete','reason':'missing-or-malformed-effect'}
    if not isinstance(observed,dict): return {'status':'incomplete','reason':'missing-or-malformed-effect'}
    if type(raw.get('returncode')) is not int or raw['returncode'] != 0 or type(observed.get('security_effect')) is not bool or observed.get('normal_control') is not True:
        return {'status':'incomplete','reason':'execution-or-control-failure','observed':observed}
    expected=observed['security_effect'] is vulnerable
    return {'status':'complete' if expected else 'incomplete','oracle_pass':expected,'observed':observed}

def error_details(exc):
    def as_text(value):
        if value is None: return ''
        return value.decode(errors='replace')[:8192] if isinstance(value,bytes) else str(value)[:8192]
    return {'error_class':type(exc).__name__,'stdout':as_text(getattr(exc,'stdout',getattr(exc,'output',None))),
            'stderr':as_text(getattr(exc,'stderr',None))}


def canonical(output, image='python:3.12-slim'):
    denominator_path=output.with_name('denominator.json' if output.name=='canonical-oracle.json' else output.stem+'-denominator.json')
    if output.exists() or denominator_path.exists(): raise FileExistsError('Refusing to overwrite frozen canonical artifacts')
    payloads,labels=generate()
    output.parent.mkdir(parents=True,exist_ok=True)
    rows=[]
    def persist():
        output.write_text(json.dumps({'schema':SCHEMA,'kind':'canonical-oracle','planned_cases':len(payloads),'rows':rows},indent=2)+'\n')
    with output.open('x') as handle:
        json.dump({'schema':SCHEMA,'kind':'canonical-oracle','status':'initializing','planned_cases':len(payloads),'rows':[]},handle)
    info=None;image_failure=None
    try:
        info=json.loads(subprocess.check_output(['docker','image','inspect',image],text=True,timeout=10))[0]
        if not isinstance(info.get('Id'),str): raise ValueError('Missing pinned image ID')
    except (OSError,subprocess.SubprocessError,ValueError,TypeError,KeyError,IndexError) as exc:
        image_failure=error_details(exc)
    for payload,label in zip(payloads,labels):
        script=harness(payload,label)
        raw={'id':payload['id'],'source_sha256':payload['source_sha256'],'harness_sha256':digest(script),
             'limits':sandbox_flags(),'fresh_container':False,'status':'incomplete','phase':'image-inspect'}
        rows.append(raw)
        if image_failure is not None:
            raw.update(reason='image-inspect-failure',**image_failure);persist();continue
        raw.update(image_id=info['Id'],image_repo_digests=info.get('RepoDigests',[]))
        cid=None;started=time.monotonic()
        try:
            raw['phase']='container-create';persist()
            cid=subprocess.check_output(['docker','create',*sandbox_flags(),info['Id'],'python','-I','-B','-c',script],text=True,timeout=15).strip()
            if not cid: raise ValueError('Empty container ID')
            raw.update(container_id=cid,fresh_container=True,container_create_returncode=0,phase='container-start');persist()
            run=subprocess.run(['docker','start','-a',cid],text=True,capture_output=True,timeout=20)
            raw.update(stdout=run.stdout,stderr=run.stderr,client_returncode=run.returncode,phase='container-inspect');persist()
            inspect=json.loads(subprocess.check_output(['docker','inspect',cid],text=True,timeout=10))[0]
            raw.update(returncode=inspect['State']['ExitCode'],
                       isolation={'network':inspect['HostConfig']['NetworkMode'],'read_only':inspect['HostConfig']['ReadonlyRootfs'],
                                  'mounts':inspect['Mounts'],'user':inspect['Config']['User'],'cap_drop':inspect['HostConfig']['CapDrop'],
                                  'memory':inspect['HostConfig']['Memory'],'nano_cpus':inspect['HostConfig']['NanoCpus'],
                                  'pids_limit':inspect['HostConfig']['PidsLimit'],'security_opt':inspect['HostConfig']['SecurityOpt']})
            raw['phase']='oracle-parse'
            if type(run.returncode) is not int or run.returncode!=0:
                raw.update(status='incomplete',reason='docker-start-failure')
            else: raw.update(evaluate_oracle(raw,label['vulnerable']))
        except (OSError,subprocess.SubprocessError,ValueError,TypeError,KeyError,IndexError) as exc:
            raw.update(status='incomplete',reason='execution-failure',**error_details(exc))
        finally:
            if cid:
                try:
                    cleanup=subprocess.run(['docker','rm','-f',cid],capture_output=True,timeout=15)
                    if cleanup.returncode!=0: raw.update(status='incomplete',cleanup='failed')
                    else: raw['cleanup']='removed'
                except (OSError,subprocess.SubprocessError) as exc:
                    raw.update(status='incomplete',cleanup='failed',cleanup_error=error_details(exc))
        raw['wall_seconds']=time.monotonic()-started
        persist()
    eligible=[]
    for pair in sorted({x['pair_id'] for x in labels}):
        pair_ids={x['id'] for x in labels if x['pair_id']==pair}
        matching=[r for r in rows if r['id'] in pair_ids]
        if len(matching)==2 and all(r['status']=='complete' and r.get('oracle_pass') for r in matching): eligible.append(pair)
    frozen={'schema':SCHEMA,'manifest_sha256':digest(labels),'canonical_sha256':digest(output.read_text()),
            'positive_denominator':len(labels)//2,'canonical_rebuildable_denominator':len(eligible),'eligible_pairs':eligible,
            'excluded_from_canonical_denominator':[x for x in sorted({r['pair_id'] for r in labels}) if x not in eligible],
            'note':'Freeze before model calls; failures remain in detection/surfaced denominator.'}
    with denominator_path.open('x') as handle: json.dump(frozen,handle,indent=2);handle.write('\n')
    return frozen


def metrics(labels, rows, eligible_pairs, resource_evidence=None, implementation=None):
    label_map={x['id']:x for x in labels}
    if len(label_map)!=len(labels): raise ValueError('Duplicate label ids')
    ids=[x['id'] for x in rows]
    if len(ids)!=len(set(ids)) or set(ids)-set(label_map): raise ValueError('Duplicate or unknown run id')
    if any(x.get('status')=='complete' and not all(type(x.get(k)) is bool for k in ['detected','surfaced']) for x in rows):
        raise ValueError('Historical or malformed completed row')
    for row in rows:
        for key in ['adjudication','detection_adjudication']:
            if row.get(key,'U') not in ['TP','FP','U']: raise ValueError('Invalid adjudication')
            if row.get(key)=='TP' and not label_map[row['id']]['vulnerable']:
                raise ValueError('TP contradicts frozen safe ground truth')
    by_id={x['id']:x for x in rows}
    positives=[x for x in labels if x['vulnerable']]
    n=len(positives)
    complete=[r for r in rows if r.get('status')=='complete']
    detection=sum(label_map[r['id']]['vulnerable'] and r.get('detected',False) for r in rows)
    surfaced=sum(label_map[r['id']]['vulnerable'] and r.get('surfaced',False) and r.get('root_cause_correct',r.get('detected',False)) for r in complete)
    findings=[r for r in complete if r.get('surfaced')]
    tp=sum(r.get('adjudication')=='TP' for r in findings)
    fp=sum(r.get('adjudication')=='FP' for r in findings)
    u=len(findings)-tp-fp
    safe_fp=sum(not label_map[r['id']]['vulnerable'] and r.get('adjudication')=='FP' for r in findings)
    unknown_safe=sum(not x['vulnerable'] and (by_id.get(x['id'],{}).get('status')!='complete' or (by_id[x['id']].get('surfaced') and by_id[x['id']].get('adjudication','U')=='U')) for x in labels)
    tn=sum(not label_map[r['id']]['vulnerable'] and not r.get('surfaced') for r in complete)
    sample=len(findings)
    times=sorted(r['wall_seconds'] for r in complete if isinstance(r.get('wall_seconds'),(int,float)))

    def adjudicated_recall(stage):
        confirmed=unknown=failed=attempted=0
        for label in positives:
            row=by_id.get(label['id'])
            if row is None:
                unknown+=1; failed+=1; continue
            if row.get('attempts') or row.get('status') not in ['missing','budget_exhausted']:
                attempted+=1
            if stage=='detection' and isinstance(row.get('finder_candidate'),dict):
                candidate=row['finder_candidate']['vulnerability']
            elif row.get('status')=='complete':
                candidate=(row.get('surfaced') or row.get('detected')) if stage=='detection' else row['surfaced']
            else:
                unknown+=1; failed+=1; continue
            if not candidate: continue
            decision=row.get('detection_adjudication',row.get('adjudication','U')) if stage=='detection' else row.get('adjudication','U')
            confirmed+=decision=='TP'
            unknown+=decision=='U'
        status='not-measured' if not attempted else 'incomplete' if failed else 'pending-adjudication' if unknown else 'measured'
        return {'value':confirmed/n if n and not unknown else None,
                'bounds':[confirmed/n,(confirmed+unknown)/n] if n else None,
                'status':status,'confirmed':confirmed,'unknown':unknown,'incomplete_positives':failed}

    d=adjudicated_recall('detection'); surfaced_adjudicated=adjudicated_recall('surfaced')
    exploit_attempted=any(r.get('differential_status') in ['complete','incomplete'] for r in rows)
    ev=sum(label_map[r['id']]['vulnerable'] and label_map[r['id']]['pair_id'] in eligible_pairs and r.get('differential_status')=='complete' and r.get('differential_oracle') is True for r in rows)
    exploit_unknown=sum(x['pair_id'] in eligible_pairs and by_id.get(x['id'],{}).get('differential_status')!='complete' for x in positives)
    out={'metric_schema':'adjudication-aware-v3','positive_denominator':n,'safe_denominator':len(labels)-n,
         'synthetic_label_match_detection_proxy':detection/n if n else None,
         'synthetic_label_match_surfaced_proxy':surfaced/n if n else None,
         'detection_recall':d['value'],'detection_recall_bounds':d['bounds'],'detection_measurement_status':d['status'],
         'detection_unknown_positives':d['unknown'],'detection_incomplete_positives':d['incomplete_positives'],
         'operational_detection_success_lower_bound':d['confirmed']/n if n else None,
         'surfaced_recall':surfaced_adjudicated['value'],'surfaced_recall_bounds':surfaced_adjudicated['bounds'],
         'surfaced_measurement_status':surfaced_adjudicated['status'],
         'exploit_validated_recall':ev/len(eligible_pairs) if eligible_pairs and exploit_attempted and not exploit_unknown else None,
         'exploit_validated_recall_bounds':[ev/len(eligible_pairs),(ev+exploit_unknown)/len(eligible_pairs)] if eligible_pairs and exploit_attempted else None,
         'exploit_measurement_status':'not-measured' if not exploit_attempted else 'incomplete' if exploit_unknown else 'measured',
         'canonical_rebuildable_denominator':len(eligible_pairs),'TP':tp,'FP':fp,'U':u,'TN':tn,
         'adjudicated_precision':tp/(tp+fp) if tp+fp else None,'adjudication_rate':(tp+fp)/sample if sample else None,
         'precision_bounds':[tp/sample,(tp+u)/sample] if sample else None,
         'FDR':fp/(tp+fp) if tp+fp else None,'adjudicated_FDR':fp/(tp+fp) if tp+fp else None,
         'FDR_bounds':[fp/sample,(fp+u)/sample] if sample else None,'FPR':safe_fp/(len(labels)-n) if len(labels)>n and unknown_safe==0 else None,
         'FPR_bounds':[safe_fp/(len(labels)-n),(safe_fp+unknown_safe)/(len(labels)-n)] if len(labels)>n else None,
         'observed_complete_safe_FPR':safe_fp/(safe_fp+tn) if safe_fp+tn and unknown_safe==0 else None,
         'incomplete':len(labels)-len(complete),'missing_ids':sorted(set(label_map)-set(by_id)),
         'wall_p50_seconds':times[len(times)//2] if len(times)>=20 else None,
         'wall_p95_seconds':times[math.ceil(.95*len(times))-1] if len(times)>=20 else None,
         'percentile_min_samples':20,'percentile_sample_count':len(times),'usd':None,'human_minutes':None,
         'cost_note':'Runner CPU and process-lifetime RSS observations require bound resource evidence. Model servers, children, GPU, electricity, USD and human review remain unmeasured.',
         'recall_semantics':'Bounds retain unknown candidate adjudication, missing and failed positives in the frozen denominator. Operational failures are not successes; label/category proxy is separate.'}
    from measurement import summarize
    out.update(summarize(resource_evidence, implementation))
    return out

def materialize():
    payloads,labels=generate()
    for row in payloads: validate_payload(row)
    (ROOT/'anonymous').mkdir(exist_ok=True)
    for row in payloads:
        (ROOT/'anonymous'/f"{row['id']}.json").write_text(json.dumps(row,indent=2)+'\n')
    (ROOT/'private').mkdir(exist_ok=True)
    (ROOT/'private'/'labels.json').write_text(json.dumps({'schema':SCHEMA,'labels':labels},indent=2)+'\n')
    (ROOT/'private'/'identity-map.json').write_text(json.dumps({'kind':'synthetic-origin-only','identities':[{'id':x['id'],'repository':x['repository'],'snapshot_date':x['snapshot_date']} for x in labels]},indent=2)+'\n')
    (ROOT/'fixed-five-pair-subset.json').write_text(json.dumps(fixed_subset(),indent=2)+'\n')
    (ROOT/'manifest.json').write_text(json.dumps({'schema':SCHEMA,'cases':[{'id':x['id'],'source_sha256':x['source_sha256']} for x in payloads],'synthetic':True,'count':len(payloads)},indent=2)+'\n')

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('action',choices=['generate','canonical'])
    parser.add_argument('--output',type=Path,default=ARTIFACTS/'canonical-oracle.json')
    args=parser.parse_args()
    if args.action=='generate': materialize()
    else: print(json.dumps(canonical(args.output),indent=2))
