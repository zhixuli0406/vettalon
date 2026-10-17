"""Verify fresh-container canonical evidence, without promoting scanner findings."""
import argparse
import json
import re
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parents[1]/'blind-twins'))
from protocol import ARTIFACTS, digest, generate, harness

def valid(row,source_hash):
    iso=row.get('isolation',{})
    effect=row.get('observed',{})
    if not isinstance(iso,dict) or not isinstance(effect,dict): return False
    image=row.get('image_id'); container=row.get('container_id'); digests=row.get('image_repo_digests')
    if not isinstance(image,str) or not re.fullmatch(r'sha256:[0-9a-f]{64}',image): return False
    if not isinstance(container,str) or not re.fullmatch(r'[0-9a-f]{64}',container): return False
    if not isinstance(digests,list) or any(not isinstance(x,str) or not re.fullmatch(r'.+@sha256:[0-9a-f]{64}',x) for x in digests): return False
    return (row.get('source_sha256')==source_hash and row.get('fresh_container') is True
            and row.get('status')=='complete' and row.get('oracle_pass') is True
            and type(row.get('returncode')) is int and row['returncode']==0
            and type(row.get('client_returncode')) is int and row['client_returncode']==0
            and iso.get('network')=='none' and iso.get('read_only') is True
            and iso.get('user')=='65534:65534' and iso.get('cap_drop')==['ALL']
            and iso.get('mounts')==[]
            and iso.get('memory')==134217728 and iso.get('pids_limit')==32
            and iso.get('nano_cpus')==500000000
            and 'no-new-privileges' in iso.get('security_opt',[])
            and type(effect.get('security_effect')) is bool and effect.get('normal_control') is True and effect.get('uid')==65534)

def verify(source):
    raw=json.loads(source.read_text())
    payloads,labels=generate()
    rows=raw['rows']
    if len({x['id'] for x in rows})!=len(rows): raise ValueError('duplicate case')
    containers=[x['container_id'] for x in rows if x.get('container_id')]
    if len(set(containers))!=len(containers): raise ValueError('container reuse')
    images={x.get('image_id') for x in rows if isinstance(x.get('image_id'),str)}
    fixed_image=next(iter(images)) if len(images)==1 else None
    lookup={x['id']:x for x in rows}
    pairs=[]
    for family in ['object','tenant','role','path','sql']:
        ids=[x for x in labels if x['family']==family and x['variant']==0]
        evidence=[]
        for label in ids:
            payload=next(x for x in payloads if x['id']==label['id'])
            row=lookup.get(label['id'],{})
            ok=fixed_image is not None and row.get('image_id')==fixed_image and valid(row,payload['source_sha256']) and row.get('harness_sha256')==digest(harness(payload,label))
            ok=ok and row.get('observed',{}).get('security_effect') is label['vulnerable']
            evidence.append({'id':label['id'],'vulnerable':label['vulnerable'],'passed':ok,
                             'container_id':row.get('container_id'),'source_sha256':payload['source_sha256'],
                             'harness_sha256':row.get('harness_sha256'),'image_id':row.get('image_id'),
                             'image_repo_digests':row.get('image_repo_digests'),
                             'raw_pointer':source.name+'#/rows/'+str(rows.index(row)) if row in rows else None})
        pairs.append({'family':family,'pair_id':ids[0]['pair_id'],'status':'complete' if all(x['passed'] for x in evidence) else 'incomplete','evidence':evidence,
                      'evidence_level':'synthetic-canonical-differential','scanner_finding_confirmed':False})
    return {'fixed_image_id':fixed_image,'image_policy':'All specimens in a batch must record one pinned image ID; identity checks are internal consistency, not signatures or external verification.','schema':'differential-evidence-v1','kind':'synthetic-canonical-differential','source':source.name,
            'source_sha256':digest(source.read_text()),'pairs':pairs,'complete':sum(x['status']=='complete' for x in pairs),
            'denominator':5,'correction_attempts':0,'limitations':'Self-built toy fixtures and canonical oracle; no real repository finding or model-written PoC is confirmed.'}

def write_result(source,output):
    if output.exists(): raise FileExistsError('Preserve existing differential summary')
    report=verify(source)
    with output.open('x') as handle: json.dump(report,handle,indent=2);handle.write('\n')
    return report

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--source',type=Path,default=ARTIFACTS/'canonical-oracle.json')
    parser.add_argument('--output',type=Path,default=ARTIFACTS/'differential-summary.json')
    args=parser.parse_args()
    report=write_result(args.source,args.output)
    print(json.dumps({'complete':report['complete'],'denominator':report['denominator']}))
    sys.exit(0 if report['complete']==report['denominator'] else 1)
