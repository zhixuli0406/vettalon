"""Offline 3-arm x 5-repeat scheduling rehearsal. Never calls a model provider."""
import argparse
import json
from pathlib import Path
from protocol import ROOT,digest,fixed_subset,generate,select_scope
from run import prepare_identity_view,run


def rehearse(output_dir,identity_view='anonymous',identity_binding_path=None):
    if identity_view not in ('anonymous','identified'):
        raise ValueError('Unsupported identity view')
    if identity_view=='identified' and identity_binding_path is None:
        raise ValueError('Identified rehearsal requires an explicit binding file')
    if identity_view=='anonymous' and identity_binding_path is not None:
        raise ValueError('Anonymous rehearsal cannot accept an identity binding file')
    if output_dir.exists(): raise FileExistsError('Preserve mock rehearsal outputs')
    subset=ROOT/'fixed-five-pair-subset.json'
    scope=json.loads(subset.read_text())
    if scope!=fixed_subset():
        raise ValueError('Frozen five-pair rehearsal scope changed')
    binding_sha=None
    if identity_view=='identified':
        payloads,_=select_scope(*generate(),scope)
        _,lineage=prepare_identity_view(payloads,scope,identity_binding_path)
        binding_sha=lineage['binding_file_sha256']
    output_dir.mkdir(parents=True)
    def fake(*args,**kwargs):
        return {'message':{'content':json.dumps({'vulnerability':False,'category':'none','line':0,'evidence':'Offline scheduling stub; no model inference.'})}}
    rows=[]
    for arm in ['finder-only','samefamily','crossfamily']:
        for repeat in range(5):
            other={} if arm=='finder-only' else {'verifier_model':'mock-same' if arm=='samefamily' else 'mock-other','verifier_family':'qwen' if arm=='samefamily' else 'other-family-unselected'}
            result=run(output_dir/f'{arm}-{repeat}.json',arm=arm,model='mock-finder',repeat=repeat,subset_path=subset,
                       transport=fake,mock=True,identity_view=identity_view,identity_binding_path=identity_binding_path,**other)
            if (result['scope_manifest_sha256']!=digest(scope)
                    or (result['identity_lineage']['binding_file_sha256'] if result['identity_lineage'] else None)!=binding_sha):
                raise ValueError('Scope or identity binding changed during rehearsal')
            rows.append({'arm':arm,'repeat':repeat,'mock_transport_invocations':result['calls'],
                         'identity_view':result['identity_view'],
                         'identity_binding_file_sha256':result['identity_lineage']['binding_file_sha256'] if result['identity_lineage'] else None,
                         'scope_manifest_sha256':result['scope_manifest_sha256'],'positive_denominator':result['metrics']['positive_denominator'],
                         'safe_denominator':result['metrics']['safe_denominator'],'real_model_calls':0})
    report={'kind':'offline-ablation-scheduling-rehearsal','identity_view':identity_view,'rows':rows,'real_model_calls':0,
            'scope_manifest_sha256':digest(json.loads(subset.read_text())),
            'planned_max_calls':{'finder-only':50,'samefamily':100,'crossfamily':100,'total':250},
            'planned_max_output_tokens':250*1024,'planned_max_inflight':1,'per_call_timeout_seconds':90,
            'per_run_wall_cap_seconds':1200,'automatic_retries':0,'USD_estimate':None,
            'limitations':'One identity view per rehearsal. Scheduling and scope readiness only; no provider inference, effectiveness, cost, or variance result. D01 budget and model selection pending.'}
    with (output_dir/'summary.json').open('x') as handle: json.dump(report,handle,indent=2);handle.write('\n')
    return report

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output-dir',type=Path,required=True)
    parser.add_argument('--identity-view',choices=['anonymous','identified'],default='anonymous')
    parser.add_argument('--identity-binding-path',type=Path)
    args=parser.parse_args()
    result=rehearse(**vars(args))
    print(json.dumps({'runs':len(result['rows']),'mock_invocations':sum(x['mock_transport_invocations'] for x in result['rows']),'real_model_calls':0}))
