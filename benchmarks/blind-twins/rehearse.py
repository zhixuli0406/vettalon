"""Offline 3-arm x 5-repeat scheduling rehearsal. Never calls a model provider."""
import argparse
import json
from pathlib import Path
from protocol import ROOT,digest
from run import run


def rehearse(output_dir):
    if output_dir.exists(): raise FileExistsError('Preserve mock rehearsal outputs')
    output_dir.mkdir(parents=True)
    subset=ROOT/'fixed-five-pair-subset.json'
    def fake(*args,**kwargs):
        return {'message':{'content':json.dumps({'vulnerability':False,'category':'none','line':0,'evidence':'Offline scheduling stub; no model inference.'})}}
    rows=[]
    for arm in ['finder-only','samefamily','crossfamily']:
        for repeat in range(5):
            other={} if arm=='finder-only' else {'verifier_model':'mock-same' if arm=='samefamily' else 'mock-other','verifier_family':'qwen' if arm=='samefamily' else 'other-family-unselected'}
            result=run(output_dir/f'{arm}-{repeat}.json',arm=arm,model='mock-finder',repeat=repeat,subset_path=subset,transport=fake,mock=True,**other)
            rows.append({'arm':arm,'repeat':repeat,'mock_transport_invocations':result['calls'],
                         'scope_manifest_sha256':result['scope_manifest_sha256'],'positive_denominator':result['metrics']['positive_denominator'],
                         'safe_denominator':result['metrics']['safe_denominator'],'real_model_calls':0})
    report={'kind':'offline-ablation-scheduling-rehearsal','rows':rows,'real_model_calls':0,
            'scope_manifest_sha256':digest(json.loads(subset.read_text())),
            'planned_max_calls':{'finder-only':50,'samefamily':100,'crossfamily':100,'total':250},
            'planned_max_output_tokens':250*1024,'planned_max_inflight':1,'per_call_timeout_seconds':90,
            'per_run_wall_cap_seconds':1200,'automatic_retries':0,'USD_estimate':None,
            'limitations':'Scheduling and scope readiness only. No cross-family model, effectiveness, cost, or variance result. D01 budget and model selection pending.'}
    with (output_dir/'summary.json').open('x') as handle: json.dump(report,handle,indent=2);handle.write('\n')
    return report

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output-dir',type=Path,required=True);args=parser.parse_args()
    result=rehearse(args.output_dir)
    print(json.dumps({'runs':len(result['rows']),'mock_invocations':sum(x['mock_transport_invocations'] for x in result['rows']),'real_model_calls':0}))
