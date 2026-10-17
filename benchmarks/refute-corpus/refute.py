"""Bounded counterexample taxonomy over self-built in-memory fixtures."""
import argparse
import hashlib
import inspect
import json
from pathlib import Path


def process(actor,item,checked):
    if checked and item['owner']!=actor:
        return None
    return item['content']


def classify(evidence):
    if evidence.get('language_supported') is not True: return 'unsupported'
    if evidence.get('scope_complete') is not True: return 'missing-path'
    if evidence.get('policy_known') is not True: return 'deployment-unknown'
    if (evidence.get('replay_success') is not True or evidence.get('normal_control') is not True
            or type(evidence.get('security_effect')) is not bool
            or evidence.get('source_sha256')!=hashlib.sha256(inspect.getsource(process).encode()).hexdigest()
            or evidence.get('oracle_contract')!='synthetic-owner-v1'):
        return 'incomplete'
    return 'candidate-survives' if evidence['security_effect'] else 'code-safe-within-fixture-contract'


def run_cases():
    source=inspect.getsource(process)
    rows=[]
    for context in ['complete','deployment-unknown','missing-path','unsupported']:
        for checked in [False,True]:
            observed={'security_effect':process('alice',{'owner':'bob','content':'dummy-other'},checked)=='dummy-other',
                      'normal_control':process('alice',{'owner':'alice','content':'dummy-own'},checked)=='dummy-own'}
            proof={'language_supported':context!='unsupported','scope_complete':context!='missing-path',
                   'policy_known':context!='deployment-unknown','source_sha256':hashlib.sha256(source.encode()).hexdigest(),
                   'oracle_contract':'synthetic-owner-v1','replay_success':True,**observed}
            result=classify(proof)
            expected=context if context!='complete' else 'code-safe-within-fixture-contract' if checked else 'candidate-survives'
            rows.append({'id':context+('-checked' if checked else '-unchecked'),'checked':checked,'observed':observed,
                         'evidence':proof,'classification':result,'expected':expected,'matched_expected':result==expected,
                         'interpretation':'Self-built toy contract only; not a real finding adjudication.'})
    return {'implementation_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'schema':'refute-fixture-v1','kind':'synthetic-counterexample-taxonomy','rows':rows,'human_labels':False,
            'production_prompt_changed':False,'source':source,
            'policy':'Unknown deployment, missing path, unsupported language, or failed control never means code-safe.'}

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    with args.output.open('x') as handle: json.dump(run_cases(),handle,indent=2);handle.write('\n')
