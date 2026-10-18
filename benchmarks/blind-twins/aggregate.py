"""Recompute adjudication-aware metrics from immutable raw records without model calls."""
import argparse
import copy
import hashlib
import json
import math
from pathlib import Path
from identity_views import build_paired_manifest, build_view, validate_view
from ledger import IDENTITY_SOURCE_FILE_CAP, read_regular
from protocol import ARTIFACTS, ROOT, SCHEMA, canonical_path_for_denominator, digest, generate, metrics, select_scope, validate_arm, validate_frozen_canonical
from run import TASK, parse_answer


def verify_identified_lineage(raw, payloads, labels, binding_path):
    """Independently reconstruct the identified source, prompts, and row bindings."""
    if binding_path is None:
        raise ValueError('Identified raw needs the original explicit binding file')
    source_bytes=read_regular((ROOT/'manifest.json').absolute(),IDENTITY_SOURCE_FILE_CAP)
    source_sha=hashlib.sha256(source_bytes).hexdigest()
    source_manifest=json.loads(source_bytes)
    generated,_=generate()
    cases=[{'id':p['id'],'source_sha256':p['source_sha256']} for p in generated]
    if (type(source_manifest) is not dict
            or set(source_manifest)!={'schema','cases','synthetic','count'}
            or source_manifest['schema']!=SCHEMA or source_manifest['synthetic'] is not True
            or type(source_manifest['count']) is not int or source_manifest['count']!=len(cases)
            or source_manifest['cases']!=cases):
        raise ValueError('Materialized source manifest differs from the frozen source set')
    if {p.name for p in (ROOT/'anonymous').glob('*.json')}!={p['id']+'.json' for p in generated}:
        raise ValueError('Materialized anonymous source set differs from the manifest')
    for expected in generated:
        actual=json.loads(read_regular((ROOT/'anonymous'/f"{expected['id']}.json").absolute(),
                                       IDENTITY_SOURCE_FILE_CAP))
        if actual!=expected or not validate_view(actual,'anonymous',expected):
            raise ValueError('Materialized source differs from frozen source')
    binding_bytes=read_regular(Path(binding_path).absolute(),IDENTITY_SOURCE_FILE_CAP)
    declared=json.loads(binding_bytes)
    selected_ids={p['id'] for p in payloads}
    if (type(declared) is not dict
            or set(declared)!={'schema','source_manifest_sha256','bindings'}
            or declared['schema']!='twins-identity-bindings-v1'
            or declared['source_manifest_sha256']!=source_sha
            or type(declared['bindings']) is not dict
            or set(declared['bindings'])!=selected_ids):
        raise ValueError('Identified binding file differs from selected materialized source scope')
    scope=raw.get('scope_manifest') or {'schema':'fixed-subset-v1',
                                        'case_ids':[p['id'] for p in payloads],
                                        'source_sha256':{p['id']:p['source_sha256'] for p in payloads}}
    paired=build_paired_manifest(payloads,scope,declared['bindings'],source_sha)
    lineage={'view':'identified','source_meaning':'synthetic-source-attribution-only',
             'source_binding_status':'materialized-locally-verified; not upstream-authenticated',
             'source_manifest_sha256':source_sha,
             'binding_file_sha256':hashlib.sha256(binding_bytes).hexdigest(),
             'paired_manifest':paired}
    if raw.get('identity_lineage')!=lineage:
        raise ValueError('Identified raw lineage does not match the binding and materialized sources')
    implementation=raw.get('implementation')
    current_implementation={'runner_sha256':digest(Path(__file__).with_name('run.py').read_text()),
                            'protocol_sha256':digest(Path(__file__).with_name('protocol.py').read_text()),
                            'identity_views_sha256':digest(Path(__file__).with_name('identity_views.py').read_text())}
    if (type(implementation) is not dict
            or any(implementation.get(k)!=v for k,v in current_implementation.items())):
        raise ValueError('Identified raw requires matching local runner, protocol, and view source')
    if (type(raw.get('rows')) is not list or len(raw['rows'])>len(payloads)
            or any(type(row) is not dict for row in raw['rows'])
            or [row.get('id') for row in raw['rows']]!=[p['id'] for p in payloads[:len(raw['rows'])]]):
        raise ValueError('Identified rows are not an exact prefix of the selected source scope')
    validate_arm(raw.get('arm'),raw.get('finder_family'),raw.get('verifier_family'))
    if (type(raw.get('model')) is not str or not raw['model']
            or (raw['arm']=='finder-only' and raw.get('verifier_model') is not None)
            or (raw['arm']!='finder-only' and (type(raw.get('verifier_model')) is not str or not raw['verifier_model']))):
        raise ValueError('Identified raw has inconsistent model declarations')
    limits=raw.get('limits')
    if (type(limits) is not dict
            or set(limits)!={'max_calls','timeout_seconds','output_tokens','wall_seconds','inflight','automatic_retry'}
            or any(type(value) is not int for value in limits.values())
            or not 1<=limits['max_calls']<=20 or limits['timeout_seconds']!=90
            or limits['output_tokens']!=1024 or not 1<=limits['wall_seconds']<=1200
            or limits['inflight']!=1 or limits['automatic_retry']!=0
            or type(raw.get('repeat')) is not int or not 0<=raw['repeat']<=4):
        raise ValueError('Identified raw exceeds or changes the bounded run contract')
    case_hashes={case['id']:case['identified_payload_sha256'] for case in paired['cases']}
    label_by_id={label['id']:label for label in labels}
    attempts=0
    for row,expected in zip(raw['rows'],payloads):
        view=build_view(expected,'identified',declared['bindings'][expected['id']])
        if (row.get('identity_view')!='identified'
                or row.get('identity_payload_sha256')!=case_hashes[expected['id']]):
            raise ValueError('Identified row payload hash differs from the selected view')
        old_fingerprint=digest({'source':expected['source_sha256'],
              'scope_manifest_sha256':raw.get('scope_manifest_sha256'),
              'model_identity':raw.get('model_identity'),'family_mapping':raw.get('family_mapping'),
              'implementation':implementation,'task':TASK,'arm':raw['arm'],'finder':raw['model'],
              'verifier':raw['verifier_model'],'max_output':1024,'repeat':raw.get('repeat')})
        fingerprint=digest({'legacy_fingerprint':old_fingerprint,'identity_view':'identified',
                            'identity_payload_sha256':case_hashes[expected['id']],
                            'source_manifest_sha256':source_sha,
                            'binding_file_sha256':lineage['binding_file_sha256'],
                            'limits':limits})
        if row.get('fingerprint')!=fingerprint:
            raise ValueError('Identified row fingerprint differs from source and view')
        required_row={'id','arm','schema','status','attempts','source_sha256','fingerprint',
                      'adjudication','differential_oracle','cache','retry_count',
                      'identity_view','identity_payload_sha256','wall_seconds'}
        derived_row={'failed_stage','detected','finder_candidate','surfaced',
                     'root_cause_correct','verifier_parent_sha256'}
        if (not required_row<=set(row) or set(row)-required_row-derived_row
                or row['arm']!=raw['arm'] or row['schema']!=SCHEMA
                or row['source_sha256']!=expected['source_sha256']
                or row['adjudication']!='U' or row['differential_oracle'] is not False
                or row['cache'] is not False or type(row['retry_count']) is not int
                or row['retry_count']!=0 or type(row['wall_seconds']) not in (int,float)
                or not math.isfinite(row['wall_seconds']) or row['wall_seconds']<0):
            raise ValueError('Identified row changed fixed or metrics-relevant fields')
        row_attempts=row.get('attempts')
        if (type(row_attempts) is not list
                or any(type(attempt) is not dict for attempt in row_attempts)
                or len(row_attempts)>(1 if raw['arm']=='finder-only' else 2)):
            raise ValueError('Identified row has invalid stage attempts')
        if row.get('status')=='complete' and (len(row_attempts)!=(1 if raw['arm']=='finder-only' else 2)
                                              or any(type(attempt.get('parsed')) is not dict for attempt in row_attempts)):
            raise ValueError('Complete identified row lacks parsed stage evidence')
        expected_stages=['finder','verifier'][:len(row_attempts)]
        if [attempt.get('stage') for attempt in row_attempts]!=expected_stages:
            raise ValueError('Identified attempt order differs from the selected arm')
        successful={}
        last_outcome=None
        for attempt in row_attempts:
            stage=attempt['stage']
            expected_model=raw['model'] if stage=='finder' else raw['verifier_model']
            if stage=='verifier' and 'finder_candidate' not in row:
                raise ValueError('Verifier prompt has no finder candidate')
            prompt=TASK+json.dumps(view)
            if stage=='verifier':
                prompt+='\nIndependent review of candidate; reject if no concrete flaw: '+json.dumps(row['finder_candidate'])
            if (attempt.get('model')!=expected_model or attempt.get('prompt')!=prompt
                    or attempt.get('prompt_sha256')!=digest(prompt)):
                raise ValueError('Identified attempt prompt, model, or prompt hash mismatch')
            timeout=attempt.get('timeout_seconds')
            if (type(attempt.get('max_output_tokens')) is not int or attempt['max_output_tokens']!=1024
                    or type(timeout) not in (int,float) or not 0<timeout<=min(90,limits['wall_seconds'])):
                raise ValueError('Identified attempt exceeds output or timeout cap')
            if 'parsed' in attempt and 'error' in attempt:
                raise ValueError('Identified attempt cannot be both parsed and failed')
            if 'parsed' in attempt:
                try:
                    parsed=parse_answer(attempt['raw']['message']['content'],expected['source'])
                except (TypeError,KeyError,ValueError) as exc:
                    raise ValueError('Identified parsed answer has no matching raw response') from exc
                if parsed!=attempt['parsed']:
                    raise ValueError('Identified parsed answer differs from raw response')
                if stage=='finder' and parsed is not None and row.get('finder_candidate')!=parsed:
                    raise ValueError('Identified finder candidate differs from raw response')
                if parsed is None:
                    last_outcome='parse_failure'
                else:
                    successful[stage]=parsed
                    last_outcome='success'
            elif type(attempt.get('error')) is str and attempt['error']:
                last_outcome='timeout' if attempt['error']=='TimeoutError' else 'engine_failure'
            else:
                raise ValueError('Identified attempt has neither parsed answer nor error')
            attempts+=1
        expected_derived={}
        if 'finder' in successful:
            candidate=successful['finder']
            hit=candidate['vulnerability'] and candidate['category']==label_by_id[expected['id']]['family']
            expected_derived.update(detected=bool(hit),finder_candidate=candidate,
                                    surfaced=candidate['vulnerability'],root_cause_correct=bool(hit))
        if 'verifier' in successful:
            candidate=successful['verifier']
            hit=candidate['vulnerability'] and candidate['category']==label_by_id[expected['id']]['family']
            expected_derived.update(verifier_parent_sha256=digest(successful['finder']),
                                    surfaced=candidate['vulnerability'],root_cause_correct=bool(hit))
        if not row_attempts:
            expected_status='budget_exhausted';expected_derived['failed_stage']='finder'
        elif last_outcome=='success' and len(row_attempts)==(1 if raw['arm']=='finder-only' else 2):
            expected_status='complete'
        elif last_outcome=='success':
            expected_status='budget_exhausted';expected_derived['failed_stage']='verifier'
        else:
            expected_status=last_outcome;expected_derived['failed_stage']=row_attempts[-1]['stage']
        if row['status']!=expected_status or any(row.get(key)!=value for key,value in expected_derived.items()) or (
                set(row)&derived_row)!=set(expected_derived):
            raise ValueError('Identified metrics fields disagree with raw stage answers')
    if (type(raw.get('calls')) is not int or raw['calls']!=attempts
            or raw['calls']>limits['max_calls'] or raw['calls']>20):
        raise ValueError('Identified call count differs from recorded attempts or exceeds cap')
    if raw.get('status')!=('complete' if len(raw['rows'])==len(payloads) and all(
            row['status']=='complete' for row in raw['rows']) else 'incomplete'):
        raise ValueError('Identified run status differs from row completion')


def has_identified_marker(row):
    if type(row) is not dict:
        return False
    if 'identity_view' in row or 'identity_payload_sha256' in row:
        return True
    attempts=row.get('attempts')
    return type(attempts) is list and any(type(attempt) is dict and
        'source_identity' in str(attempt.get('prompt','')) for attempt in attempts)

def apply_overlay(raw,overlay,raw_sha256):
    if set(overlay)!={'schema','raw_sha256','reviewer','decisions'} or overlay['schema']!='adjudication-overlay-v1':
        raise ValueError('Unsupported overlay schema')
    if overlay['raw_sha256']!=raw_sha256: raise ValueError('Overlay does not bind this immutable raw file')
    if not isinstance(overlay['reviewer'],str) or not overlay['reviewer'].strip(): raise ValueError('Independent reviewer required')
    result=copy.deepcopy(raw)
    rows={row['id']:row for row in result['rows']}
    seen=set()
    for decision in overlay['decisions']:
        if set(decision)!={'id','fingerprint','adjudication','detection_adjudication','reason'}:
            raise ValueError('Exact adjudication decision fields required')
        case_id=decision['id']
        if case_id not in rows or case_id in seen: raise ValueError('Unknown or duplicate adjudication id')
        seen.add(case_id)
        row=rows[case_id]
        if decision['fingerprint']!=row['fingerprint']: raise ValueError('Candidate fingerprint mismatch')
        if not isinstance(decision['reason'],str) or not decision['reason'].strip(): raise ValueError('Review evidence reason required')
        if any(decision[key] not in ['TP','FP','U'] for key in ['adjudication','detection_adjudication']):
            raise ValueError('Unfilled or unknown adjudication decision')
        if row.get('status')!='complete' or not row.get('surfaced'):
            raise ValueError('Surface overlay requires an actually surfaced candidate')
        row.update(adjudication=decision['adjudication'],detection_adjudication=decision['detection_adjudication'],
                   adjudication_reviewer=overlay['reviewer'],adjudication_reason=decision['reason'])
    return result

def aggregate(raw_path,denominator_path,overlay_path=None,identity_binding_path=None):
    raw_path=Path(raw_path)
    raw_bytes=read_regular(raw_path.absolute(),16*1024*1024)
    raw_sha256=hashlib.sha256(raw_bytes).hexdigest()
    raw=json.loads(raw_bytes)
    if raw.get('schema')=='formal-experiment-v1':
        if overlay_path is not None or identity_binding_path is not None:
            raise ValueError('Formal stage overlays and identity bindings require the formal reader')
        from transport import project_formal_report
        report=project_formal_report(raw_path,denominator_path)
        if report['raw_sha256']!=raw_sha256:
            raise ValueError('Formal raw changed after classification')
        return report
    frozen=json.loads(read_regular(Path(denominator_path).absolute(),2*1024*1024))
    validate_frozen_canonical(frozen,read_regular(canonical_path_for_denominator(denominator_path).absolute(),2*1024*1024))
    if raw.get('schema')!='vettalon-synthetic-twins-v1' or 'rows' not in raw: raise ValueError('Unsupported raw schema')
    if raw['frozen_denominator_sha256']!=digest(frozen): raise ValueError('Frozen denominator fingerprint mismatch')
    payloads,labels=generate()
    scope=raw.get('scope_manifest')
    if scope is not None and raw.get('scope_manifest_sha256')!=digest(scope): raise ValueError('Subset manifest digest mismatch')
    payloads,labels=select_scope(payloads,labels,scope)
    view=raw.get('identity_view','anonymous')
    if view=='identified':
        verify_identified_lineage(raw,payloads,labels,identity_binding_path)
    elif view!='anonymous' or raw.get('identity_lineage') is not None or identity_binding_path is not None:
        raise ValueError('Anonymous or historical raw cannot claim an identified binding')
    elif ((type(raw.get('implementation')) is dict and 'identity_views_sha256' in raw['implementation'])
          or any(has_identified_marker(row) for row in raw['rows'])):
        raise ValueError('Identified row or prompt cannot be downgraded to anonymous raw')
    eligible_pairs=sorted({x['pair_id'] for x in labels if x['vulnerable']} & set(frozen['eligible_pairs']))
    by_id={x['id']:x for x in payloads}
    for row in raw['rows']:
        if row['id'] not in by_id or row['source_sha256']!=by_id[row['id']]['source_sha256']:
            raise ValueError('Unknown case or source mismatch')
    overlay=None
    if overlay_path:
        overlay_bytes=read_regular(Path(overlay_path).absolute(),1024*1024)
        overlay=json.loads(overlay_bytes)
        raw=apply_overlay(raw,overlay,raw_sha256)
    return {'overlay_file':str(overlay_path) if overlay_path else None,'overlay_sha256':hashlib.sha256(overlay_bytes).hexdigest() if overlay_path else None,'reviewer':overlay['reviewer'] if overlay else None,'kind':'recomputed-metrics','raw_file':raw_path.name,'raw_sha256':raw_sha256,
            'aggregator_sha256':digest(Path(__file__).read_text()),'measurement_sha256':digest(Path(__file__).with_name('measurement.py').read_text()),'protocol_sha256':digest(Path(__file__).with_name('protocol.py').read_text()),
            'metrics':metrics(labels,raw['rows'],eligible_pairs,raw.get('resource_evidence'),raw.get('implementation'))}


def aggregate_formal_batch(raw_paths, denominator_path, ledger_path):
    """Reconcile all supplied formal runs against one durable D01 ledger."""
    from ledger import read_regular, reconcile_debits, schedule, validate_plan
    from transport import project_formal_report
    planned=schedule()
    if not raw_paths or len(raw_paths)>planned['runs']:
        raise ValueError('One to fifteen formal raw run paths required')
    seen=set(); plan=None; attempts=[]; reports=[]
    expected_keys={slot['attempt_key'] for slot in planned['slots']}
    for path in raw_paths:
        checked=project_formal_report(path,denominator_path)
        raw_bytes=read_regular(Path(path).absolute(),16*1024*1024)
        if hashlib.sha256(raw_bytes).hexdigest()!=checked['raw_sha256']:
            raise ValueError('Formal raw changed after its reader validation')
        raw=json.loads(raw_bytes)
        prepared=raw['prepared']
        key=(prepared['arm'],prepared['repeat'])
        if key in seen or key[0] not in ('finder-only','samefamily','crossfamily') or type(key[1]) is not int or not 0<=key[1]<=4:
            raise ValueError('Duplicate or foreign formal arm/repeat')
        seen.add(key)
        current=raw['budget_plan']
        validate_plan(current,planned)
        if plan is not None and current!=plan:
            raise ValueError('Formal runs do not share a single frozen batch plan')
        plan=current
        for row in raw['rows']:
            for attempt in row['attempts']:
                if attempt['attempt_key'] not in expected_keys:
                    raise ValueError('Attempt is outside the fixed D01 batch schedule')
                attempts.append(attempt)
        reports.append(checked)
    ledger=reconcile_debits(plan,planned,ledger_path,attempts)
    unknown_input=sum(report['observed']['unknown_input_attempts'] for report in reports)
    unknown_output=sum(report['observed']['unknown_output_attempts'] for report in reports)
    known_input=sum(report['observed']['known_input_tokens'] for report in reports)
    known_output=sum(report['observed']['known_output_tokens'] for report in reports)
    all_client_entries = (len(attempts)==250 and all(
        type(attempt.get('worker_invocations')) is int and attempt['worker_invocations']==1
        and type(attempt.get('client_request_entries')) is int and attempt['client_request_entries']==1
        for attempt in attempts))
    all_dispatch_entries = (ledger['recorded_debits']==250 and ledger['recorded_dispatch_entries']==250
                            and ledger['raw_attempts_bound']==250)
    return {'schema':'twins-formal-batch-audit-v1','status':'complete' if len(seen)==15 and len(attempts)==250 and ledger['reconciled']
            and all_client_entries and all_dispatch_entries
            and all(report['raw_status']=='complete' and report['metrics']['incomplete']==0 for report in reports) else 'incomplete',
            'requested':{'runs':15,'calls':250,'output_tokens_per_call':1024,'total_output_reservation':256000,
                         'automatic_retries':0,'inflight':1},
            'enforced':{'supplied_runs':len(seen),'raw_attempts':len(attempts),'ledger':ledger,
                        'all_client_entries_recorded':all_client_entries,
                        'all_dispatch_entries_bound':all_dispatch_entries,
                        'provider_output_cap_independently_verified':None,
                        'provider_internal_retry_control_verified':None},
            'observed':{'input_tokens':known_input if attempts and unknown_input==0 else None,
                        'output_tokens':known_output if attempts and unknown_output==0 else None,
                        'known_input_tokens':known_input,'known_output_tokens':known_output,
                        'unknown_input_attempts':unknown_input,'unknown_output_attempts':unknown_output,
                        'provider_attempts':None,'usd':None,'human_minutes':None},
            'run_raw_sha256':[report['raw_sha256'] for report in reports],
            'context_evidence_gap':{'status':'not-measured','reason':'No exploration trace or gold role-tagged context blocks'}}

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--raw',type=Path,default=ARTIFACTS/'local-pilot.json')
    parser.add_argument('--denominator',type=Path,default=ARTIFACTS/'denominator.json')
    parser.add_argument('--overlay',type=Path)
    parser.add_argument('--identity-binding-path',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    report=aggregate(args.raw,args.denominator,args.overlay,args.identity_binding_path)
    with args.output.open('x') as handle: json.dump(report,handle,indent=2); handle.write('\n')
