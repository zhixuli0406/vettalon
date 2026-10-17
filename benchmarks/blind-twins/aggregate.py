"""Recompute adjudication-aware metrics from immutable raw records without model calls."""
import argparse
import copy
import json
from pathlib import Path
from protocol import ARTIFACTS, digest, generate, metrics, select_scope

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

def aggregate(raw_path,denominator_path,overlay_path=None):
    raw=json.loads(raw_path.read_text())
    frozen=json.loads(denominator_path.read_text())
    if raw.get('schema')!='vettalon-synthetic-twins-v1' or 'rows' not in raw: raise ValueError('Unsupported raw schema')
    if raw['frozen_denominator_sha256']!=digest(frozen): raise ValueError('Frozen denominator fingerprint mismatch')
    payloads,labels=generate()
    scope=raw.get('scope_manifest')
    if scope is not None and raw.get('scope_manifest_sha256')!=digest(scope): raise ValueError('Subset manifest digest mismatch')
    payloads,labels=select_scope(payloads,labels,scope)
    eligible_pairs=sorted({x['pair_id'] for x in labels if x['vulnerable']} & set(frozen['eligible_pairs']))
    by_id={x['id']:x for x in payloads}
    for row in raw['rows']:
        if row['id'] not in by_id or row['source_sha256']!=by_id[row['id']]['source_sha256']:
            raise ValueError('Unknown case or source mismatch')
    overlay=None
    if overlay_path:
        overlay=json.loads(overlay_path.read_text())
        raw=apply_overlay(raw,overlay,digest(raw_path.read_text()))
    return {'overlay_file':str(overlay_path) if overlay_path else None,'overlay_sha256':digest(overlay_path.read_text()) if overlay_path else None,'reviewer':overlay['reviewer'] if overlay else None,'kind':'recomputed-metrics','raw_file':raw_path.name,'raw_sha256':digest(raw_path.read_text()),
            'aggregator_sha256':digest(Path(__file__).read_text()),'measurement_sha256':digest(Path(__file__).with_name('measurement.py').read_text()),'protocol_sha256':digest(Path(__file__).with_name('protocol.py').read_text()),
            'metrics':metrics(labels,raw['rows'],eligible_pairs,raw.get('resource_evidence'),raw.get('implementation'))}

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--raw',type=Path,default=ARTIFACTS/'local-pilot.json')
    parser.add_argument('--denominator',type=Path,default=ARTIFACTS/'denominator.json')
    parser.add_argument('--overlay',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    report=aggregate(args.raw,args.denominator,args.overlay)
    with args.output.open('x') as handle: json.dump(report,handle,indent=2); handle.write('\n')
