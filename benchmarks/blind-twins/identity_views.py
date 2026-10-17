"""Pure identified synthetic source attribution, not recovered upstream identity.

Callers must first check the actual materialized source and manifest bytes before
passing their declared bindings here. These functions verify data consistency,
not filesystem existence, provenance authenticity, or contamination effects.
They never dispatch inference, select a budget, write artifacts, or read labels.
"""
import hashlib
import json
import re


def build_view(payload, view='anonymous', identity_binding=None):
    """Preserve the anonymous default; identified needs an explicit declared binding."""
    validate_view(payload, 'anonymous', payload)
    if view == 'anonymous':
        if identity_binding is not None:
            raise ValueError('Anonymous view does not accept identity metadata')
        return dict(payload)
    if view != 'identified' or type(identity_binding) is not dict:
        raise ValueError('Identified synthetic source attribution needs an explicit binding')
    result = dict(payload, source_identity=dict(identity_binding))
    validate_view(result, view, payload, identity_binding.get('source_manifest_sha256'))
    return result


def validate_view(payload, view, expected_case, source_manifest_sha256=None):
    """Check declared data against caller-checked source; no files are inspected."""
    base = {'id', 'source', 'source_sha256'}
    if view not in ('anonymous', 'identified'):
        raise ValueError('Unsupported identity view')
    if type(expected_case) is not dict or set(expected_case) != base:
        raise ValueError('Expected an exact anonymous source record')
    if (type(payload) is not dict or set(payload) != (base if view == 'anonymous' else base | {'source_identity'})
            or not all(type(expected_case[k]) is str for k in base)
            or not re.fullmatch(r'c-[0-9a-f]{16}', expected_case['id'])
            or not re.fullmatch(r'[0-9a-f]{64}', expected_case['source_sha256'])):
        raise ValueError('Invalid source record or unexpected identity fields')
    try:
        actual_hash = hashlib.sha256(expected_case['source'].encode('utf-8', 'strict')).hexdigest()
    except UnicodeError as error:
        raise ValueError('Source is not strict UTF-8') from error
    if actual_hash != expected_case['source_sha256'] or any(
            type(payload[k]) is not str or payload[k] != expected_case[k] for k in base):
        raise ValueError('Identity view changed the expected source, id, or hash')
    base_payload = {key: payload[key] for key in ('id', 'source', 'source_sha256')}
    # Preserve the frozen anonymous text guard before considering identity metadata.
    if re.search(r'cve-|vulnerable|patched|oracle|commit|holdout|ground.truth', json.dumps(base_payload), re.I):
        raise ValueError('Label or identity leakage in anonymous payload')
    if view == 'identified':
        identity = payload['source_identity']
        expected_keys = {'kind', 'collection', 'artifact', 'source_manifest_sha256'}
        if (type(identity) is not dict or set(identity) != expected_keys
                or not all(type(identity[k]) is str for k in expected_keys)
                or type(source_manifest_sha256) is not str
                or not re.fullmatch(r'[0-9a-f]{64}', source_manifest_sha256)
                or identity['source_manifest_sha256'] != source_manifest_sha256
                or identity['kind'] != 'self-authored-synthetic'
                or identity['collection'] != 'vettalon-self-authored-twins'
                or identity['artifact'] != f"benchmarks/blind-twins/anonymous/{expected_case['id']}.json"):
            raise ValueError('Invalid declared synthetic artifact binding; files are not verified here')
    return True


def build_paired_manifest(payloads, scope_manifest, identity_bindings, source_manifest_sha256):
    """Bind both views of every case in the explicit full or subset scope, without dispatch."""
    if (type(source_manifest_sha256) is not str or not re.fullmatch(r'[0-9a-f]{64}', source_manifest_sha256)
            or type(scope_manifest) is not dict
            or set(scope_manifest) != {'schema', 'case_ids', 'source_sha256'}
            or scope_manifest['schema'] != 'fixed-subset-v1'
            or type(scope_manifest['case_ids']) is not list or not scope_manifest['case_ids']
            or not all(type(i) is str and re.fullmatch(r'c-[0-9a-f]{16}', i) for i in scope_manifest['case_ids'])
            or len(set(scope_manifest['case_ids'])) != len(scope_manifest['case_ids'])
            or type(scope_manifest['source_sha256']) is not dict
            or set(scope_manifest['source_sha256']) != set(scope_manifest['case_ids'])
            or not all(type(h) is str and re.fullmatch(r'[0-9a-f]{64}', h) for h in scope_manifest['source_sha256'].values())
            or type(payloads) is not list or type(identity_bindings) is not dict
            or set(identity_bindings) != set(scope_manifest['case_ids'])):
        raise ValueError('Invalid explicit scope or declared source bindings')
    cases = {}
    for payload in payloads:
        validate_view(payload, 'anonymous', payload)
        if payload['id'] in cases:
            raise ValueError('Duplicate source case')
        cases[payload['id']] = payload
    if set(cases) != set(scope_manifest['case_ids']):
        raise ValueError('Source records must exactly cover the explicit scope')
    rows = []
    for case_id in scope_manifest['case_ids']:
        payload = cases[case_id]
        if scope_manifest['source_sha256'][case_id] != payload['source_sha256']:
            raise ValueError('Scope source hash mismatch')
        anonymous = build_view(payload)
        identified = build_view(payload, 'identified', identity_bindings[case_id])
        validate_view(identified, 'identified', payload, source_manifest_sha256)
        rows.append({
            'id': case_id, 'source_sha256': payload['source_sha256'],
            'anonymous_payload_sha256': hashlib.sha256(json.dumps(
                anonymous, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()).hexdigest(),
            'identified_payload_sha256': hashlib.sha256(json.dumps(
                identified, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()).hexdigest(),
        })
    return {
        'schema': 'twins-identity-pairs-v1', 'views': ['anonymous', 'identified'],
        'identified_view_meaning': 'synthetic-source-attribution-only',
        'source_binding_status': 'declared-only; filesystem-not-verified',
        'source_manifest_sha256': source_manifest_sha256,
        # Same semantic scope digest as the frozen protocol, not a raw-file digest.
        'scope_manifest_sha256': hashlib.sha256(json.dumps(scope_manifest, sort_keys=True).encode()).hexdigest(),
        'payload_serialization': 'JSON sort_keys=true ensure_ascii=false separators=comma-colon UTF-8',
        'cases': rows,
    }


def validate_paired_manifest(manifest, payloads, scope_manifest, identity_bindings, source_manifest_sha256):
    """Recompute exact paired data; this does not validate a filesystem witness."""
    expected = build_paired_manifest(payloads, scope_manifest, identity_bindings, source_manifest_sha256)
    if type(manifest) is not dict or manifest != expected:
        raise ValueError('Paired manifest does not match both views of the exact declared scope')
    return True
