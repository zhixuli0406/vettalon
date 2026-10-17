"""Pure synthetic source attribution contracts; no model, Docker, or filesystem claims."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('frozen_twins_protocol', HERE/'protocol.py')
protocol = importlib.util.module_from_spec(spec); spec.loader.exec_module(protocol)


class IdentityViewTests(unittest.TestCase):
    def setUp(self):
        path = HERE/'identity_views.py'
        self.assertTrue(path.is_file(), 'Identity view module is not implemented yet')
        spec = importlib.util.spec_from_file_location('identity_views_under_test',path)
        self.module = importlib.util.module_from_spec(spec);spec.loader.exec_module(self.module)
        self.payloads, _ = protocol.generate()
        self.manifest_sha = 'a'*64
        self.scope = {'schema':'fixed-subset-v1','case_ids':[p['id'] for p in self.payloads],
                      'source_sha256':{p['id']:p['source_sha256'] for p in self.payloads}}
        # Declared synthetic bindings only. Tests do not pretend these files were verified.
        self.bindings = {p['id']:{'kind':'self-authored-synthetic','collection':'vettalon-self-authored-twins',
            'artifact':f"benchmarks/blind-twins/anonymous/{p['id']}.json",'source_manifest_sha256':self.manifest_sha}
            for p in self.payloads}

    def test_anonymous_default_is_exact_current_payload_and_serialization(self):
        for payload in self.payloads:
            original=copy.deepcopy(payload);view=self.module.build_view(payload)
            self.assertEqual(view,original);self.assertIsNot(view,payload)
            self.assertEqual(json.dumps(view),json.dumps(payload))
            protocol.validate_payload(view)
            self.assertTrue(self.module.validate_view(view,'anonymous',payload))
            self.assertEqual(payload,original)

    def test_identified_source_attribution_only_and_binding_required(self):
        payload=self.payloads[0];binding=self.bindings[payload['id']]
        view=self.module.build_view(payload,'identified',binding)
        self.assertEqual({k:view[k] for k in payload},payload)
        self.assertEqual(view['source_identity'],binding)
        self.assertEqual(set(view),set(payload)|{'source_identity'})
        self.assertTrue(self.module.validate_view(view,'identified',payload,self.manifest_sha))
        with self.assertRaises(ValueError):self.module.build_view(payload,'identified')
        with self.assertRaises(ValueError):self.module.build_view(payload,'original-upstream',binding)

    def test_identity_rejects_family_repository_labels_and_extra_nested_fields(self):
        payload=self.payloads[0];good=self.bindings[payload['id']]
        for field in ('repository','family','variant','split','pair_id','vulnerable','patched','oracle','label','cve','commit','note'):
            with self.subTest(field=field):
                bad=dict(good,**{field:'synthetic-object-0'})
                with self.assertRaises(ValueError):self.module.build_view(payload,'identified',bad)
        for artifact in ('/absolute/source.json','../source.json','https://upstream.example/source',
                         'benchmarks/blind-twins/anonymous/c-'+'0'*16+'.json'):
            with self.subTest(artifact=artifact),self.assertRaises(ValueError):
                self.module.build_view(payload,'identified',dict(good,artifact=artifact))

    def test_wrong_source_id_hash_digest_types_and_anonymous_extra_rejected(self):
        payload=self.payloads[0];binding=self.bindings[payload['id']]
        for field,value in [('id','plain-label'),('source',False),('source_sha256','0'*64)]:
            bad=dict(payload,**{field:value})
            with self.subTest(field=field),self.assertRaises(ValueError):self.module.build_view(bad)
        for field,value in [('kind','upstream'),('collection','synthetic-object-0'),('source_manifest_sha256',True),('source_manifest_sha256','bad')]:
            with self.subTest(field=field),self.assertRaises(ValueError):
                self.module.build_view(payload,'identified',dict(binding,**{field:value}))
        with self.assertRaises(ValueError):self.module.build_view(dict(payload,label='safe'))
        view=self.module.build_view(payload,'identified',binding)
        with self.assertRaises(ValueError):self.module.validate_view(view,'identified',payload,'b'*64)

    def test_matching_hash_does_not_bypass_frozen_base_text_leak_guard(self):
        for marker in ('CVE-2030-0001','vulnerable','patched','oracle','commit','holdout','ground-truth'):
            source='# '+marker+'\ndef process(): return None\n'
            source_hash=hashlib.sha256(source.encode()).hexdigest()
            payload={'id':'c-'+source_hash[:16],'source':source,'source_sha256':source_hash}
            binding={'kind':'self-authored-synthetic','collection':'vettalon-self-authored-twins',
                'artifact':f"benchmarks/blind-twins/anonymous/{payload['id']}.json",'source_manifest_sha256':self.manifest_sha}
            with self.subTest(marker=marker):
                with self.assertRaises(ValueError):protocol.validate_payload(payload)
                with self.assertRaises(ValueError):self.module.build_view(payload)
                with self.assertRaises(ValueError):self.module.build_view(payload,'identified',binding)
                with self.assertRaises(ValueError):self.module.validate_view(payload,'anonymous',payload)
                identified=dict(payload,source_identity=binding)
                with self.assertRaises(ValueError):self.module.validate_view(identified,'identified',payload,self.manifest_sha)
                scope={'schema':'fixed-subset-v1','case_ids':[payload['id']],
                       'source_sha256':{payload['id']:source_hash}}
                with self.assertRaises(ValueError):
                    self.module.build_paired_manifest([payload],scope,{payload['id']:binding},self.manifest_sha)

    def test_whole_twenty_and_explicit_fixed_ten_subset_both_valid(self):
        for scope in (self.scope,protocol.fixed_subset()):
            ids=set(scope['case_ids']);payloads=[p for p in self.payloads if p['id'] in ids]
            bindings={k:v for k,v in self.bindings.items() if k in ids}
            manifest=self.module.build_paired_manifest(payloads,scope,bindings,self.manifest_sha)
            self.assertEqual([r['id'] for r in manifest['cases']],scope['case_ids'])
            self.assertEqual(len(manifest['cases']),len(ids))
            self.assertEqual(manifest['scope_manifest_sha256'],protocol.digest(scope))
            self.assertEqual(manifest['source_binding_status'],'declared-only; filesystem-not-verified')
            self.assertEqual(manifest['identified_view_meaning'],'synthetic-source-attribution-only')
            self.assertTrue(self.module.validate_paired_manifest(manifest,payloads,scope,bindings,self.manifest_sha))

    def test_pair_hashes_recompute_and_no_identity_or_source_mutation(self):
        before=copy.deepcopy((self.payloads,self.scope,self.bindings))
        manifest=self.module.build_paired_manifest(self.payloads,self.scope,self.bindings,self.manifest_sha)
        for row,payload in zip(manifest['cases'],self.payloads):
            for view in ('anonymous','identified'):
                value=self.module.build_view(payload,view,self.bindings[payload['id']] if view=='identified' else None)
                raw=json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()
                self.assertEqual(row[view+'_payload_sha256'],hashlib.sha256(raw).hexdigest())
        self.assertEqual((self.payloads,self.scope,self.bindings),before)

    def test_paired_manifest_mutation_duplicate_missing_unknown_case_fail_closed(self):
        good=self.module.build_paired_manifest(self.payloads,self.scope,self.bindings,self.manifest_sha)
        for mutate in ('schema','extra','casehash','missing'):
            bad=copy.deepcopy(good)
            if mutate=='schema':bad['schema']='unknown'
            elif mutate=='extra':bad['label']='safe'
            elif mutate=='casehash':bad['cases'][0]['identified_payload_sha256']='0'*64
            else:bad['cases'].pop()
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):
                self.module.validate_paired_manifest(bad,self.payloads,self.scope,self.bindings,self.manifest_sha)
        for payloads in (self.payloads[:-1],self.payloads+[self.payloads[0]]):
            with self.assertRaises(ValueError):self.module.build_paired_manifest(payloads,self.scope,self.bindings,self.manifest_sha)
        bad_scope=copy.deepcopy(self.scope);bad_scope['case_ids'][1]=bad_scope['case_ids'][0]
        with self.assertRaises(ValueError):self.module.build_paired_manifest(self.payloads,bad_scope,self.bindings,self.manifest_sha)
        bad_bindings=copy.deepcopy(self.bindings);bad_bindings.pop(self.payloads[0]['id'])
        with self.assertRaises(ValueError):self.module.build_paired_manifest(self.payloads,self.scope,bad_bindings,self.manifest_sha)

    def test_pure_build_never_dispatches_process_network_or_reads_files(self):
        with patch('subprocess.Popen',side_effect=AssertionError('no child')) as spawn, \
             patch('urllib.request.urlopen',side_effect=AssertionError('no model/network')) as network, \
             patch('builtins.open',side_effect=AssertionError('no filesystem verification')) as files, \
             patch.object(Path,'open',side_effect=AssertionError('no filesystem verification')):
            manifest=self.module.build_paired_manifest(self.payloads,self.scope,self.bindings,self.manifest_sha)
            self.assertTrue(self.module.validate_paired_manifest(manifest,self.payloads,self.scope,self.bindings,self.manifest_sha))
            spawn.assert_not_called();network.assert_not_called();files.assert_not_called()


if __name__=='__main__':unittest.main()
