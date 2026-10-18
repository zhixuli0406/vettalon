import importlib.util
from pathlib import Path
import unittest
from fixture_support import synthetic_denominator

spec = importlib.util.spec_from_file_location('protocol', Path(__file__).with_name('protocol.py'))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


def setUpModule():
    global _unit_denominator
    _unit_denominator = synthetic_denominator()
    _unit_denominator.__enter__()


def tearDownModule():
    _unit_denominator.__exit__(None, None, None)

class ProtocolTests(unittest.TestCase):
    def test_twenty_anonymous_payloads_and_ten_pairs(self):
        payloads, labels = p.generate()
        self.assertEqual(len(payloads), 20)
        self.assertEqual(len({x['pair_id'] for x in labels}), 10)
        for row in payloads:
            p.validate_payload(row)
        self.assertFalse(any(k in str(payloads).lower() for k in ['vulnerable', 'patched', 'cve-', 'oracle', 'commit']))

    def test_splits_hold_family_repo_date(self):
        _, labels = p.generate()
        for key in ['family', 'repository', 'snapshot_date']:
            dev = {x[key] for x in labels if x['split'] == 'dev'}
            hold = {x[key] for x in labels if x['split'] == 'holdout'}
            self.assertFalse(dev & hold)

    def test_leakage_rejected(self):
        with self.assertRaises(ValueError):
            p.validate_payload({'id':'c-1', 'source':'# patched\ndef process(): pass'})

    def test_duplicate_and_unknown_results_rejected(self):
        payloads, labels = p.generate()
        row = {'id':payloads[0]['id'], 'status':'complete', 'detected':True, 'surfaced':True}
        with self.assertRaises(ValueError):
            p.metrics(labels, [row, row], [])
        with self.assertRaises(ValueError):
            p.metrics(labels, [{'id':'unknown'}], [])

    def test_missing_and_timeout_remain_in_denominator(self):
        _, labels = p.generate()
        result = p.metrics(labels, [{'id':labels[0]['id'], 'status':'timeout'}], [])
        self.assertEqual(result['positive_denominator'], 10)
        self.assertIsNone(result['detection_recall'])
        self.assertEqual(result['detection_recall_bounds'],[0,1])
        self.assertEqual(result['incomplete'], 20)
        self.assertIsNone(result['wall_p95_seconds'])

    def test_unknown_precision_bounds_and_fpr(self):
        _, labels = p.generate()
        ids = [x['id'] for x in labels if x['vulnerable']][:2]
        raw = [{'id':ids[0], 'status':'complete','detected':True,'surfaced':True,'adjudication':'TP'},
               {'id':ids[1], 'status':'complete','detected':True,'surfaced':True,'adjudication':'U'}]
        r=p.metrics(labels, raw, [])
        self.assertEqual(r['precision_bounds'], [0.5,1.0])
        self.assertEqual(r['U'],1)
        self.assertEqual(r['synthetic_label_match_detection_proxy'],0.2)
        self.assertIsNone(r['detection_recall'])
        self.assertEqual(r['detection_recall_bounds'],[0.1,1.0])
        self.assertEqual(r['adjudicated_precision'],1.0)
        self.assertEqual(r['adjudication_rate'],0.5)

    def test_exit_zero_without_effect_is_incomplete(self):
        self.assertEqual(p.evaluate_oracle({'returncode':0, 'stdout':'{}'}, True)['status'],'incomplete')

    def test_explicit_false_control_does_not_pass(self):
        r=p.evaluate_oracle({'returncode':0,'stdout':'{"security_effect":true,"normal_control":false}'},True)
        self.assertEqual(r['status'],'incomplete')

    def test_sandbox_flags_no_host_mounts(self):
        flags = p.sandbox_flags()
        self.assertIn('--read-only',flags)
        self.assertIn('none',flags)
        self.assertIn('ALL',flags)
        self.assertNotIn('-v',flags)
        self.assertNotIn('--mount',flags)

    def test_different_family_required_for_crossarm(self):
        with self.assertRaises(ValueError):
            p.validate_arm('crossfamily','qwen','qwen')
        p.validate_arm('samefamily','qwen','qwen')

if __name__=='__main__': unittest.main()

class RunnerTests(unittest.TestCase):
    def setUp(self):
        import sys
        sys.path.insert(0,str(Path(__file__).parent))
        import run
        self.run=run

    def test_parse_no_json_no_evidence_no_valid_line(self):
        self.assertIsNone(self.run.parse_answer('not json','pass'))
        self.assertIsNone(self.run.parse_answer('{"vulnerability":true,"category":"path","line":99,"evidence":"x"}','pass'))
        self.assertIsNone(self.run.parse_answer('{"vulnerability":"true"}','pass'))

    def test_zero_call_budget_denied(self):
        with self.assertRaises(ValueError): self.run.run(Path('/tmp/unused'),max_calls=0)

    def test_greater_than_hard_cap_denied(self):
        with self.assertRaises(ValueError): self.run.run(Path('/tmp/unused'),max_calls=21)

class ExecutionContractTests(unittest.TestCase):
    def setUp(self):
        import sys
        sys.path.insert(0,str(Path(__file__).parent))
        import run
        self.runner=run

    def test_mock_rows_twenty_and_no_labels_in_prompt(self):
        import tempfile
        import json
        def fake(model,prompt,timeout):
            self.assertNotIn('pair_id',prompt)
            self.assertNotIn('vulnerable',prompt)
            self.assertNotIn('snapshot_date',prompt)
            self.assertLessEqual(timeout,90)
            return {'message':{'content':json.dumps({'vulnerability':False,'category':'none','line':0,'evidence':'controlled stub'})}}
        with tempfile.TemporaryDirectory() as d:
            r=self.runner.run(Path(d).resolve()/'result.json',transport=fake,mock=True)
            self.assertEqual(r['calls'],20)
            self.assertEqual(len(r['rows']),20)
            self.assertEqual(r['metrics']['incomplete'],0)
            self.assertEqual(r['kind'],'mock-contract-only')
            self.assertIsNone(r['metrics']['exploit_validated_recall'])

    def test_one_timeout_no_retry_rest_budget_remains_denominator(self):
        import tempfile
        def fake(*args,**kwargs): raise TimeoutError('controlled')
        with tempfile.TemporaryDirectory() as d:
            r=self.runner.run(Path(d).resolve()/'result.json',transport=fake,max_calls=1,mock=True)
            self.assertEqual(r['calls'],1)
            self.assertEqual(r['rows'][0]['status'],'timeout')
            self.assertEqual(r['metrics']['incomplete'],20)

    def test_same_family_does_not_relax_crossfamily_gate(self):
        import tempfile
        import json
        def fake(*args,**kwargs):
            return {'message':{'content':json.dumps({'vulnerability':False,'category':'none','line':0,'evidence':'stub'})}}
        with tempfile.TemporaryDirectory() as d:
            r=self.runner.run(Path(d).resolve()/'result.json',arm='samefamily',verifier_model='mock',verifier_family='qwen',transport=fake,max_calls=1,mock=True)
            self.assertEqual(r['rows'][0]['status'],'budget_exhausted')
            self.assertEqual(r['metrics']['incomplete'],20)

    def test_historical_completed_row_rejected(self):
        _, labels=p.generate()
        with self.assertRaises(ValueError): p.metrics(labels,[{'id':labels[0]['id'],'status':'complete'}],[])

class ImmutableArtifactTests(unittest.TestCase):
    def test_model_unknown_fields_rejected(self):
        import sys,json
        sys.path.insert(0,str(Path(__file__).parent))
        import run
        value={'vulnerability':False,'category':'none','line':0,'evidence':'safe','extra':'unexpected'}
        self.assertIsNone(run.parse_answer(json.dumps(value),'pass'))

    def test_existing_run_is_preserved(self):
        import tempfile,sys
        sys.path.insert(0,str(Path(__file__).parent))
        import run
        with tempfile.TemporaryDirectory() as d:
            out=Path(d).resolve()/'raw.json'; out.write_text('previous raw')
            with self.assertRaises(FileExistsError): run.run(out,mock=True)
            self.assertEqual(out.read_text(),'previous raw')

    def test_existing_canonical_is_preserved_before_docker(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            out=Path(d).resolve()/'canonical-oracle.json'; out.write_text('previous raw')
            with self.assertRaises(FileExistsError): p.canonical(out)
            self.assertEqual(out.read_text(),'previous raw')

class MockedBoundaryTests(unittest.TestCase):
    def test_canonical_orchestrator_with_mocked_docker(self):
        import tempfile,json,types
        from unittest.mock import patch
        _, labels=p.generate()
        current={'index':-1}
        def check(args,**kwargs):
            if args[1:3]==['image','inspect']:
                return json.dumps([{'Id':'sha256:mock','RepoDigests':[]}])
            if args[1]=='create':
                current['index']+=1
                return 'mock-container-'+str(current['index'])
            if args[1]=='inspect':
                return json.dumps([{'State':{'ExitCode':0},'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'CapDrop':['ALL'],'Memory':134217728,'NanoCpus':500000000,'PidsLimit':32,'SecurityOpt':['no-new-privileges']},'Mounts':[],'Config':{'User':'65534:65534'}}])
            raise AssertionError(args)
        def call(args,**kwargs):
            return types.SimpleNamespace(returncode=0,stdout=json.dumps({'security_effect':labels[current['index']]['vulnerable'],'normal_control':True,'uid':65534}),stderr='')
        with tempfile.TemporaryDirectory() as d, patch.object(p.subprocess,'check_output',side_effect=check),patch.object(p.subprocess,'run',side_effect=call):
            canonical_path=Path(d).resolve()/'canonical-oracle.json'
            result=p.canonical(canonical_path)
            self.assertEqual(result['canonical_rebuildable_denominator'],10)
            self.assertEqual(current['index'],19)
            canonical=canonical_path.read_text()
            self.assertEqual(len(p.validate_frozen_canonical(result,canonical)),10)
            declared_empty=dict(result,eligible_pairs=[],canonical_rebuildable_denominator=0,
                                excluded_from_canonical_denominator=result['eligible_pairs'])
            with self.assertRaises(ValueError):
                p.validate_frozen_canonical(declared_empty,canonical)
            cleanup_failure=json.loads(canonical)
            cleanup_failure['rows'][0]['status']='incomplete'
            cleanup_failure['rows'][0]['cleanup']='failed'
            incomplete_text=json.dumps(cleanup_failure)
            excluded_pair=labels[0]['pair_id']
            incomplete_frozen=dict(result,canonical_sha256=p.digest(incomplete_text),
                                   eligible_pairs=[pair for pair in result['eligible_pairs'] if pair!=excluded_pair],
                                   canonical_rebuildable_denominator=9,
                                   excluded_from_canonical_denominator=[excluded_pair])
            self.assertEqual(len(p.validate_frozen_canonical(incomplete_frozen,incomplete_text)),9)
            for mutation in ('not_executed','wrong_harness','incomplete_pair','duplicate_case'):
                forged=json.loads(canonical)
                if mutation=='not_executed': forged['rows'][0]['oracle_executed']=False
                elif mutation=='wrong_harness': forged['rows'][0]['harness_sha256']='0'*64
                elif mutation=='incomplete_pair':
                    forged['rows'][0]['status']='incomplete';forged['rows'][0]['oracle_pass']=False
                else: forged['rows'][1]['id']=forged['rows'][0]['id']
                text=json.dumps(forged)
                frozen=dict(result,canonical_sha256=p.digest(text))
                with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                    p.validate_frozen_canonical(frozen,text)

    def test_loopback_transport_metadata_and_hashes_no_real_network(self):
        import tempfile,json,sys
        from unittest.mock import patch
        sys.path.insert(0,str(Path(__file__).parent))
        import run
        class Response:
            def __init__(self,data): self.data=data
            def __enter__(self): return self
            def __exit__(self,*args): pass
            def read(self,*args): return json.dumps(self.data).encode()
        def open_url(request,**kwargs):
            if isinstance(request,str): return Response({'models':[{'name':'qwen2.5-coder:7b','digest':'sha256:mock','details':{'family':'qwen2'}}]})
            self.assertEqual(request.full_url,'http://127.0.0.1:11434/api/chat')
            data=json.loads(request.data)
            self.assertEqual(data['options']['num_predict'],1024)
            return Response({'message':{'content':json.dumps({'vulnerability':False,'category':'none','line':0,'evidence':'transport mock'})}})
        with tempfile.TemporaryDirectory() as d, patch.object(run.urllib.request,'urlopen',side_effect=open_url):
            result=run.run(Path(d).resolve()/'raw.json')
            self.assertEqual(result['model_identity']['qwen2.5-coder:7b'],'sha256:mock')
            self.assertTrue(result['implementation']['runner_sha256'])

class AdjudicatedRecallBoundaryTests(unittest.TestCase):
    def labels(self):
        return [{'id':'positive','pair_id':'p','vulnerable':True}, {'id':'safe','pair_id':'s','vulnerable':False}]

    def test_category_mismatch_does_not_remove_semantic_tp_or_unknown_from_bounds(self):
        row={'id':'positive','status':'complete','detected':False,'surfaced':True,
             'finder_candidate':{'vulnerability':True,'category':'object'},'adjudication':'U'}
        r=p.metrics(self.labels(),[row],[])
        self.assertEqual(r['synthetic_label_match_detection_proxy'],0)
        self.assertEqual(r['detection_recall_bounds'],[0,1])
        row['detection_adjudication']='TP'; row['adjudication']='TP'
        r=p.metrics(self.labels(),[row],[])
        self.assertEqual(r['detection_recall'],1)

    def test_all_missing_not_measured_not_zero_certain(self):
        r=p.metrics(self.labels(),[],[])
        self.assertIsNone(r['detection_recall'])
        self.assertEqual(r['detection_recall_bounds'],[0,1])
        self.assertEqual(r['detection_measurement_status'],'not-measured')
        self.assertEqual(r['positive_denominator'],1)

    def test_failed_positive_incomplete_not_zero_certain(self):
        r=p.metrics(self.labels(),[{'id':'positive','status':'timeout'}],[])
        self.assertIsNone(r['detection_recall'])
        self.assertEqual(r['detection_recall_bounds'],[0,1])
        self.assertEqual(r['detection_measurement_status'],'incomplete')
        self.assertEqual(r['operational_detection_success_lower_bound'],0)

    def test_complete_negative_answer_is_observed_miss(self):
        r=p.metrics(self.labels(),[{'id':'positive','status':'complete','detected':False,'surfaced':False,
                                  'finder_candidate':{'vulnerability':False}}],[])
        self.assertEqual(r['detection_recall'],0)
        self.assertEqual(r['detection_recall_bounds'],[0,0])
        self.assertEqual(r['detection_measurement_status'],'measured')

class OverlayTests(unittest.TestCase):
    def test_wrong_raw_or_duplicate_decision_rejected(self):
        import aggregate
        raw={'rows':[{'id':'a','fingerprint':'f','status':'complete','detected':False,'surfaced':True,'finder_candidate':{'vulnerability':True}}]}
        overlay={'schema':'adjudication-overlay-v1','raw_sha256':'wrong','reviewer':'independent','decisions':[]}
        with self.assertRaises(ValueError): aggregate.apply_overlay(raw,overlay,'actual')
        overlay.update(raw_sha256='actual',decisions=[{'id':'a','fingerprint':'f','adjudication':'FP','detection_adjudication':'FP','reason':'safe boundary checked'}]*2)
        with self.assertRaises(ValueError): aggregate.apply_overlay(raw,overlay,'actual')

    def test_overlay_preserves_raw_and_does_not_filter_category_mismatch(self):
        import aggregate
        raw={'rows':[{'id':'a','fingerprint':'f','status':'complete','detected':False,'surfaced':True,'finder_candidate':{'vulnerability':True}}]}
        overlay={'schema':'adjudication-overlay-v1','raw_sha256':'actual','reviewer':'independent','decisions':[{'id':'a','fingerprint':'f','adjudication':'TP','detection_adjudication':'TP','reason':'root cause independently checked'}]}
        result=aggregate.apply_overlay(raw,overlay,'actual')
        self.assertNotIn('adjudication',raw['rows'][0])
        self.assertEqual(result['rows'][0]['detection_adjudication'],'TP')

class FixedSubsetTests(unittest.TestCase):
    def test_fixed_five_pairs_reproducible_and_hashbound(self):
        self.assertEqual(p.fixed_subset(),p.fixed_subset())
        payloads,labels=p.select_scope(*p.generate(),p.fixed_subset())
        self.assertEqual(len(payloads),10)
        self.assertEqual(sum(x['vulnerable'] for x in labels),5)
        bad=p.fixed_subset();bad['case_ids'][0]=bad['case_ids'][1]
        with self.assertRaises(ValueError): p.select_scope(*p.generate(),bad)
        bad=p.fixed_subset();bad['source_sha256'][bad['case_ids'][0]]='wrong'
        with self.assertRaises(ValueError): p.select_scope(*p.generate(),bad)

    def test_all_arms_share_subset_denominator_and_no_real_calls(self):
        import run,tempfile,json
        def fake(*args,**kwargs): return {'message':{'content':json.dumps({'vulnerability':False,'category':'none','line':0,'evidence':'contract mock'})}}
        with tempfile.TemporaryDirectory() as d:
            subset=Path(d).resolve()/'subset.json';subset.write_text(json.dumps(p.fixed_subset()))
            results=[]
            for arm in ['finder-only','samefamily','crossfamily']:
                kwargs={} if arm=='finder-only' else {'verifier_model':'mock','verifier_family':'qwen' if arm=='samefamily' else 'claude'}
                results.append(run.run(Path(d).resolve()/(arm+'.json'),arm=arm,subset_path=subset,transport=fake,mock=True,**kwargs))
            self.assertEqual([r['calls'] for r in results],[10,20,20])
            self.assertEqual({r['metrics']['positive_denominator'] for r in results},{5})
            self.assertEqual(len({r['scope_manifest_sha256'] for r in results}),1)

class ReaggregationTests(unittest.TestCase):
    def test_recompute_with_subset_and_independent_overlay(self):
        import aggregate,json,tempfile
        payloads,labels=p.select_scope(*p.generate(),p.fixed_subset())
        positive=next(x for x in labels if x['vulnerable'])['id']
        rows=[{'id':x['id'],'source_sha256':x['source_sha256'],'fingerprint':x['id'],'status':'complete',
               'detected':False,'surfaced':x['id']==positive,'finder_candidate':{'vulnerability':x['id']==positive}} for x in payloads]
        _,all_labels=p.generate()
        canonical=json.dumps({'kind':'unit-fixture-only','no-oracle-executed':True})+'\n'
        frozen={'schema':p.SCHEMA,'canonical_sha256':p.digest(canonical),
                'manifest_sha256':p.digest(all_labels),'positive_denominator':10,
                'canonical_rebuildable_denominator':0,'eligible_pairs':[],
                'excluded_from_canonical_denominator':sorted({x['pair_id'] for x in all_labels})}
        raw={'schema':p.SCHEMA,'rows':rows,'frozen_denominator_sha256':p.digest(frozen),
             'scope_manifest':p.fixed_subset(),'scope_manifest_sha256':p.digest(p.fixed_subset())}
        with tempfile.TemporaryDirectory() as d:
            base=Path(d).resolve(); source=base/'raw.json';source.write_text(json.dumps(raw));denominator=base/'denominator.json';denominator.write_text(json.dumps(frozen))
            (base/'canonical-oracle.json').write_text(canonical)
            report=aggregate.aggregate(source,denominator)
            self.assertEqual(report['metrics']['positive_denominator'],5)
            self.assertIsNone(report['metrics']['detection_recall'])
            overlay={'schema':'adjudication-overlay-v1','raw_sha256':p.digest(source.read_text()),'reviewer':'unit-test-only',
                     'decisions':[{'id':positive,'fingerprint':positive,'adjudication':'TP','detection_adjudication':'TP','reason':'Controlled test label, not a real finding.'}]}
            decision=base/'overlay.json';decision.write_text(json.dumps(overlay))
            report=aggregate.aggregate(source,denominator,decision)
            self.assertEqual(report['metrics']['detection_recall'],.2)
            self.assertEqual(json.loads(source.read_text()),raw)
            raw['rows'][0]['source_sha256']='tampered';source.write_text(json.dumps(raw))
            with self.assertRaises(ValueError): aggregate.aggregate(source,denominator)

    def test_overlay_rejects_unknown_fields_blank_review_and_wrong_candidate(self):
        import aggregate,copy
        raw={'rows':[{'id':'a','fingerprint':'f','status':'complete','surfaced':True}]}
        base={'schema':'adjudication-overlay-v1','raw_sha256':'sha','reviewer':'reviewer',
              'decisions':[{'id':'a','fingerprint':'f','adjudication':'U','detection_adjudication':'U','reason':'unknown deployment'}]}
        for mutation in ['schema','reviewer','reason','fingerprint','decision','fields','not-surfaced']:
            overlay=copy.deepcopy(base);candidate=copy.deepcopy(raw)
            if mutation=='schema': overlay['schema']='old'
            elif mutation=='reviewer': overlay['reviewer']=''
            elif mutation=='reason': overlay['decisions'][0]['reason']=''
            elif mutation=='fingerprint': overlay['decisions'][0]['fingerprint']='bad'
            elif mutation=='decision': overlay['decisions'][0]['adjudication']=None
            elif mutation=='fields': overlay['decisions'][0]['extra']='bad'
            else: candidate['rows'][0]['surfaced']=False
            with self.subTest(mutation=mutation):
                with self.assertRaises(ValueError): aggregate.apply_overlay(candidate,overlay,'sha')

class CanonicalFailureRetentionTests(unittest.TestCase):
    def test_image_and_create_failures_keep_all_twins_incomplete(self):
        import tempfile,json,subprocess
        from unittest.mock import patch
        for scenario in ['image','create']:
            def check(args,**kwargs):
                if scenario=='image': raise subprocess.CalledProcessError(1,args,output='missing image')
                if args[1:3]==['image','inspect']: return json.dumps([{'Id':'sha256:mock','RepoDigests':[]}])
                raise OSError('create unavailable')
            with self.subTest(scenario=scenario),tempfile.TemporaryDirectory() as d,patch.object(p.subprocess,'check_output',side_effect=check):
                out=Path(d).resolve()/'canonical-oracle.json'
                result=p.canonical(out)
                raw=json.loads(out.read_text())
                self.assertEqual(len(raw['rows']),20)
                self.assertTrue(all(x['status']=='incomplete' for x in raw['rows']))
                self.assertEqual(result['positive_denominator'],10)
                self.assertEqual(result['canonical_rebuildable_denominator'],0)

    def test_bool_exit_code_not_accepted(self):
        self.assertEqual(p.evaluate_oracle({'returncode':False,'stdout':'{"security_effect":true,"normal_control":true}'},True)['status'],'incomplete')

class StageAndModelIdentityTests(unittest.TestCase):
    def test_finder_failure_not_overwritten_by_two_stage_budget_label(self):
        import run,tempfile
        for kind in ['timeout','parse_failure']:
            def fake(*args,**kwargs):
                if kind=='timeout': raise TimeoutError('controlled')
                return {'message':{'content':'not JSON'}}
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as d:
                result=run.run(Path(d).resolve()/'raw.json',arm='samefamily',verifier_model='mock-verifier',verifier_family='qwen',transport=fake,mock=True)
                self.assertEqual(result['rows'][0]['status'],kind)
                self.assertEqual(result['rows'][0]['failed_stage'],'finder')

    def test_missing_verifier_or_conflicting_same_model_family_rejected_preflight(self):
        import run,tempfile
        def forbidden(*args,**kwargs): raise AssertionError('No model transport should be called')
        with tempfile.TemporaryDirectory() as d:
            for kwargs in [{'arm':'crossfamily','verifier_family':'other'},
                           {'arm':'crossfamily','model':'same-model','verifier_model':'same-model','verifier_family':'other'}]:
                with self.subTest(kwargs=kwargs):
                    with self.assertRaises(ValueError): run.run(Path(d).resolve()/'raw.json',transport=forbidden,mock=True,**kwargs)
                    self.assertFalse((Path(d).resolve()/'raw.json').exists())

    def test_real_family_mapping_does_not_trust_arm_string(self):
        import run,tempfile,json
        from unittest.mock import patch
        class Response:
            def __enter__(self): return self
            def __exit__(self,*args): pass
            def read(self,*args): return json.dumps({'models':[{'name':'qwen2.5-coder:7b','digest':'sha256:mock','details':{'family':'qwen2'}}]}).encode()
        with tempfile.TemporaryDirectory() as d,patch.object(run.urllib.request,'urlopen',return_value=Response()):
            with self.assertRaises(ValueError): run.run(Path(d).resolve()/'raw.json',finder_family='claude')
            self.assertFalse((Path(d).resolve()/'raw.json').exists())
