"""Offline one-view runner contracts; no model provider or Docker calls."""
import copy
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import protocol
import aggregate
import rehearse
import run


class IdentityRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name).resolve()
        self.materialized=self.root/'materialized'
        (self.materialized/'anonymous').mkdir(parents=True)
        all_payloads,labels=protocol.generate()
        manifest={'schema':protocol.SCHEMA,
                  'cases':[{'id':p['id'],'source_sha256':p['source_sha256']} for p in all_payloads],
                  'synthetic':True,'count':len(all_payloads)}
        (self.materialized/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
        for payload in all_payloads:
            (self.materialized/'anonymous'/f"{payload['id']}.json").write_text(json.dumps(payload,indent=2)+'\n')
        (self.materialized/'fixed-five-pair-subset.json').write_text(json.dumps(protocol.fixed_subset(),indent=2)+'\n')
        self.evidence=self.root/'evidence'
        self.evidence.mkdir()
        canonical=json.dumps({'kind':'unit-fixture-only','no-oracle-executed':True})+'\n'
        (self.evidence/'canonical-oracle.json').write_text(canonical)
        pairs=sorted({x['pair_id'] for x in labels})
        frozen={'schema':protocol.SCHEMA,'canonical_sha256':protocol.digest(canonical),
                'manifest_sha256':protocol.digest(labels),'positive_denominator':len(labels)//2,
                'canonical_rebuildable_denominator':0,'eligible_pairs':[],
                'excluded_from_canonical_denominator':pairs,
                'note':'Unit fixture only; no canonical oracle executed.'}
        self.denominator_path=self.evidence/'denominator.json'
        self.denominator_path.write_text(json.dumps(frozen))
        for module,name,value in ((run,'ROOT',self.materialized),(run,'ARTIFACTS',self.evidence),
                                  (rehearse,'ROOT',self.materialized),(aggregate,'ROOT',self.materialized)):
            replacement=patch.object(module,name,value)
            replacement.start()
            self.addCleanup(replacement.stop)
        self.subset=self.root/'subset.json'
        self.subset.write_text(json.dumps(protocol.fixed_subset()))
        self.scope=protocol.fixed_subset()
        self.manifest_sha=hashlib.sha256((self.materialized/'manifest.json').read_bytes()).hexdigest()
        self.payloads,_=protocol.select_scope(*protocol.generate(),self.scope)
        self.bindings={p['id']:{'kind':'self-authored-synthetic',
                        'collection':'vettalon-self-authored-twins',
                        'artifact':f"benchmarks/blind-twins/anonymous/{p['id']}.json",
                        'source_manifest_sha256':self.manifest_sha} for p in self.payloads}
        self.binding_file=self.root/'bindings.json'
        self.write_bindings()

    def write_bindings(self,overrides=None):
        data={'schema':'twins-identity-bindings-v1',
              'source_manifest_sha256':self.manifest_sha,'bindings':self.bindings}
        if overrides: data.update(overrides)
        self.binding_file.write_text(json.dumps(data))

    def fake(self,model,prompt,timeout):
        self.assertNotIn('pair_id',prompt)
        self.assertNotIn('snapshot_date',prompt)
        self.assertNotIn('vulnerable',prompt)
        self.assertNotIn('synthetic-object-0',prompt)
        self.assertLessEqual(timeout,90)
        return {'message':{'content':json.dumps({'vulnerability':False,'category':'none','line':0,
                                                'evidence':'Offline stub, no model inference'})}}

    def forge_positive_canonical(self):
        payloads,labels=protocol.generate()
        canonical={'schema':protocol.SCHEMA,'kind':'canonical-oracle',
                   'planned_cases':len(payloads),'rows':[
                       {'id':payload['id'],'source_sha256':payload['source_sha256'],
                        'harness_sha256':protocol.digest(protocol.harness(payload,label)),
                        'status':'complete','oracle_pass':True,'oracle_executed':False}
                       for payload,label in zip(payloads,labels)]}
        canonical_text=json.dumps(canonical)+'\n'
        (self.evidence/'canonical-oracle.json').write_text(canonical_text)
        frozen=json.loads(self.denominator_path.read_text())
        frozen.update(canonical_sha256=protocol.digest(canonical_text),
                      eligible_pairs=sorted({label['pair_id'] for label in labels}),
                      canonical_rebuildable_denominator=10,
                      excluded_from_canonical_denominator=[])
        self.denominator_path.write_text(json.dumps(frozen))
        return frozen

    def test_forged_positive_canonical_rejected_by_mock_cli_and_aggregator(self):
        raw_path=self.root/'baseline.json'
        baseline=run.run(raw_path,subset_path=self.subset,transport=self.fake,mock=True)
        frozen=self.forge_positive_canonical()
        forged_raw=copy.deepcopy(baseline)
        forged_raw['frozen_denominator_sha256']=protocol.digest(frozen)
        aggregate_path=self.root/'forged-bound-raw.json'
        aggregate_path.write_text(json.dumps(forged_raw))
        with self.assertRaises(ValueError):
            aggregate.aggregate(aggregate_path,self.denominator_path)

        sandbox=self.root/'cli-sandbox'
        cli_dir=sandbox/'benchmarks'/'blind-twins'
        cli_dir.mkdir(parents=True)
        for source in HERE.glob('*.py'):
            shutil.copy2(source,cli_dir/source.name)
        cli_artifacts=sandbox/'reports'/'evidence-acceptance'/'experiments'
        cli_artifacts.mkdir(parents=True)
        shutil.copy2(self.evidence/'canonical-oracle.json',cli_artifacts/'canonical-oracle.json')
        shutil.copy2(self.denominator_path,cli_artifacts/'denominator.json')
        cli_raw=sandbox/'forged-cli-raw.json'
        result=subprocess.run([sys.executable,'-B','-I','-S',str(cli_dir/'run.py'),
                               '--mock','--output',str(cli_raw),'--subset-path',str(self.subset)],
                              cwd=sandbox,capture_output=True,text=True,timeout=20)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('Canonical',result.stderr)
        self.assertFalse(cli_raw.exists())

    def test_identified_one_view_same_scope_budget_and_raw_lineage(self):
        frozen=json.loads(self.denominator_path.read_text())
        self.assertTrue(json.loads((self.evidence/'canonical-oracle.json').read_text())['no-oracle-executed'])
        self.assertEqual(frozen['eligible_pairs'],[])
        self.assertEqual(frozen['canonical_rebuildable_denominator'],0)
        self.assertEqual(len(frozen['excluded_from_canonical_denominator']),10)
        results=[]
        for arm in ('finder-only','samefamily','crossfamily'):
            extra={} if arm=='finder-only' else {'verifier_model':'mock-verifier',
                          'verifier_family':'qwen' if arm=='samefamily' else 'other'}
            captured=[]
            def fake(model,prompt,timeout):
                captured.append(prompt)
                return self.fake(model,prompt,timeout)
            raw_path=self.root/f'{arm}.json'
            result=run.run(raw_path,arm=arm,model='mock-finder',subset_path=self.subset,
                           transport=fake,mock=True,identity_view='identified',
                           identity_binding_path=self.binding_file,**extra)
            results.append(result)
            self.assertEqual(len(result['rows']),10)
            self.assertEqual(result['identity_view'],'identified')
            self.assertEqual(result['metrics']['positive_denominator'],5)
            self.assertEqual(result['metrics']['safe_denominator'],5)
            self.assertEqual(result['metrics']['canonical_rebuildable_denominator'],0)
            self.assertIsNone(result['metrics']['exploit_validated_recall'])
            self.assertEqual(result['scope_manifest_sha256'],protocol.digest(self.scope))
            self.assertEqual(result['identity_lineage']['source_manifest_sha256'],self.manifest_sha)
            self.assertEqual(result['identity_lineage']['binding_file_sha256'],hashlib.sha256(self.binding_file.read_bytes()).hexdigest())
            self.assertEqual(result['identity_lineage']['source_binding_status'],
                             'materialized-locally-verified; not upstream-authenticated')
            self.assertEqual(len(result['identity_lineage']['paired_manifest']['cases']),10)
            self.assertEqual(json.loads(raw_path.read_text()),result)
            self.assertTrue(all('source_identity' in prompt for prompt in captured))
            self.assertTrue(all(row['identity_view']=='identified' and len(row['identity_payload_sha256'])==64
                                for row in result['rows']))
            self.assertEqual(sum(len(row['attempts']) for row in result['rows']),result['calls'])
            recomputed=aggregate.aggregate(raw_path,self.denominator_path,
                                            identity_binding_path=self.binding_file)
            self.assertEqual(recomputed['metrics']['positive_denominator'],5)
            self.assertEqual(recomputed['metrics']['canonical_rebuildable_denominator'],0)
        self.assertEqual([r['calls'] for r in results],[10,20,20])
        self.assertEqual({r['scope_manifest_sha256'] for r in results},{protocol.digest(self.scope)})

    def test_aggregator_rejects_identified_lineage_and_prompt_mutations(self):
        raw_path=self.root/'raw-identified.json'
        baseline=run.run(raw_path,subset_path=self.subset,transport=self.fake,mock=True,
                         identity_view='identified',identity_binding_path=self.binding_file)
        with self.assertRaises(ValueError):
            aggregate.aggregate(raw_path,self.denominator_path)
        mutations=('source_manifest','binding_sha','paired_hash','row_payload','row_fingerprint',
                   'prompt','prompt_sha','parsed','source_identity','calls','complete_attempt')
        for name in mutations:
            bad=copy.deepcopy(baseline)
            if name=='source_manifest':bad['identity_lineage']['source_manifest_sha256']='0'*64
            elif name=='binding_sha':bad['identity_lineage']['binding_file_sha256']='0'*64
            elif name=='paired_hash':bad['identity_lineage']['paired_manifest']['cases'][0]['identified_payload_sha256']='0'*64
            elif name=='row_payload':bad['rows'][0]['identity_payload_sha256']='0'*64
            elif name=='row_fingerprint':bad['rows'][0]['fingerprint']='0'*64
            elif name=='prompt':bad['rows'][0]['attempts'][0]['prompt']='changed prompt'
            elif name=='prompt_sha':bad['rows'][0]['attempts'][0]['prompt_sha256']='0'*64
            elif name=='parsed':bad['rows'][0]['attempts'][0]['parsed']['evidence']='forged'
            elif name=='source_identity':bad['rows'][0]['attempts'][0]['prompt']+='\nsource_identity: upstream'
            elif name=='calls':bad['calls']+=1
            else:bad['rows'][0]['attempts'].clear()
            target=self.root/f'tampered-{name}.json'
            target.write_text(json.dumps(bad))
            with self.subTest(name=name),self.assertRaises(ValueError):
                aggregate.aggregate(target,self.denominator_path,identity_binding_path=self.binding_file)
        downgraded=copy.deepcopy(baseline)
        downgraded.pop('identity_view');downgraded.pop('identity_lineage')
        downgraded_path=self.root/'downgraded.json'
        downgraded_path.write_text(json.dumps(downgraded))
        with self.assertRaises(ValueError):
            aggregate.aggregate(downgraded_path,self.denominator_path)
        other_binding=self.root/'other-binding.json'
        other_binding.write_text(json.dumps({'schema':'twins-identity-bindings-v1',
             'source_manifest_sha256':self.manifest_sha,'bindings':{}}))
        with self.assertRaises(ValueError):
            aggregate.aggregate(raw_path,self.denominator_path,identity_binding_path=other_binding)

    def test_aggregator_recomputes_metrics_fields_from_raw_answer(self):
        raw_path=self.root/'metrics-baseline.json'
        baseline=run.run(raw_path,subset_path=self.subset,transport=self.fake,mock=True,
                         identity_view='identified',identity_binding_path=self.binding_file)
        _,labels=protocol.select_scope(*protocol.generate(),self.scope)
        positive_index=next(i for i,label in enumerate(labels) if label['vulnerable'])
        self.assertEqual(baseline['metrics']['synthetic_label_match_detection_proxy'],0)
        mutations=('detected','surfaced','root_cause_correct','finder_candidate','adjudication',
                   'detection_adjudication','differential_oracle','cache','retry_count','status','extra_metric')
        for name in mutations:
            bad=copy.deepcopy(baseline)
            row=bad['rows'][positive_index]
            if name=='detected':row['detected']=True
            elif name=='surfaced':row['surfaced']=True
            elif name=='root_cause_correct':row['root_cause_correct']=True
            elif name=='finder_candidate':row['finder_candidate']['vulnerability']=True
            elif name=='adjudication':row['adjudication']='TP'
            elif name=='detection_adjudication':row['detection_adjudication']='TP'
            elif name=='differential_oracle':row['differential_oracle']=True
            elif name=='cache':row['cache']=True
            elif name=='retry_count':row['retry_count']=1
            elif name=='status':row['status']='timeout'
            else:row['exploit_validated']=True
            candidate=self.root/f'metric-tamper-{name}.json';candidate.write_text(json.dumps(bad))
            with self.subTest(name=name),self.assertRaises(ValueError):
                aggregate.aggregate(candidate,self.denominator_path,
                                    identity_binding_path=self.binding_file)

    def test_aggregator_rejects_budget_forgery_and_accepts_real_incomplete_rows(self):
        raw_path=self.root/'budget-baseline.json'
        baseline=run.run(raw_path,subset_path=self.subset,transport=self.fake,mock=True,
                         identity_view='identified',identity_binding_path=self.binding_file)
        for field,value in [('max_calls',250),('timeout_seconds',9000),('output_tokens',1000000),
                            ('wall_seconds',9000),('inflight',2),('automatic_retry',1),
                            ('max_calls',1)]:
            bad=copy.deepcopy(baseline);bad['limits'][field]=value
            candidate=self.root/f'budget-tamper-{field}-{value}.json';candidate.write_text(json.dumps(bad))
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):
                aggregate.aggregate(candidate,self.denominator_path,
                                    identity_binding_path=self.binding_file)
        for field,value in [('max_output_tokens',1000000),('timeout_seconds',9000)]:
            bad=copy.deepcopy(baseline);bad['rows'][0]['attempts'][0][field]=value
            candidate=self.root/f'attempt-tamper-{field}.json';candidate.write_text(json.dumps(bad))
            with self.subTest(field=field),self.assertRaises(ValueError):
                aggregate.aggregate(candidate,self.denominator_path,
                                    identity_binding_path=self.binding_file)
        low_budget=self.root/'incomplete-budget.json'
        partial=run.run(low_budget,arm='samefamily',verifier_model='mock-verifier',
                        verifier_family='qwen',subset_path=self.subset,transport=self.fake,mock=True,
                        max_calls=1,identity_view='identified',identity_binding_path=self.binding_file)
        self.assertEqual(partial['calls'],1)
        self.assertEqual(partial['status'],'incomplete')
        self.assertEqual(aggregate.aggregate(low_budget,self.denominator_path,
                          identity_binding_path=self.binding_file)['metrics']['incomplete'],10)
        def timeout(*args,**kwargs): raise TimeoutError('controlled')
        timeout_path=self.root/'timeout.json'
        timed=run.run(timeout_path,subset_path=self.subset,transport=timeout,mock=True,
                      max_calls=1,identity_view='identified',identity_binding_path=self.binding_file)
        self.assertEqual(timed['rows'][0]['status'],'timeout')
        self.assertEqual(aggregate.aggregate(timeout_path,self.denominator_path,
                          identity_binding_path=self.binding_file)['metrics']['incomplete'],10)

    def test_positive_two_stage_proxy_and_verifier_parent_are_recomputed(self):
        _,labels=protocol.select_scope(*protocol.generate(),self.scope)
        positive=next(label for label in labels if label['vulnerable'])
        def one_positive(model,prompt,timeout):
            selected=f'"id": "{positive["id"]}"' in prompt
            return {'message':{'content':json.dumps({'vulnerability':selected,
                'category':positive['family'] if selected else 'none',
                'line':1 if selected else 0,'evidence':'controlled synthetic answer'})}}
        raw_path=self.root/'positive-two-stage.json'
        raw=run.run(raw_path,arm='samefamily',verifier_model='mock-verifier',verifier_family='qwen',
                    subset_path=self.subset,transport=one_positive,mock=True,
                    identity_view='identified',identity_binding_path=self.binding_file)
        row=next(row for row in raw['rows'] if row['id']==positive['id'])
        self.assertTrue(row['detected'])
        self.assertTrue(row['surfaced'])
        self.assertTrue(row['root_cause_correct'])
        self.assertEqual(row['verifier_parent_sha256'],protocol.digest(row['finder_candidate']))
        recomputed=aggregate.aggregate(raw_path,self.denominator_path,
                                     identity_binding_path=self.binding_file)['metrics']
        self.assertEqual(recomputed['synthetic_label_match_detection_proxy'],.2)
        self.assertEqual(recomputed['canonical_rebuildable_denominator'],0)
        self.assertIsNone(recomputed['exploit_validated_recall'])
        bad=copy.deepcopy(raw);next(row for row in bad['rows'] if row['id']==positive['id'])['verifier_parent_sha256']='0'*64
        changed=self.root/'wrong-parent.json';changed.write_text(json.dumps(bad))
        with self.assertRaises(ValueError):
            aggregate.aggregate(changed,self.denominator_path,identity_binding_path=self.binding_file)

    def test_full_twenty_identified_scope_recomputes_without_private_assets(self):
        all_payloads,_=protocol.generate()
        self.bindings={p['id']:{'kind':'self-authored-synthetic',
                       'collection':'vettalon-self-authored-twins',
                       'artifact':f"benchmarks/blind-twins/anonymous/{p['id']}.json",
                       'source_manifest_sha256':self.manifest_sha} for p in all_payloads}
        self.write_bindings()
        raw_path=self.root/'full.json'
        raw=run.run(raw_path,transport=self.fake,mock=True,identity_view='identified',
                    identity_binding_path=self.binding_file)
        self.assertEqual(raw['calls'],20)
        self.assertIsNone(raw['scope_manifest'])
        self.assertEqual(len(raw['identity_lineage']['paired_manifest']['cases']),20)
        recomputed=aggregate.aggregate(raw_path,self.denominator_path,
                                        identity_binding_path=self.binding_file)
        self.assertEqual(recomputed['metrics']['positive_denominator'],10)
        self.assertEqual(recomputed['metrics']['canonical_rebuildable_denominator'],0)

    def test_anonymous_default_stays_anonymous_and_binding_is_rejected(self):
        anonymous=run.run(self.root/'anonymous.json',subset_path=self.subset,transport=self.fake,mock=True)
        self.assertEqual(anonymous['identity_view'],'anonymous')
        self.assertIsNone(anonymous['identity_lineage'])
        self.assertEqual(anonymous['calls'],10)
        self.assertTrue(all('source_identity' not in a['prompt'] for r in anonymous['rows'] for a in r['attempts']))
        legacy=copy.deepcopy(anonymous)
        legacy.pop('identity_view');legacy.pop('identity_lineage');legacy.pop('verifier_model')
        old_path=self.root/'legacy-anonymous.json';old_path.write_text(json.dumps(legacy))
        self.assertEqual(aggregate.aggregate(old_path,self.denominator_path)['metrics']['positive_denominator'],5)
        out=self.root/'rejected.json'
        with self.assertRaises(ValueError):
            run.run(out,mock=True,transport=self.fake,identity_binding_path=self.binding_file)
        self.assertFalse(out.exists())

    def test_identified_nonmock_fails_before_raw_or_network(self):
        out=self.root/'nonmock.json'
        with patch.object(run.urllib.request,'urlopen',side_effect=AssertionError('network must remain unused')):
            with self.assertRaisesRegex(ValueError, 'offline mock only'):
                run.run(out,subset_path=self.subset,identity_view='identified',
                        identity_binding_path=self.binding_file)
        self.assertFalse(out.exists())

    def test_invalid_or_mismatched_binding_fails_before_raw_or_transport(self):
        mutations=[]
        data=json.loads(self.binding_file.read_text())
        bad=copy.deepcopy(data);bad['source_manifest_sha256']='0'*64;mutations.append(bad)
        bad=copy.deepcopy(data);bad['bindings'].pop(self.payloads[0]['id']);mutations.append(bad)
        bad=copy.deepcopy(data);bad['bindings']['c-'+'0'*16]=bad['bindings'][self.payloads[0]['id']];mutations.append(bad)
        bad=copy.deepcopy(data);bad['bindings'][self.payloads[0]['id']]['artifact']='private/identity-map.json';mutations.append(bad)
        bad=copy.deepcopy(data);bad['bindings'][self.payloads[0]['id']]['family']='object';mutations.append(bad)
        for index,bad in enumerate(mutations):
            with self.subTest(index=index):
                self.binding_file.write_text(json.dumps(bad))
                out=self.root/f'invalid-{index}.json'
                with patch.object(run.urllib.request,'urlopen',side_effect=AssertionError('network must remain unused')):
                    with self.assertRaises(ValueError):
                        run.run(out,subset_path=self.subset,identity_view='identified',
                                identity_binding_path=self.binding_file)
                self.assertFalse(out.exists())
        self.write_bindings()
        with self.assertRaises(ValueError):
            run.run(self.root/'missing.json',subset_path=self.subset,mock=True,
                    identity_view='identified',transport=self.fake)
        self.assertFalse((self.root/'missing.json').exists())

    def test_materialized_source_mismatch_fails_before_transport(self):
        copied=self.root/'mismatch-materialized'
        copied.mkdir()
        (copied/'anonymous').mkdir()
        (copied/'manifest.json').write_bytes((self.materialized/'manifest.json').read_bytes())
        for source in (self.materialized/'anonymous').glob('*.json'):
            (copied/'anonymous'/source.name).write_bytes(source.read_bytes())
        chosen=copied/'anonymous'/f"{self.payloads[0]['id']}.json"
        record=json.loads(chosen.read_text());record['source']='def changed(): pass\n'
        chosen.write_text(json.dumps(record))
        out=self.root/'mismatch.json'
        with patch.object(run,'ROOT',copied),patch.object(run.urllib.request,'urlopen',side_effect=AssertionError('network must remain unused')):
            with self.assertRaises(ValueError):
                run.run(out,subset_path=self.subset,identity_view='identified',identity_binding_path=self.binding_file)
        self.assertFalse(out.exists())

    def test_identified_materialized_and_binding_files_reject_symlink_or_oversize(self):
        raw_path=self.root/'bounded-baseline.json'
        run.run(raw_path,subset_path=self.subset,transport=self.fake,mock=True,
                identity_view='identified',identity_binding_path=self.binding_file)
        targets={'manifest':self.materialized/'manifest.json',
                 'source':self.materialized/'anonymous'/f"{self.payloads[0]['id']}.json",
                 'binding':self.binding_file}
        for kind,target in targets.items():
            original=target.read_bytes()
            for mutation in ('symlink','oversize'):
                with self.subTest(kind=kind,mutation=mutation):
                    target.unlink()
                    if mutation=='symlink':
                        saved=self.root/f'{kind}-saved.json'
                        saved.write_bytes(original)
                        target.symlink_to(saved)
                        error='Cannot read ordinary file'
                    else:
                        with target.open('wb') as handle:
                            handle.truncate(run.IDENTITY_SOURCE_FILE_CAP+1)
                        error='Bounded regular file required'
                    try:
                        output=self.root/f'rejected-{kind}-{mutation}.json'
                        fake=Mock(side_effect=AssertionError('transport must remain unused'))
                        with patch.object(run.urllib.request,'urlopen',
                                          side_effect=AssertionError('network must remain unused')) as network:
                            with self.assertRaisesRegex(ValueError,error):
                                run.run(output,subset_path=self.subset,transport=fake,mock=True,
                                        identity_view='identified',identity_binding_path=self.binding_file)
                        fake.assert_not_called()
                        network.assert_not_called()
                        self.assertFalse(output.exists())
                        with self.assertRaisesRegex(ValueError,error):
                            aggregate.aggregate(raw_path,self.denominator_path,
                                                identity_binding_path=self.binding_file)
                    finally:
                        target.unlink()
                        target.write_bytes(original)

    def test_rehearsal_selects_one_view_without_doubling(self):
        baseline=rehearse.rehearse(self.root/'anonymous-rehearsal')
        self.assertEqual(baseline['identity_view'],'anonymous')
        self.assertEqual(sum(row['mock_transport_invocations'] for row in baseline['rows']),250)
        self.assertEqual(baseline['real_model_calls'],0)
        self.assertEqual({row['identity_binding_file_sha256'] for row in baseline['rows']},{None})
        result=rehearse.rehearse(self.root/'rehearsal',identity_view='identified',
                                identity_binding_path=self.binding_file)
        self.assertEqual(result['identity_view'],'identified')
        self.assertEqual(len(result['rows']),15)
        self.assertEqual(sum(row['mock_transport_invocations'] for row in result['rows']),250)
        self.assertEqual(result['planned_max_output_tokens'],256000)
        self.assertEqual(result['real_model_calls'],0)
        self.assertEqual({row['identity_view'] for row in result['rows']},{'identified'})
        self.assertEqual({row['identity_binding_file_sha256'] for row in result['rows']},
                         {hashlib.sha256(self.binding_file.read_bytes()).hexdigest()})
        with self.assertRaises(ValueError):
            rehearse.rehearse(self.root/'no-binding',identity_view='identified')
        self.assertFalse((self.root/'no-binding').exists())
        self.write_bindings({'source_manifest_sha256':'0'*64})
        with self.assertRaises(ValueError):
            rehearse.rehearse(self.root/'invalid-binding',identity_view='identified',
                              identity_binding_path=self.binding_file)
        self.assertFalse((self.root/'invalid-binding').exists())


if __name__=='__main__': unittest.main()
