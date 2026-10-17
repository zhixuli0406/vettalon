import unittest
import hashlib, inspect
from refute import classify, run_cases, process

class RefuteTests(unittest.TestCase):
    def proof(self):
        return {'language_supported':True,'scope_complete':True,'policy_known':True,'security_effect':False,
                'normal_control':True,'source_sha256':hashlib.sha256(inspect.getsource(process).encode()).hexdigest(),'replay_success':True,'oracle_contract':'synthetic-owner-v1'}
    def test_deployment_unknown_never_code_safe(self):
        proof=self.proof(); proof['policy_known']=False
        self.assertEqual(classify(proof),'deployment-unknown')
    def test_missing_path_never_code_safe(self):
        proof=self.proof(); proof['scope_complete']=False
        self.assertEqual(classify(proof),'missing-path')
    def test_unsupported_and_failed_oracle_never_code_safe(self):
        proof=self.proof(); proof['language_supported']=False
        self.assertEqual(classify(proof),'unsupported')
        proof=self.proof(); proof['normal_control']=False
        self.assertEqual(classify(proof),'incomplete')
    def test_positive_counterpart_survives(self):
        proof=self.proof(); proof['security_effect']=True
        self.assertEqual(classify(proof),'candidate-survives')
    def test_safe_requires_contract_replay_and_hash(self):
        self.assertEqual(classify(self.proof()),'code-safe-within-fixture-contract')
        for key in ['source_sha256','oracle_contract']:
            proof=self.proof(); proof.pop(key)
            self.assertEqual(classify(proof),'incomplete')
    def test_eight_cases_have_actual_effect_and_normal_controls(self):
        result=run_cases()
        self.assertEqual(len(result['rows']),8)
        self.assertEqual(sum(r['observed']['security_effect'] for r in result['rows']),4)
        self.assertTrue(all(r['observed']['normal_control'] for r in result['rows']))
        self.assertTrue(all(r['matched_expected'] for r in result['rows']))
