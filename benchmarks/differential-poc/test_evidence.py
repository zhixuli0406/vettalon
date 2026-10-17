import importlib.util
import unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('evidence',Path(__file__).with_name('evidence.py'))
e=importlib.util.module_from_spec(spec); spec.loader.exec_module(e)

class EvidenceTests(unittest.TestCase):
    def test_missing_oracle_does_not_count(self):
        self.assertFalse(e.valid({'returncode':0,'status':'complete'},'hash'))
    def test_network_or_host_mounts_cannot_pass(self):
        for isolation in [{'network':'bridge'},{'network':'none','mounts':[{'Type':'bind'}]}]:
            self.assertFalse(e.valid({'isolation':isolation},'hash'))
    def test_wrong_source_hash_cannot_pass(self):
        self.assertFalse(e.valid({'source_sha256':'other'},'hash'))

if __name__=='__main__': unittest.main()

class ImmutableOutputTests(unittest.TestCase):
    def test_existing_output_refused_before_reading_raw(self):
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'existing.json';out.write_bytes(b'preserve original')
            with patch.object(e,'verify',side_effect=AssertionError('must not verify')):
                with self.assertRaises(FileExistsError): e.write_result(Path('/missing-input'),out)
            self.assertEqual(out.read_bytes(),b'preserve original')

class StrictIdentityTests(unittest.TestCase):
    def row(self):
        return {'source_sha256':'d'*64,'fresh_container':True,'status':'complete','oracle_pass':True,
                'returncode':0,'client_returncode':0,'container_id':'a'*64,'image_id':'sha256:'+'b'*64,
                'image_repo_digests':['python@sha256:'+'c'*64],
                'observed':{'normal_control':True,'security_effect':True,'uid':65534},
                'isolation':{'network':'none','read_only':True,'user':'65534:65534','cap_drop':['ALL'],'mounts':[],
                             'memory':134217728,'pids_limit':32,'nano_cpus':500000000,'security_opt':['no-new-privileges']}}
    def test_strict_codes_hashes_and_boolean_effect(self):
        self.assertTrue(e.valid(self.row(),'d'*64))
        for key,value in [('returncode',False),('client_returncode',False),('image_id','unknown'),('container_id','short'),('image_repo_digests',None)]:
            row=self.row();row[key]=value
            with self.subTest(key=key): self.assertFalse(e.valid(row,'d'*64))
        row=self.row();row['observed']['security_effect']=1
        self.assertFalse(e.valid(row,'d'*64))

    def test_mixed_image_batch_is_not_valid_differential(self):
        import tempfile,json
        payloads,labels=e.generate();rows=[]
        for index,(payload,label) in enumerate(zip(payloads,labels)):
            row=self.row();row.update(id=payload['id'],source_sha256=payload['source_sha256'],
              harness_sha256=e.digest(e.harness(payload,label)),container_id=f'{index:064x}')
            row['observed']['security_effect']=label['vulnerable']
            if index==1: row['image_id']='sha256:'+'e'*64
            rows.append(row)
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/'raw.json';source.write_text(json.dumps({'rows':rows}))
            result=e.verify(source)
            self.assertEqual(result['complete'],0)
            self.assertIsNone(result['fixed_image_id'])
