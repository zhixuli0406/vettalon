import tempfile
from pathlib import Path
import unittest
from selection import select

class SelectionTests(unittest.TestCase):
    def tree(self,path):
        (path/'entry.py').write_text('from storage import read_record\ndef route(name):\n    return read_record(name)\n')
        (path/'storage.py').write_text('from pathlib import Path\ndef read_record(name):\n    return Path(name).read_text()\n')

    def test_cross_file_call_path_and_hash(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); self.tree(root)
            result=select(root,mode='callchain')
            self.assertIn('entry.route',result['selected_functions'])
            self.assertIn('storage.read_record',result['selected_functions'])
            self.assertEqual(result['edges'],[['entry.route','storage.read_record']])
            self.assertTrue(all(x['source_sha256'] and x['ranges'] for x in result['files']))

    def test_parser_failure_preserved_as_fallback(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); (root/'bad.py').write_text('def broken(\n')
            result=select(root,mode='callchain')
            self.assertEqual(result['files'][0]['status'],'parser_fallback')
            self.assertTrue(result['incomplete'])

    def test_unknown_sink_not_silently_deleted(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); (root/'x.py').write_text('def process(x):\n    return plugin(x)\n')
            r=select(root,mode='callchain')
            self.assertIn('x.process',r['selected_functions'])
            self.assertIn('x.process',r['unknown_calls'])

    def test_hard_cap_and_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for i in range(45): (root/f'x{i:02d}.py').write_text('def a(x):\n    return x\n')
            r=select(root,max_modules=0,byte_budget=80)
            self.assertEqual(len(r['files']),40)
            self.assertEqual(len(r['omitted_modules']),5)
            self.assertLessEqual(r['selected_bytes'],80)
            self.assertTrue(r['incomplete'])

    def test_symlink_escapes_not_read(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); (root/'host.py').symlink_to('/etc/passwd')
            r=select(root)
            self.assertEqual(r['files'][0]['status'],'symlink_skipped')

if __name__=='__main__': unittest.main()

class ImmutableOutputTests(unittest.TestCase):
    def test_existing_output_refused_before_reading_fixture(self):
        import selection
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'existing.json';out.write_bytes(b'preserve original')
            with patch.object(selection,'select',side_effect=AssertionError('must not select')):
                with self.assertRaises(FileExistsError): selection.write_result(Path('/missing-input'),'baseline',out)
            self.assertEqual(out.read_bytes(),b'preserve original')
