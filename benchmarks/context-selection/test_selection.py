import tempfile
from pathlib import Path
import unittest
import hashlib
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

    def test_class_methods_decorators_and_module_calls_are_selected(self):
        source=('from pathlib import Path\n'
                '@decorate(1)\nclass Reader:\n'
                '    @classmethod\n    def read(cls, name):\n'
                '        return Path(name).read_text()\n'
                '    def route(self, name):\n        return self.read(name)\n'
                'APP = register(Reader)\n')
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'entry.py').write_text(source)
            result=select(root,mode='callchain')
        self.assertEqual(result['edges'],[['entry.Reader.route','entry.Reader.read']])
        self.assertIn('entry.Reader.read',result['selected_functions'])
        self.assertIn('entry.Reader.route',result['selected_functions'])
        selected=''.join(item['text'] for item in result['files'][0]['ranges'])
        self.assertIn('@decorate(1)',selected)
        self.assertIn('@classmethod',selected)
        self.assertIn('APP = register(Reader)',selected)
        ranges=result['files'][0]['ranges']
        self.assertEqual(result['selected_bytes'],sum(item['end_byte']-item['start_byte'] for item in ranges))
        for index,left in enumerate(ranges):
            self.assertTrue(all(left['end_byte']<=right['start_byte'] or right['end_byte']<=left['start_byte']
                                for right in ranges[index+1:]))
        self.assertEqual(result['strategy_status'],'strategies_equivalent')
        self.assertIn('functions',result['equivalent_to'])

    def test_distinct_callchain_when_depth_excludes_entry(self):
        source=''.join(f'def f{i}():\n    return f{i+1}()\n' for i in range(5))
        source+='def f5():\n    return open("record")\n'
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'entry.py').write_text(source)
            result=select(root,mode='callchain')
        self.assertNotIn('entry.f0',result['selected_functions'])
        self.assertIn('entry.f5',result['selected_functions'])
        self.assertEqual(result['strategy_status'],'distinct')
        self.assertTrue(result['incomplete'])

    def test_byte_offsets_match_crlf_multibyte_and_unicode_separator(self):
        raw='note = "中\u2028文"\r\ndef route():\r\n    return open(note)\r\n'.encode()
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'entry.py').write_bytes(raw)
            result=select(root,mode='functions',byte_budget=100)
        row=result['files'][0]
        self.assertEqual(row['raw_bytes_sha256'],hashlib.sha256(raw).hexdigest())
        self.assertEqual(row['line_count'],3)
        for segment in row['ranges']:
            self.assertEqual(raw[segment['start_byte']:segment['end_byte']],segment['text'].encode())

    def test_utf8_budget_cut_keeps_exact_source_byte_slice(self):
        raw='def route():\n    return "中"\n'.encode()
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'entry.py').write_bytes(raw)
            result=select(root,mode='functions',byte_budget=25)
        self.assertLessEqual(result['selected_bytes'],25)
        self.assertTrue(result['files'][0]['ranges'][0]['truncated'])
        for segment in result['files'][0]['ranges']:
            self.assertEqual(raw[segment['start_byte']:segment['end_byte']],segment['text'].encode())

    def test_non_python_sources_have_explicit_unsupported_status(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'lib.rs').write_text('fn main() {}\n')
            (root/'index.ts').write_text('export const x = 1;\n')
            result=select(root,mode='functions')
        self.assertEqual(result['strategy_status'],'unsupported_language')
        self.assertEqual(result['unsupported_sources'],['index.ts','lib.rs'])
        self.assertTrue(result['inventory_complete'])
        self.assertTrue(result['incomplete'])

    def test_unknown_code_suffixes_are_not_silently_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/'safe.py').write_text('def route():\n    return 1\n')
            for name in ('danger.go','module.c','types.pyi','newlang.zig'):
                (root/name).write_text('untrusted source\n')
            (root/'README.md').write_text('Documentation only\n')
            result=select(root,mode='functions')
        self.assertEqual(result['excluded_data_files'],['README.md'])
        self.assertEqual(result['unsupported_sources'],
                         ['danger.go','module.c','newlang.zig','types.pyi'])
        self.assertEqual(result['strategy_status'],'unsupported_language')
        self.assertTrue(result['incomplete'])

    def test_directory_symlink_marks_inventory_incomplete(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'source';root.mkdir()
            elsewhere=Path(d)/'elsewhere';elsewhere.mkdir()
            (root/'entry.py').write_text('def route():\n    return 1\n')
            (root/'hidden').symlink_to(elsewhere,target_is_directory=True)
            result=select(root,mode='functions')
        self.assertEqual(result['skipped_dir_symlinks'],['hidden'])
        self.assertFalse(result['inventory_complete'])
        self.assertTrue(result['incomplete'])

    def test_class_base_call_without_methods_is_selected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/'entry.py').write_text('import os\nclass A(factory()): pass\n')
            result=select(root,mode='functions')
        self.assertTrue(any('class A(factory())' in item['text'] for item in result['files'][0]['ranges']))

    def test_dotted_import_call_resolves_or_is_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'pkg').mkdir()
            (root/'entry.py').write_text('import pkg.helper\ndef route():\n    return pkg.helper.read()\n')
            (root/'pkg'/'helper.py').write_text('def read():\n    return open("record")\n')
            result=select(root,mode='callchain')
        self.assertIn(['entry.route','pkg.helper.read'],result['edges'])
        self.assertIn('entry.route',result['selected_functions'])
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/'entry.py').write_text('import pkg.helper\ndef route():\n    return pkg.helper.read()\n')
            unresolved=select(root,mode='callchain')
        self.assertIn('entry.route',unresolved['unknown_calls'])
        self.assertTrue(unresolved['incomplete'])

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
