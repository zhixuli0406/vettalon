"""Offline local lifecycle observations: every subprocess is mocked, zero child."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HELPER = Path(__file__).parent / 'verify_local_install.py'


class LocalInstallHelperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='plugin helper test ')
        self.root = Path(self.temp.name).resolve()
        spec = importlib.util.spec_from_file_location('install_helper', HELPER)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.log = self.root / 'lifecycle.jsonl'
        self.fake = self.root / 'fake claude'
        self.fake.write_text('self-authored path token; never executed')
        self.calls = []
        self.guard = patch.object(self.module.subprocess, 'run', side_effect=AssertionError('No unmocked child'))
        self.guard.start(); self.addCleanup(self.guard.stop)

    def tearDown(self):
        self.temp.cleanup()

    def run_main(self, *args):
        with contextlib.redirect_stderr(io.StringIO()):
            return self.module.main(list(args))

    def fake_cli(self, *, stale=False, wrong_bytes=False, missing=False, fail_install=False):
        initial = []
        def call(command, *, cwd, env, **kwargs):
            args = command[1:]; self.calls.append((args, Path(cwd), dict(env)))
            stdout = 'SECRET_DO_NOT_RECORD'; rc = 0
            if args == ['--version']: stdout = '2.1.300 (Claude Code)\n'
            if args[:2] == ['plugin', 'details']: stdout = 'Skills (3)\nAgents (0)\nHooks (0)\nMCP servers (0)\nLSP servers (0)\n'
            if fail_install and args[:2] == ['plugin', 'install']: rc = 7
            if args == ['plugin', 'list', '--json']:
                source = Path(cwd) / 'marketplace/plugins/vettalon'
                version = json.loads((source / '.claude-plugin/plugin.json').read_text())['version']
                if not initial: initial.append(version)
                path = source
                if wrong_bytes:
                    path = Path(cwd) / 'config/cache/unit-plugin'
                    if path.exists(): shutil.rmtree(path)
                    shutil.copytree(source, path)
                    with (path / 'scripts/vettalon_plugin.py').open('a') as f: f.write('\n# wrong installed bytes\n')
                row = {'id': 'vettalon@vettalon-local', 'scope': 'user', 'enabled': True,
                       'installPath': str(path), 'version': version}
                if not wrong_bytes:
                    row.update(readFromFolder=str(source), folderVersion=initial[0] if stale else version)
                stdout = json.dumps([] if missing else [row])
            return SimpleNamespace(returncode=rc, stdout=stdout, stderr='TOKEN_DO_NOT_RECORD')
        return call

    def execute(self, **options):
        with patch.object(self.module.shutil, 'which', return_value=str(self.fake)), \
             patch.object(self.module.subprocess, 'run', side_effect=self.fake_cli(**options)):
            return self.run_main('--output', str(self.log))

    def events(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_existing_output_refused_before_cli_lookup(self):
        self.log.write_text('historical artifact\n')
        with patch.object(self.module.shutil, 'which') as lookup:
            self.assertEqual(self.run_main('--output', str(self.log)), 2)
            lookup.assert_not_called()
        self.assertEqual(self.log.read_text(), 'historical artifact\n')

    def test_missing_binary_clear_error_without_real_profile_fingerprint(self):
        with patch.object(self.module.shutil, 'which', return_value=None), contextlib.redirect_stderr(io.StringIO()) as error:
            self.assertEqual(self.module.main(['--output', str(self.log)]), 2)
        self.assertIn('Claude CLI not found', error.getvalue())
        final = self.events()[-1]
        self.assertEqual(final['status'], 'partial')
        self.assertIsNone(final['real_user_config_hashes_unchanged'])
        self.assertFalse(final['profile_fingerprint_verified'])

    def test_failed_command_retains_partial_and_never_logs_raw_output(self):
        self.assertEqual(self.execute(fail_install=True), 2)
        text = self.log.read_text()
        self.assertNotIn('SECRET_DO_NOT_RECORD', text); self.assertNotIn('TOKEN_DO_NOT_RECORD', text)
        self.assertEqual(self.events()[-1]['status'], 'partial')
        self.assertTrue(any(event.get('exit') == 7 for event in self.events()))
        self.assertFalse(any(args[:2] == ['plugin', 'update'] for args, _, _ in self.calls))

    def test_two_actual_owned_observations_and_dynamic_manifest_version(self):
        self.assertEqual(self.execute(), 0)
        observed = [e for e in self.events() if e.get('event') == 'installation-observed']
        self.assertEqual(len(observed), 2)
        self.assertNotEqual(observed[0]['observed_version'], observed[1]['observed_version'])
        self.assertTrue(all(e['files_match_owned_source'] for e in observed))
        self.assertTrue(all(e['observation_kind'] == 'local-relative-source' for e in observed))
        self.assertTrue(all(e['hosted_cache_verified'] is False for e in observed))
        self.assertEqual(sum(args == ['plugin', 'list', '--json'] for args, _, _ in self.calls), 2)
        self.assertIsNone(self.events()[-1]['real_user_config_hashes_unchanged'])

    def test_wrong_installed_bytes_do_not_pass_on_version_or_exit_zero(self):
        self.assertEqual(self.execute(wrong_bytes=True), 2)
        self.assertEqual(self.events()[-1]['status'], 'partial')
        self.assertFalse(any(e.get('event') == 'installation-observed' for e in self.events()))

    def test_missing_inventory_is_partial_not_successful_service_metadata(self):
        self.assertEqual(self.execute(missing=True), 2)
        self.assertEqual(self.events()[-1]['status'], 'partial')

    def test_clean_allowlist_env_has_owned_home_and_no_credentials_or_proxies(self):
        with patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'SECRET_PARENT_KEY', 'HTTPS_PROXY': 'SECRET_PARENT_PROXY', 'NODE_OPTIONS': 'SECRET_PARENT_NODE'}):
            self.assertEqual(self.execute(), 0)
        for _, cwd, env in self.calls:
            self.assertNotIn('ANTHROPIC_API_KEY', env); self.assertNotIn('HTTPS_PROXY', env); self.assertNotIn('NODE_OPTIONS', env)
            self.assertEqual(Path(env['HOME']), cwd / 'home')
            self.assertEqual(Path(env['CLAUDE_CONFIG_DIR']), cwd / 'config')
        self.assertNotIn('SECRET_PARENT', self.log.read_text())

    def test_next_version_uses_actual_manifest_and_is_distinct(self):
        self.assertEqual(self.module.next_version('0.1.0-preview.9'), '0.1.0-preview.10')
        self.assertNotEqual(self.module.next_version('4.5.6'), '4.5.6')
        with self.assertRaises(self.module.LifecycleError): self.module.next_version('unknown')

    def test_inventory_contract_rejects_unknown_shape_outside_owned_and_symlink(self):
        owned = self.root / 'owned'; owned.mkdir()
        source = owned / 'plugin'; source.mkdir()
        for text in ('{}', '[{"id":"other"}]', '[{"id":"vettalon@vettalon-local","scope":"user","enabled":true,"version":"1.0.0","installPath":"/outside"}]'):
            with self.subTest(text=text), self.assertRaises(self.module.LifecycleError):
                self.module.observe_inventory(text, owned, source, '1.0.0', {})
        link = owned / 'linked'; link.symlink_to(source, target_is_directory=True)
        record = {'id': 'vettalon@vettalon-local', 'scope': 'user', 'enabled': True,
                  'version': '1.0.0', 'installPath': str(link)}
        with self.assertRaisesRegex(self.module.LifecycleError, 'symlink'):
            self.module.observe_inventory(json.dumps([record]), owned, source, '1.0.0', {})

    def test_stale_observed_install_is_partial_despite_successful_commands(self):
        from types import SimpleNamespace
        initial = []
        def successful_but_stale(command, *, cwd, env, **kwargs):
            args = command[1:]
            stdout = 'SECRET_DO_NOT_RECORD'
            if args == ['--version']:
                stdout = '2.1.300 (Claude Code)\n'
            elif args[:2] == ['plugin', 'details']:
                stdout = 'Skills (3)\nAgents (0)\nHooks (0)\nMCP servers (0)\nLSP servers (0)\n'
            elif args == ['plugin', 'list', '--json']:
                plugin = Path(cwd) / 'marketplace/plugins/vettalon'
                current = json.loads((plugin / '.claude-plugin/plugin.json').read_text())['version']
                if not initial: initial.append(current)
                # The actual owned source advances, but installed-folder inventory stays stale.
                stdout = json.dumps([{'id': 'vettalon@vettalon-local', 'scope': 'user', 'enabled': True,
                    'installPath': str(plugin), 'version': initial[0], 'readFromFolder': str(plugin),
                    'folderVersion': initial[0]}])
            return SimpleNamespace(returncode=0, stdout=stdout, stderr='TOKEN_DO_NOT_RECORD')
        with patch.object(self.module.shutil, 'which', return_value=str(self.fake)), \
             patch.object(self.module, 'fingerprint', return_value=('unit-profile-not-read',), create=True), \
             patch.object(self.module.subprocess, 'run', side_effect=successful_but_stale):
            result = self.run_main('--output', str(self.log))
        self.assertEqual(result, 2, 'Stale observed installation must remain partial, not command-success complete')
        events = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual(events[-1]['status'], 'partial')
        self.assertNotIn('SECRET_DO_NOT_RECORD', self.log.read_text())
        self.assertNotIn('TOKEN_DO_NOT_RECORD', self.log.read_text())

    def test_nonversion_registry_text_is_partial_and_never_logged(self):
        callback = self.fake_cli()
        def bad_version(command, **kwargs):
            result = callback(command, **kwargs)
            if command[1:] == ['plugin', 'list', '--json']:
                rows = json.loads(result.stdout); rows[0]['version'] = 'TOKEN_DO_NOT_RECORD'
                result.stdout = json.dumps(rows)
            return result
        with patch.object(self.module.shutil, 'which', return_value=str(self.fake)), \
             patch.object(self.module.subprocess, 'run', side_effect=bad_version):
            self.assertEqual(self.run_main('--output', str(self.log)), 2)
        self.assertEqual(self.events()[-1]['status'], 'partial')
        self.assertNotIn('TOKEN_DO_NOT_RECORD', self.log.read_text())

    def test_unknown_details_inventory_remains_partial(self):
        callback = self.fake_cli()
        def unknown(command, **kwargs):
            result = callback(command, **kwargs)
            if command[1:3] == ['plugin', 'details']: result.stdout = 'unknown inventory format'
            return result
        with patch.object(self.module.shutil, 'which', return_value=str(self.fake)), \
             patch.object(self.module.subprocess, 'run', side_effect=unknown):
            self.assertEqual(self.run_main('--output', str(self.log)), 2)
        self.assertEqual(self.events()[-1]['status'], 'partial')

    def test_output_required(self):
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()): self.module.main([])


if __name__ == '__main__': unittest.main()
