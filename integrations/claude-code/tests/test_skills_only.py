"""Directory policy and documented CLI contracts; no external commands run."""
import json
from pathlib import Path
import re
import shlex
import unittest


ROOT = Path(__file__).resolve().parents[3]
PLUGIN = ROOT / 'integrations/claude-code/plugins/vettalon'
BIN = '/absolute/trusted/vettalon'


def bash_commands(text):
    for block in re.findall(r'^```bash[ \t]*\n(.*?)^```[ \t]*$', text, re.M | re.S):
        # shlex handles quoted arguments, comments and continued command lines.
        for line in block.replace('\\\n', '').splitlines():
            argv = shlex.split(line, comments=True)
            if argv:
                yield argv



class SkillsOnlyTests(unittest.TestCase):
    def test_directory_file_policy(self):
        files = sorted(path for path in PLUGIN.rglob('*') if path.is_file())
        self.assertTrue(files)
        for path in files:
            with self.subTest(path=path.relative_to(PLUGIN)):
                self.assertFalse(path.is_symlink())
                self.assertIn(path.suffix, {'.md', '.json', '.png'})
                raw = path.read_bytes()
                self.assertFalse(raw.startswith(b'#!'))
                if path.suffix in {'.md', '.json'}:
                    self.assertNotIn(b'\0', raw)
                    text = raw.decode('utf-8', errors='strict')
                    if path.suffix == '.json':
                        json.loads(text)
                # Package-manager configuration is forbidden even if JSON.
                self.assertNotIn(path.name.lower(), {
                    'package.json', 'package-lock.json', 'npm-shrinkwrap.json',
                    'composer.json', 'composer.lock', 'deno.json', 'deno.jsonc',
                    'bower.json', 'jsr.json',
                })

    def test_manual_skills_and_exact_commands(self):
        skills = sorted(PLUGIN.glob('skills/*/SKILL.md'))
        self.assertEqual({path.parent.name for path in skills}, {'doctor', 'scan', 'report'})
        expected = {
            'doctor': [[BIN, '--version'], [BIN, 'agents', 'images']],
            'scan': [
                [BIN, 'scan', '/absolute/audited/repository', '--profile', 'quick',
                 '--report', '/absolute/new-output/report.json',
                 '--sarif', '/absolute/new-output/report.sarif',
                 '--no-prior', '--rank', 'heuristic', '--prescreen', 'off',
                 '--finder-parse-retries', '0', '--verifier-parse-retries', '0'],
                [BIN, 'scan', '/absolute/audited/repository', '--profile', 'deep',
                 '--config', '/absolute/trusted/roster.toml',
                 '--report', '/absolute/new-deep-output/report.json',
                 '--sarif', '/absolute/new-deep-output/report.sarif',
                 '--max-modules', '5', '--time-budget', '120',
                 '--no-prior', '--rank', 'heuristic', '--prescreen', 'off',
                 '--finder-parse-retries', '0', '--verifier-parse-retries', '0'],
            ],
            'report': [],
        }
        for path in skills:
            with self.subTest(skill=path.parent.name):
                text = path.read_text(encoding='utf-8')
                self.assertTrue(text.startswith('---\n'))
                frontmatter = text.split('---', 2)[1]
                self.assertRegex(frontmatter, r'(?m)^disable-model-invocation: true$')
                self.assertEqual(list(bash_commands(text)), expected[path.parent.name])

    def test_command_example_allow_list(self):
        # README scope is the plugin and its integration guide. The OSS README
        # also documents unrestricted CLI workflows outside these skills.
        paths = sorted(PLUGIN.rglob('SKILL.md'))
        paths += sorted(PLUGIN.rglob('README*.md'))
        paths += sorted((ROOT / 'integrations/claude-code').glob('README*.md'))
        scan_count = 0
        for path in paths:
            text = path.read_text(encoding='utf-8')
            for block in re.findall(r'^```bash[ \t]*\n(.*?)^```[ \t]*$', text, re.M | re.S):
                with self.subTest(path=path.relative_to(ROOT), block=block):
                    self.assertNotRegex(block, r'--(?:poc|save|accept-egress)\b|\bjev\b')
            for argv in bash_commands(text):
                with self.subTest(path=path.relative_to(ROOT), argv=argv):
                    # The integration guide also shows the maintainer test command.
                    if path == ROOT / 'integrations/claude-code/README.md' and argv == [
                        'python3', '-B', '-I', '-S', '-m', 'unittest', 'discover',
                        '-s', 'integrations/claude-code/tests', '-p', 'test_*.py',
                    ]:
                        continue
                    self.assertIn(argv[0], {BIN, 'vettalon'})
                    if argv[1:] == ['--version']:
                        continue
                    self.assertIn(argv[1], {'scan', 'agents'})
                    if argv[1] == 'agents':
                        self.assertEqual(argv[1:], ['agents', 'images'])
                        continue
                    scan_count += 1
                    self.assertIn('--no-prior', argv)
                    for option, value in (
                        ('--rank', 'heuristic'), ('--prescreen', 'off'),
                        ('--finder-parse-retries', '0'), ('--verifier-parse-retries', '0'),
                    ):
                        self.assertIn(option, argv)
                        self.assertEqual(argv[argv.index(option) + 1], value)
                    if argv[argv.index('--profile') + 1] == 'deep':
                        self.assertIn('--config', argv)
                        for option, value in (('--max-modules', '5'), ('--time-budget', '120')):
                            self.assertIn(option, argv)
                            self.assertEqual(argv[argv.index(option) + 1], value)
        self.assertEqual(scan_count, 2)

    def test_manifest_listing_fields_and_version(self):
        manifest = json.loads((PLUGIN / '.claude-plugin/plugin.json').read_text())
        self.assertEqual(manifest['name'], 'vettalon')
        self.assertEqual(manifest['version'], '0.2.0')
        for field in ('homepage', 'repository', 'license', 'author',
                      'privacyPolicyUrl', 'documentationUrl', 'supportUrl'):
            self.assertTrue(manifest[field])
        for relative in ('.claude-plugin/marketplace.json',
                         'integrations/claude-code/.claude-plugin/marketplace.json'):
            listing = json.loads((ROOT / relative).read_text())['plugins'][0]
            self.assertEqual(listing['name'], 'vettalon')
            self.assertEqual(listing['version'], manifest['version'])


if __name__ == '__main__':
    unittest.main()
