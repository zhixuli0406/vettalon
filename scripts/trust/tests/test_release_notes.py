"""Offline tests for the release-body builder (no network)."""

from pathlib import Path
import re
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parents[1]))
import release_notes as rn  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]
# The public changelog: oss/CHANGELOG.md in the private repo, CHANGELOG.md once exported.
PUBLIC_CHANGELOG = next(p for p in (ROOT / 'oss/CHANGELOG.md', ROOT / 'CHANGELOG.md') if p.is_file())

SAMPLE = """# Changelog

## [Unreleased]

### Added
- something new

## [0.3.2] - 2026-10-22

### 升級須知 / Upgrade notes
- **Rebuild once:** run `vettalon agents build`.
  English line for the release page.
- **CI:** exit 4 when no AI engine ran.

### Changed
- the changed thing

## [0.3.1] - 2026-10-21

### Fixed
- a fix
"""


class ReleaseNotesTests(unittest.TestCase):
    def test_upgrade_notes_lead_the_body(self):
        body = rn.release_body(SAMPLE, 'v0.3.2')
        self.assertTrue(body.startswith('## 升級須知 / Upgrade notes\n\n- **Rebuild once:**'))
        self.assertIn('  English line for the release page.\n- **CI:** exit 4', body)
        self.assertNotIn('the changed thing', body)
        self.assertIn('https://github.com/zhixuli0406/vettalon/blob/v0.3.2/CHANGELOG.md#032---2026-10-22', body)

    def test_version_without_notes_gets_only_the_link(self):
        body = rn.release_body(SAMPLE, 'v0.3.1')
        self.assertNotIn('Upgrade notes', body)
        self.assertEqual(body.count('\n'), 1)
        self.assertIn('#031---2026-10-21', body)

    def test_missing_section_and_bad_tag_fail(self):
        with self.assertRaisesRegex(rn.NotesError, 'cut the CHANGELOG'):
            rn.release_body(SAMPLE, 'v0.4.0')
        for tag in ('0.3.2', 'v0.3', 'v0.3.2-rc1', 'main'):
            with self.assertRaises(rn.NotesError):
                rn.release_body(SAMPLE, tag)
        # A prefix of another version is not that version.
        with self.assertRaises(rn.NotesError):
            rn.release_body(SAMPLE.replace('[0.3.1]', '[0.3.10]'), 'v0.3.1')

    def test_code_fences_and_trailing_spaces_do_not_cut_the_notes(self):
        text = SAMPLE.replace('### 升級須知 / Upgrade notes\n', '### 升級須知 / Upgrade notes  \n').replace(
            '- **CI:** exit 4 when no AI engine ran.\n',
            '- **CI:** exit 4 when no AI engine ran.\n  ```sh\n  # keep the old exit code\n## not a heading\n  vettalon scan . --allow-incomplete\n  ```\n')
        body = rn.release_body(text, 'v0.3.2')
        self.assertIn('## not a heading\n  vettalon scan . --allow-incomplete\n  ```', body)
        self.assertNotIn('the changed thing', body)

    def test_cli_writes_the_file_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'CHANGELOG.md'
            log.write_text(SAMPLE, encoding='utf-8')
            out = Path(directory) / 'notes.md'
            self.assertEqual(rn.main([str(log), 'v0.3.2', '--out', str(out)]), 0)
            self.assertEqual(out.read_text(encoding='utf-8'), rn.release_body(SAMPLE, 'v0.3.2'))
            self.assertEqual(rn.main([str(log), 'v9.9.9', '--out', str(out)]), 1)

    def test_public_changelog_parses_for_every_release_and_a_simulated_cut(self):
        text = PUBLIC_CHANGELOG.read_text(encoding='utf-8')
        versions = re.findall(r'^## \[(\d+\.\d+\.\d+)\]', text, re.M)
        self.assertTrue(versions)
        for version in versions:
            rn.release_body(text, f'v{version}')
        # Cutting [Unreleased] into a version carries its upgrade notes, if any.
        cut = text.replace('## [Unreleased]', '## [99.0.0] - 2099-01-01', 1)
        body = rn.release_body(cut, 'v99.0.0')
        notes = rn.upgrade_notes(rn.version_section(cut, '99.0.0'))
        if notes:
            self.assertTrue(body.startswith('## 升級須知 / Upgrade notes\n\n' + notes))
        else:
            self.assertNotIn('Upgrade notes', body)

    def test_release_workflow_uses_the_extracted_body(self):
        text = (ROOT / '.github/workflows/release.yml').read_text()
        self.assertIn('trust-source/scripts/trust/release_notes.py trust-source/CHANGELOG.md "$TAG"', text)
        create = text.split('      - name: Create GitHub Release\n', 1)[1].split('\n\n', 1)[0]
        self.assertIn('body_path: ${{ runner.temp }}/release-notes.md', create)
        self.assertIn('generate_release_notes: true', create)


if __name__ == '__main__':
    unittest.main()
