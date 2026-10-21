#!/usr/bin/env python3
"""Build the GitHub release body for a tag from CHANGELOG.md.

The release workflow passes the output as `body_path`; softprops/action-gh-release
puts it in front of GitHub's generated notes (PR list). The body carries the
version's "升級須知 / Upgrade notes" subsection, when it has one, and a link to
the full CHANGELOG entry. A tag whose version has no `## [X.Y.Z]` section fails:
the CHANGELOG must be cut before tagging, or upgrade steps would never reach the
release page.

Usage: release_notes.py CHANGELOG.md vX.Y.Z [--out FILE] [--repo OWNER/NAME]
Standard library only; reads one local file and writes one.
"""

import argparse
import re
import sys
from pathlib import Path

UPGRADE_HEADING = '### 升級須知 / Upgrade notes'
TAG = re.compile(r'v(\d+\.\d+\.\d+)')
DEFAULT_REPO = 'zhixuli0406/vettalon'


class NotesError(ValueError):
    pass


def headings(lines):
    """Indexes of lines that are Markdown headings, skipping fenced code
    (a `# comment` inside a shell example is not a heading)."""
    fenced = False
    for i, line in enumerate(lines):
        if line.lstrip().startswith(('```', '~~~')):
            fenced = not fenced
        elif not fenced and line.startswith('#'):
            yield i


def version_section(changelog: str, version: str) -> str:
    """Body of `## [version]` (heading line excluded), up to the next `## `."""
    lines = changelog.splitlines()
    start = None
    for i in headings(lines):
        line = lines[i].rstrip()
        if start is None:
            if line == f'## [{version}]' or line.startswith(f'## [{version}] '):
                start = i + 1
        elif line.startswith('## '):
            return '\n'.join(lines[start:i])
    if start is None:
        raise NotesError(f'CHANGELOG has no "## [{version}]" section; cut the CHANGELOG before tagging')
    return '\n'.join(lines[start:])


def upgrade_notes(section: str) -> str:
    """Items under the upgrade-notes subsection, or '' when there is none."""
    lines = section.splitlines()
    marks = list(headings(lines))
    start = next((i + 1 for i in marks if lines[i].rstrip() == UPGRADE_HEADING), None)
    if start is None:
        return ''
    end = next((i for i in marks if i >= start), len(lines))
    return '\n'.join(lines[start:end]).strip()


def anchor(version: str, date: str) -> str:
    """GitHub's heading anchor for `## [X.Y.Z] - DATE`."""
    text = f'[{version}] - {date}' if date else f'[{version}]'
    return re.sub(r'[^\w\- ]', '', text.lower()).replace(' ', '-')


def release_body(changelog: str, tag: str, repo: str = DEFAULT_REPO) -> str:
    match = TAG.fullmatch(tag)
    if not match:
        raise NotesError(f'tag must look like vX.Y.Z (got {tag!r})')
    version = match.group(1)
    section = version_section(changelog, version)
    heading = next(line.rstrip() for line in changelog.splitlines()
                   if line.rstrip() == f'## [{version}]' or line.startswith(f'## [{version}] '))
    date = heading.partition(' - ')[2].strip()
    link = f'https://github.com/{repo}/blob/{tag}/CHANGELOG.md#{anchor(version, date)}'
    parts = []
    notes = upgrade_notes(section)
    if notes:
        parts.append(f'## 升級須知 / Upgrade notes\n\n{notes}')
    parts.append(f'完整變更 / Full changes: [CHANGELOG.md]({link})')
    return '\n\n'.join(parts) + '\n'


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('changelog')
    parser.add_argument('tag')
    parser.add_argument('--out', help='write the body here (default: stdout)')
    parser.add_argument('--repo', default=DEFAULT_REPO)
    args = parser.parse_args(argv)
    try:
        body = release_body(Path(args.changelog).read_text(encoding='utf-8'), args.tag, args.repo)
    except (OSError, NotesError) as exc:
        print(f'release_notes: {exc}', file=sys.stderr)
        return 1
    if args.out:
        Path(args.out).write_text(body, encoding='utf-8')
    else:
        sys.stdout.write(body)
    return 0


if __name__ == '__main__':
    sys.exit(main())
