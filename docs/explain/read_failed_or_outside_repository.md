# read_failed_or_outside_repository: A file could not be read safely

## What it means

When building the module prompt, Vettalon could not read this file. Either the read failed, or the path resolved outside the repository, for example through a symlink pointing elsewhere, which is refused. The code does not say which. The file's status is `unreadable`, and its source was not reviewed.

## Why you see it

Typical causes are a missing file, no read permission, or a symlink that leaves the repository.

## What to do

Check the path, permissions and symlinks. Fix them and rescan, or review the file by hand. The module is then shown as `partially_reviewed`.

## Related

[unreadable](unreadable.md), [partially_reviewed](partially_reviewed.md).
