//! Bounded source-file intake shared by the per-language analyzers: capped
//! reads that refuse symlinks and swapped files, file identity re-checks, and
//! label clipping. Moved out of `py_parse` unchanged so a Java analyzer can
//! reuse them.

use std::io::Read;
use std::path::Path;

/// Longest label (qualified name, chain entry) kept, in characters.
pub(super) const MAX_LABEL_CHARS: usize = 256;

/// Clip `s` to [`MAX_LABEL_CHARS`] characters, appending `…`.
pub(super) fn clip_label(s: String) -> String {
    match s.char_indices().nth(MAX_LABEL_CHARS) {
        Some((i, _)) => {
            let mut out = s[..i].to_string();
            out.push('…');
            out
        }
        None => s,
    }
}

/// `(dev, ino)` of walk-time metadata (unix only), to check that the file
/// opened later is the one the walk saw.
#[cfg(unix)]
pub(super) fn file_id(m: &std::fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Some((m.dev(), m.ino()))
}

#[cfg(not(unix))]
pub(super) fn file_id(_: &std::fs::Metadata) -> Option<(u64, u64)> {
    None
}

/// Read at most `cap` bytes of the regular file `path`. `Ok(None)` when the
/// file holds more than `cap` bytes, however it grew since any earlier
/// metadata check. On unix the open does not follow a final symlink
/// (`O_NOFOLLOW`) nor block on a FIFO (`O_NONBLOCK`), and the opened handle
/// must be the file the walk saw (`expect` = walk-time `(dev, ino)`).
pub(super) fn read_capped(
    path: &Path,
    cap: u64,
    expect: Option<(u64, u64)>,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = opts.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    if let Some(want) = expect
        && file_id(&meta).is_some_and(|got| got != want)
    {
        return Err(std::io::Error::other("file changed during the walk"));
    }
    let mut bytes = Vec::new();
    file.take(cap + 1).read_to_end(&mut bytes)?;
    Ok((bytes.len() as u64 <= cap).then_some(bytes))
}
