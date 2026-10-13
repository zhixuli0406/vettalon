//! Small helpers ported from DuDuClaw (`duduclaw-core` text/match utils and
//! `duduclaw-security::audit::mask_sensitive_text`) so vettalon has no
//! dependency on the DuDuClaw workspace.

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

/// vettalon's state directory: `$VETTALON_HOME`, else `~/.vettalon`
/// (`%USERPROFILE%` on Windows). Shared by the CLI and every front end so
/// they read the same roster and saved reports.
///
/// The tool was called polyaudit before its first public release: an
/// existing `$POLYAUDIT_HOME` or `~/.polyaudit` is still used when the new
/// location does not exist yet, so a renamed install keeps its roster.
pub fn vettalon_home() -> std::path::PathBuf {
    if let Ok(h) = std::env::var("VETTALON_HOME") {
        return std::path::PathBuf::from(h);
    }
    if let Ok(h) = std::env::var("POLYAUDIT_HOME") {
        return std::path::PathBuf::from(h);
    }
    let home = std::path::PathBuf::from(
        std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".into()),
    );
    resolve_home(&home)
}

fn resolve_home(home: &Path) -> std::path::PathBuf {
    let current = home.join(".vettalon");
    let legacy = home.join(".polyaudit");
    if !current.exists() && legacy.is_dir() {
        legacy
    } else {
        current
    }
}

/// Truncate `s` to at most `max_bytes` bytes, walking back to a char
/// boundary so multi-byte UTF-8 (CJK, emoji) never panics.
pub fn truncate_bytes(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Case-insensitive ASCII keyword match on word boundaries (`hi` never
/// matches inside `this`).
pub fn word_contains_ci(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let hay = haystack.as_bytes();
    let need = needle.as_bytes();
    let is_word = |b: u8| b.is_ascii_alphanumeric();
    let eq_ci = |a: u8, b: u8| a.eq_ignore_ascii_case(&b);
    if need.len() > hay.len() {
        return false;
    }
    let last_start = hay.len() - need.len();
    for start in 0..=last_start {
        // Match the needle bytes case-insensitively.
        if !(0..need.len()).all(|i| eq_ci(hay[start + i], need[i])) {
            continue;
        }
        let before_ok = start == 0 || !is_word(hay[start - 1]);
        let after_idx = start + need.len();
        let after_ok = after_idx == hay.len() || !is_word(hay[after_idx]);
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

/// Resolve a CLI on `PATH`, then a few common user-local install dirs
/// (Homebrew, `~/.local/bin`, npm/bun/volta shims).
pub fn which_cli(bin: &str) -> Option<String> {
    let lookup_cmd = if cfg!(windows) { "where" } else { "which" };
    if let Ok(output) = std::process::Command::new(lookup_cmd).arg(bin).output()
        && output.status.success()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && Path::new(trimmed).exists() {
                return Some(trimmed.to_string());
            }
        }
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_default();
    [
        format!("{home}/.local/bin/{bin}"),
        format!("/opt/homebrew/bin/{bin}"),
        format!("/usr/local/bin/{bin}"),
        format!("{home}/.bun/bin/{bin}"),
        format!("{home}/.volta/bin/{bin}"),
        format!("{home}/.npm-global/bin/{bin}"),
        format!("{home}/.cargo/bin/{bin}"),
    ]
    .into_iter()
    .find(|c| Path::new(c).exists())
}

/// Read `r` to EOF, keeping at most `cap` bytes and discarding the rest, so
/// a child that prints without end neither fills our memory nor blocks on a
/// full pipe. Returns `(kept, truncated)`.
pub async fn read_capped<R: tokio::io::AsyncRead + Unpin>(
    mut r: R,
    cap: usize,
) -> std::io::Result<(Vec<u8>, bool)> {
    use tokio::io::AsyncReadExt;
    let mut kept = Vec::new();
    let mut buf = [0u8; 8192];
    let mut truncated = false;
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            return Ok((kept, truncated));
        }
        let room = cap.saturating_sub(kept.len());
        if n > room {
            truncated = true;
        }
        kept.extend_from_slice(&buf[..n.min(room)]);
    }
}

/// Resolve a repo-relative `path` to a regular file that really lives under
/// `repo_root`: rejects unsafe paths, and resolves symlinks (in the file or
/// any parent directory) before checking the result is still inside the
/// canonical repo root. Every read of a model-supplied path goes through
/// this, so a planted `docs/x -> ~/.ssh/id_ed25519` is never read.
pub fn resolve_in_repo(repo_root: &Path, path: &str) -> Result<std::path::PathBuf, String> {
    let safe = vettalon_contract::safe_path::SafeRepoPath::parse(path)
        .map_err(|e| format!("unsafe path {path:?}: {e}"))?;
    let root = std::fs::canonicalize(repo_root).map_err(|e| format!("repo root: {e}"))?;
    let real = std::fs::canonicalize(safe.join_under(repo_root))
        .map_err(|e| format!("cannot resolve {path:?}: {e}"))?;
    if !real.starts_with(&root) {
        return Err(format!("{path:?} resolves outside the repository"));
    }
    if !real.is_file() {
        return Err(format!("{path:?} is not a regular file"));
    }
    Ok(real)
}

/// Read a repo file through [`resolve_in_repo`].
pub fn read_repo_file(repo_root: &Path, path: &str) -> Result<String, String> {
    let real = resolve_in_repo(repo_root, path)?;
    std::fs::read_to_string(real).map_err(|e| format!("could not read {path:?}: {e}"))
}

/// Write `contents` to a file created owner-only (0600) from the start, so
/// a report holding code excerpts is never briefly world-readable.
pub fn write_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(contents)?;
    // An existing file keeps its old mode on open; tighten it.
    set_owner_only(path)
}

/// Owner read/write only (0o600). No-op on non-Unix.
pub fn set_owner_only(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// Key names whose values are treated as secrets.
const SENSITIVE_KEYS: &[&str] = &[
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "secret",
    "client_secret",
    "corpsecret",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "authorization",
    "auth",
    "credential",
    "credentials",
    "cookie",
    "session_key",
    "private_key",
    "signing_key",
    "webhook_secret",
    "secret_access_key",
    "access_key",
    "secret_key",
];

/// Value prefixes that mark a string as a credential regardless of its key
/// (well-known secret formats). Anchored `starts_with`, never substring.
const SENSITIVE_VALUE_PREFIXES: &[&str] = &[
    "sk-",
    "sk_live_",
    "sk_test_",
    "rk_live_",
    "xai-",
    "AIza",
    "ASIA",
    "ghs_",
    "ghu_",
    "ghr_",
    "hf_",
    "gsk_",
    "eyJ",
    "xoxb-",
    "xoxp-",
    "xapp-",
    "ghp_",
    "gho_",
    "github_pat_",
    "AKIA",
    "Bearer ",
    "Basic ",
    "Token ",
    "glpat-",
];

/// Regex alternation of [`SENSITIVE_KEYS`], tolerating `-`/`_` interchange.
fn sensitive_keys_pattern() -> String {
    SENSITIVE_KEYS
        .iter()
        .map(|k| regex::escape(k).replace('_', "[-_]"))
        .collect::<Vec<_>>()
        .join("|")
}

static SENSITIVE_TEXT_JSON_KV_RE: LazyLock<Regex> = LazyLock::new(|| {
    let keys = sensitive_keys_pattern();
    Regex::new(&format!(
        r#"(?i)"([A-Za-z0-9_-]*?(?:{keys}))"\s*:\s*"((?:[^"\\]|\\.)*)""#
    ))
    .expect("static SENSITIVE_TEXT_JSON_KV_RE must compile")
});

/// Plain `key: value` lines; consumes the rest of the line (over-masking is
/// the accepted trade-off). Left boundary is not `\b` so CJK↔ASCII seams match.
static SENSITIVE_TEXT_PLAIN_KV_RE: LazyLock<Regex> = LazyLock::new(|| {
    let keys = sensitive_keys_pattern();
    Regex::new(&format!(
        r#"(?i)(^|[^A-Za-z0-9_])([A-Za-z0-9_]*?(?:{keys}))\b\s*[:=]\s*([^\n]+)"#
    ))
    .expect("static SENSITIVE_TEXT_PLAIN_KV_RE must compile")
});

static SENSITIVE_TEXT_VALUE_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    let alts: Vec<String> = SENSITIVE_VALUE_PREFIXES
        .iter()
        .map(|p| regex::escape(p))
        .collect();
    // Left boundary so `sk-` never fires inside a word like `desk-lamp`.
    Regex::new(&format!(
        r#"(^|[^A-Za-z0-9_-])(?:{})[^\s"')\]}}]*"#,
        alts.join("|")
    ))
    .expect("static SENSITIVE_TEXT_VALUE_TOKEN_RE must compile")
});

/// A PEM private key block (multi-line).
static SENSITIVE_TEXT_PEM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----")
        .expect("static SENSITIVE_TEXT_PEM_RE must compile")
});

static SENSITIVE_TEXT_CONN_STRING_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)([a-z][a-z0-9+.-]*://[^/\s:@]+:)[^@\s]+(@)"#)
        .expect("static SENSITIVE_TEXT_CONN_STRING_RE must compile")
});

static SENSITIVE_TEXT_TELEGRAM_BOT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(/bot\d+:)[A-Za-z0-9_-]+"#)
        .expect("static SENSITIVE_TEXT_TELEGRAM_BOT_RE must compile")
});

static SENSITIVE_TEXT_SLACK_WEBHOOK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(hooks\.slack\.com/services/)[A-Za-z0-9/]+"#)
        .expect("static SENSITIVE_TEXT_SLACK_WEBHOOK_RE must compile")
});

/// Best-effort masking of secret-shaped substrings in free text. Six passes,
/// shape-based first, then `key: value`. Over-masking is acceptable,
/// under-masking is not.
pub fn mask_sensitive_text(text: &str) -> String {
    let masked = SENSITIVE_TEXT_JSON_KV_RE.replace_all(text, |caps: &regex::Captures| {
        format!("\"{}\":\"***\"", &caps[1])
    });
    let masked = SENSITIVE_TEXT_PEM_RE.replace_all(
        &masked,
        "-----BEGIN PRIVATE KEY----- *** -----END PRIVATE KEY-----",
    ); // gitleaks:allow (fake test value)
    let masked = SENSITIVE_TEXT_VALUE_TOKEN_RE.replace_all(&masked, "${1}***");
    let masked = SENSITIVE_TEXT_CONN_STRING_RE.replace_all(&masked, "${1}***${2}");
    let masked = SENSITIVE_TEXT_TELEGRAM_BOT_RE.replace_all(&masked, "${1}***");
    let masked = SENSITIVE_TEXT_SLACK_WEBHOOK_RE.replace_all(&masked, "${1}***");
    let masked = SENSITIVE_TEXT_PLAIN_KV_RE.replace_all(&masked, |caps: &regex::Captures| {
        format!("{}{}: ***", &caps[1], &caps[2])
    });
    masked.into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_prefers_new_dir_and_falls_back_to_legacy() {
        let t = tempfile::tempdir().unwrap();
        assert_eq!(resolve_home(t.path()), t.path().join(".vettalon"));
        std::fs::create_dir(t.path().join(".polyaudit")).unwrap();
        assert_eq!(resolve_home(t.path()), t.path().join(".polyaudit"));
        std::fs::create_dir(t.path().join(".vettalon")).unwrap();
        assert_eq!(resolve_home(t.path()), t.path().join(".vettalon"));
    }

    #[test]
    fn truncate_bytes_never_splits_a_char() {
        assert_eq!(truncate_bytes("hello", 10), "hello");
        assert_eq!(truncate_bytes("中文字", 4), "中");
    }

    /// Security review M1 samples: env-style names, common prefixes, PEM.
    #[test]
    fn mask_text_catches_env_style_names_prefixes_and_pem() {
        for sample in [
            "OPENAI_API_KEY=sk-abcdef123456", // gitleaks:allow (fake test value)
            "DB_PASSWORD=hunter2hunter2",
            "GITHUB_TOKEN=ghs_abcdefghijklmnop",
            "aws_secret_access_key = wJalrXUtnFEMIabcdef",
            "XAI_API_KEY: xai-abcdef123456", // gitleaks:allow (fake test value)
            "key AIzaSyD-abcdefghijklmnop here",
            "creds ASIAABCDEFGHIJKLMNOP x", // gitleaks:allow (fake test value)
            "stripe sk_live_abcdef123456",  // gitleaks:allow (fake test value)
            "openrouter sk-or-v1-abcdef123456",
            "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",
            r#"{"OPENAI_API_KEY":"sk-zzz999"}"#,
        ] {
            let m = mask_sensitive_text(sample);
            for secret in [
                "sk-abcdef123456",
                "hunter2hunter2",
                "ghs_abcdefghijklmnop",
                "wJalrXUtnFEMIabcdef",
                "xai-abcdef123456",
                "AIzaSyD",
                "ASIAABCDEFGHIJKLMNOP", // gitleaks:allow (fake test value)
                "sk_live_abcdef",
                "sk-or-v1",
                "eyJhbGci",
                "sk-zzz999",
            ] {
                // gitleaks:allow (fake test value)
                assert!(!m.contains(secret), "{sample:?} → {m:?}");
            }
        }
        let pem = "a\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nxyz\n-----END RSA PRIVATE KEY-----\nb";
        let m = mask_sensitive_text(pem);
        assert!(!m.contains("MIIEowIBAAKCAQEA"), "{m}");
        assert!(m.starts_with("a\n") && m.ends_with("\nb"));
    }

    #[test]
    fn mask_text_prefixes_need_a_word_boundary() {
        let t = "put the desk-lamp next to the task-list";
        assert_eq!(mask_sensitive_text(t), t);
        assert_eq!(mask_sensitive_text("token_count: 5"), "token_count: 5");
    }

    #[tokio::test]
    async fn read_capped_keeps_cap_and_drains_the_rest() {
        let data = vec![b'x'; 50_000];
        let (kept, truncated) = read_capped(&data[..], 1000).await.unwrap();
        assert_eq!(kept.len(), 1000);
        assert!(truncated);
        let (kept, truncated) = read_capped(&b"short"[..], 1000).await.unwrap();
        assert_eq!(kept, b"short");
        assert!(!truncated);
    }

    #[cfg(unix)]
    #[test]
    fn repo_reads_refuse_symlinks_that_escape() {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), "KEY").unwrap();
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join("docs")).unwrap();
        std::fs::write(repo.path().join("docs/ok.txt"), "fine").unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("secret"),
            repo.path().join("docs/notes.txt"),
        )
        .unwrap();
        std::os::unix::fs::symlink(outside.path(), repo.path().join("linkdir")).unwrap();
        assert_eq!(read_repo_file(repo.path(), "docs/ok.txt").unwrap(), "fine");
        assert!(
            read_repo_file(repo.path(), "docs/notes.txt")
                .unwrap_err()
                .contains("outside")
        );
        assert!(
            read_repo_file(repo.path(), "linkdir/secret")
                .unwrap_err()
                .contains("outside")
        );
        assert!(read_repo_file(repo.path(), "../x").is_err());
        assert!(read_repo_file(repo.path(), "docs").is_err());
    }

    #[test]
    fn word_contains_ci_is_word_bounded() {
        assert!(word_contains_ci("Fix XSS in login", "xss"));
        assert!(!word_contains_ci("this", "hi"));
    }

    // ── B3b: result-text masking ─────────────────────────

    #[test]
    fn mask_text_masks_json_kv_pairs_embedded_in_free_text() {
        let text = r#"Connected. {"api_key":"sk-live-abcdef","status":"ok"}"#;
        let masked = mask_sensitive_text(text);
        assert!(masked.contains(r#""api_key":"***""#));
        assert!(!masked.contains("sk-live-abcdef"));
        assert!(
            masked.contains(r#""status":"ok""#),
            "non-secret key untouched"
        );
    }

    #[test]
    fn mask_text_masks_plain_key_value_lines() {
        let text = "Login succeeded.\ntoken: abc.def.ghi\nuser: agnes";
        let masked = mask_sensitive_text(text);
        assert!(masked.contains("token: ***"));
        assert!(!masked.contains("abc.def.ghi"));
        assert!(masked.contains("user: agnes"), "non-secret key untouched");
    }

    #[test]
    fn mask_text_masks_bare_value_prefix_tokens_mid_sentence() {
        let text =
            "here is the token you asked for: sk-ant-api03-verylongsecrettoken, keep it safe";
        let masked = mask_sensitive_text(text);
        assert!(!masked.contains("verylongsecrettoken"));
        assert!(masked.contains("***"));
    }

    #[test]
    fn mask_text_key_match_is_word_boundary_not_substring() {
        // `author` must survive even though it contains the letters of `auth`.
        let text = "author: agnes, authorization: Bearer xyz123";
        let masked = mask_sensitive_text(text);
        assert!(
            masked.contains("author: agnes"),
            "author must not be masked"
        );
        assert!(!masked.contains("xyz123"));
    }

    #[test]
    fn mask_text_is_cjk_safe() {
        let text = "查詢結果：password: 憑證繁體中文密碼內容 完成";
        let masked = mask_sensitive_text(text); // must not panic on multi-byte content
        assert!(masked.contains("password: ***"));
        assert!(!masked.contains("憑證繁體中文密碼內容"));
    }

    #[test]
    fn mask_text_leaves_plain_prose_untouched() {
        let text = "Refund policy: 30 days from purchase, receipt required.";
        assert_eq!(mask_sensitive_text(text), text);
    }
}
