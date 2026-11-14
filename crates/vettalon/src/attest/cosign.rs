//! The user's cosign v3, run with a fixed argv (no shell), a wall-clock
//! timeout and capped output. Executable ownership, writable ancestors, excluded
//! working/receipt/repository directories and pre-spawn identity checks follow
//! the same trust policy as [`super::pq`].
//!
//! Keys are passed as absolute paths of local regular files (remote and KMS
//! references are refused before cosign runs). Vettalon never reads a key or
//! prints `COSIGN_PASSWORD`; only local private-key operations receive that
//! password. Every invocation clears the environment, uses fixed PATH/locales
//! and a fresh private HOME. cosign gets no stdin, so it cannot prompt.

use std::path::Path;
use std::time::Duration;

use crate::audit::{
    AttestationEnv, SubprocessLimits, SubprocessOutcome, TrustedExecutable,
    run_attestation_subprocess,
};

/// Wall-clock limit for one cosign invocation.
pub const COSIGN_TIMEOUT: Duration = Duration::from_secs(60);
/// The only supported cosign major version.
pub const REQUIRED_MAJOR: u32 = 3;
const COSIGN_OUTPUT_MAX_BYTES: usize = 256 * 1024;
const DIAGNOSTIC_MAX_CHARS: usize = 2000;
const VERSION_MAX_CHARS: usize = 64;
const COSIGN_MISSING: &str =
    "cosign was not found on PATH; install cosign v3.0.4 or later (v3) to sign or verify receipts";

/// Why a cosign call did not succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CosignError {
    /// cosign is missing, unsupported, timed out or could not be run.
    Unavailable(String),
    /// cosign ran and exited non-zero (for verify: the signature was rejected).
    Rejected(String),
}

impl std::fmt::Display for CosignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(message) | Self::Rejected(message) => f.write_str(message),
        }
    }
}

/// `cosign attest-blob` argv: local key, no signing config, no transparency
/// log upload, new-format bundle written to `bundle`.
pub fn sign_args<'a>(
    key: &'a str,
    predicate: &'a str,
    predicate_type: &'a str,
    bundle: &'a str,
    blob: &'a str,
) -> [&'a str; 13] {
    [
        "attest-blob",
        "--key",
        key,
        "--predicate",
        predicate,
        "--type",
        predicate_type,
        "--use-signing-config=false",
        "--tlog-upload=false",
        "--bundle",
        bundle,
        "-y",
        blob,
    ]
}

/// `cosign verify-blob-attestation` argv: local public key, offline (no
/// transparency log lookup).
pub fn verify_args<'a>(
    key: &'a str,
    bundle: &'a str,
    predicate_type: &'a str,
    blob: &'a str,
) -> [&'a str; 9] {
    [
        "verify-blob-attestation",
        "--key",
        key,
        "--bundle",
        bundle,
        "--type",
        predicate_type,
        "--insecure-ignore-tlog",
        blob,
    ]
}

/// Extract the release label from `cosign version` output.
fn version_label(output: &str) -> Result<&str, String> {
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix("GitVersion:"))
        .map(str::trim)
        .filter(|version| !version.is_empty())
        .ok_or_else(|| {
            "cannot read the cosign version (no GitVersion line in `cosign version`)".into()
        })
}

/// Require a patched v3 release for receipt signing and verification.
pub fn require_supported_version(output: &str) -> Result<String, String> {
    require_release_version(version_label(output)?)
}

/// Parse an entire strict release label, without prerelease or build suffixes.
pub(crate) fn parse_release_version(version: &str) -> Option<(u32, u32, u32)> {
    let parts: Vec<&str> = version.strip_prefix('v')?.split('.').collect();
    if version.len() > VERSION_MAX_CHARS
        || parts.len() != 3
        || !parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_digit())
                && (part.len() == 1 || !part.starts_with('0'))
        })
    {
        return None;
    }
    Some((
        parts[0].parse().ok()?,
        parts[1].parse().ok()?,
        parts[2].parse().ok()?,
    ))
}

/// Validate the entire release label, also used for stored package claims.
pub(crate) fn require_release_version(version: &str) -> Result<String, String> {
    match parse_release_version(version) {
        Some((REQUIRED_MAJOR, minor, patch)) if (minor, patch) >= (0, 4) => Ok(version.into()),
        _ => Err(format!(
            "cosign v3.0.4 or later (v3) is required; found {}",
            printable(version, VERSION_MAX_CHARS)
        )),
    }
}

/// Image verification supports patched v2 and v3 release output formats.
pub(crate) fn require_image_version(output: &str) -> Result<String, String> {
    let requirement = "agents pull requires cosign v2.6.2 or later (v2), or v3.0.4 or later (v3)";
    let version = version_label(output).map_err(|error| format!("{requirement}: {error}"))?;
    match parse_release_version(version) {
        Some((2, minor, patch)) if (minor, patch) >= (6, 2) => Ok(version.into()),
        Some((3, minor, patch)) if (minor, patch) >= (0, 4) => Ok(version.into()),
        _ => Err(format!(
            "{requirement}; found {}",
            printable(version, VERSION_MAX_CHARS)
        )),
    }
}

pub(crate) fn resolve_program(override_path: Option<&std::ffi::OsStr>) -> Result<String, String> {
    match override_path {
        Some(path) => {
            if !Path::new(path).is_absolute() {
                return Err("VETTALON_COSIGN must be an absolute executable path".into());
            }
            let path = path.to_str().ok_or("VETTALON_COSIGN must be valid UTF-8")?;
            crate::util::which_cli(path).ok_or_else(|| COSIGN_MISSING.into())
        }
        None => crate::util::which_cli("cosign").ok_or_else(|| COSIGN_MISSING.into()),
    }
}

/// A located cosign v3 binary.
#[derive(Debug, Clone)]
pub struct Cosign {
    program: TrustedExecutable,
    pub version: String,
}

impl Cosign {
    /// Find `VETTALON_COSIGN` (absolute only), or `cosign` on PATH, and check
    /// its version. `workdir` is the
    /// private directory every cosign call runs in.
    pub async fn locate(workdir: &Path, excluded: &[&Path]) -> Result<Self, CosignError> {
        let program = resolve_program(std::env::var_os("VETTALON_COSIGN").as_deref())
            .map_err(CosignError::Unavailable)?;
        Self::probe(&program, workdir, excluded).await
    }

    /// Probe an explicitly resolved binary (also the subprocess test seam).
    pub async fn probe(
        program: &str,
        workdir: &Path,
        excluded: &[&Path],
    ) -> Result<Self, CosignError> {
        let program =
            TrustedExecutable::resolve(program, excluded).map_err(CosignError::Unavailable)?;
        let out = run(&program, &["version"], workdir).await?;
        let text = format!("{}\n{}", out.stdout, out.stderr_tail);
        let version = require_supported_version(&text).map_err(CosignError::Unavailable)?;
        Ok(Self { program, version })
    }

    /// Run cosign with a fixed argv in `workdir`.
    pub async fn run(&self, args: &[&str], workdir: &Path) -> Result<(), CosignError> {
        run(&self.program, args, workdir).await.map(|_| ())
    }
}

async fn run(
    program: &TrustedExecutable,
    args: &[&str],
    workdir: &Path,
) -> Result<SubprocessOutcome, CosignError> {
    let limits = SubprocessLimits {
        timeout: COSIGN_TIMEOUT,
        max_output_bytes: COSIGN_OUTPUT_MAX_BYTES,
    };
    let mut builder = tempfile::Builder::new();
    builder.prefix("vettalon-cosign-home-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    let home = builder
        .tempdir()
        .map_err(|e| CosignError::Unavailable(format!("cannot create private cosign HOME: {e}")))?;
    let private_key = args.first() == Some(&"generate-key-pair")
        || (matches!(args.first(), Some(&"attest-blob" | &"sign-blob"))
            && args
                .windows(2)
                .any(|pair| pair[0] == "--key" && Path::new(pair[1]).is_absolute()));
    let env = AttestationEnv::Cosign {
        private_key,
        home: home.path(),
    };
    let out = run_attestation_subprocess(program, args, workdir, &limits, env)
        .await
        .into_text();
    let command = args.first().copied().unwrap_or("cosign");
    let unavailable = if let Some(error) = &out.spawn_error {
        Some(format!("cannot run cosign {command}: {error}"))
    } else if out.timed_out {
        let secs = COSIGN_TIMEOUT.as_secs();
        Some(format!("cosign {command} did not finish within {secs} s"))
    } else if let Some(error) = &out.cleanup_error {
        Some(format!("cosign {command} cleanup failed: {error}"))
    } else if out.stdout_truncated {
        Some(format!("cosign {command} printed too much output"))
    } else {
        None
    };
    if let Some(message) = unavailable {
        return Err(CosignError::Unavailable(message));
    }
    if out.exit_code != Some(0) {
        return Err(CosignError::Rejected(format!(
            "cosign {command} failed (exit {:?}): {}",
            out.exit_code,
            printable(out.stderr_tail.trim(), DIAGNOSTIC_MAX_CHARS)
        )));
    }
    Ok(out)
}

/// Escape control characters (newlines kept) and keep at most the last
/// `max_chars` characters.
pub fn printable(text: &str, max_chars: usize) -> String {
    let mut escaped = String::new();
    for c in text.chars() {
        if c.is_control() && c != '\n' {
            escaped.extend(c.escape_default());
        } else {
            escaped.push(c);
        }
    }
    let count = escaped.chars().count();
    if count <= max_chars {
        return escaped;
    }
    let tail: String = escaped.chars().skip(count - max_chars).collect();
    format!("...{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosign_override_requires_absolute_path() {
        for path in ["", "cosign", "./cosign", "../bin/cosign", "~/bin/cosign"] {
            assert_eq!(
                resolve_program(Some(std::ffi::OsStr::new(path))).unwrap_err(),
                "VETTALON_COSIGN must be an absolute executable path"
            );
        }
        assert!(
            resolve_program(Some(std::ffi::OsStr::new("/nonexistent/vettalon-cosign"))).is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn cosign_override_requires_utf8() {
        use std::os::unix::ffi::OsStrExt;
        assert_eq!(
            resolve_program(Some(std::ffi::OsStr::from_bytes(b"/bin/\xff"))).unwrap_err(),
            "VETTALON_COSIGN must be valid UTF-8"
        );
    }
}
