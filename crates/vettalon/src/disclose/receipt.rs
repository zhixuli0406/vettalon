//! Optional reproduce receipt attached to a draft (`--receipt`,
//! `--receipt-bundle`).
//!
//! The receipt is the JSON written by `vettalon reproduce`
//! ([`TargetPocReceipt`]). It is tied to the finding by its target file, the
//! file's SHA-256 (against the finding's recorded `file_hash`) and, when the
//! finding records one, the target function; its outcome is re-derived from
//! its phases rather than trusted as written. The draft quotes its file
//! name, SHA-256 and outcome, and (with a bundle) prints the verification
//! command for the maintainer. Signatures are NOT verified here, and the
//! draft says so: the verification command is text for the reader; nothing
//! is executed or contacted.

use std::io::Read;
use std::path::Path;

use serde::Serialize;

use crate::audit::poc_oracle::classify_finding_target;
use crate::audit::schema::{Finding, sha256_hex};
use crate::audit::target_poc::{TargetPocOutcome, TargetPocReceipt};

/// Size cap for the receipt and the bundle.
pub const MAX_RECEIPT_BYTES: u64 = 16 * 1024 * 1024;

/// Placeholders printed in the verification command for a file name that
/// is not plain `[A-Za-z0-9._-]+`.
pub const RECEIPT_PLACEHOLDER: &str = "<receipt-file>";
pub const BUNDLE_PLACEHOLDER: &str = "<bundle-file>";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BundleNote {
    pub file: String,
    pub sha256: String,
}

/// What the PoC section of a draft says about the receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReceiptNote {
    pub file: String,
    pub sha256: String,
    /// Always `effect_observed`: any other outcome is refused.
    pub outcome: String,
    /// `(observed, requested)` replays of a version-2 receipt; `None` for v1.
    pub replays: Option<(u32, u32)>,
    pub bundle: Option<BundleNote>,
}

/// A regular, non-symlink file no larger than the cap, read whole. The type
/// is checked again on the opened handle (`O_NOFOLLOW | O_NONBLOCK` on
/// unix, so a FIFO swapped in after the first check cannot block the read).
fn read_capped_bytes(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    let not_regular = || {
        format!(
            "{label} {} must be a regular file, not a symlink",
            path.display()
        )
    };
    let too_large = || {
        format!(
            "{label} {} is larger than {MAX_RECEIPT_BYTES} bytes",
            path.display()
        )
    };
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("cannot inspect {label} {}: {e}", path.display()))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(not_regular());
    }
    if meta.len() > MAX_RECEIPT_BYTES {
        return Err(too_large());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|e| format!("cannot open {label} {}: {e}", path.display()))?;
    let opened = file
        .metadata()
        .map_err(|e| format!("cannot inspect {label} {}: {e}", path.display()))?;
    if !opened.is_file() {
        return Err(not_regular());
    }
    if opened.len() > MAX_RECEIPT_BYTES {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    file.take(MAX_RECEIPT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read {label} {}: {e}", path.display()))?;
    if bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return Err(too_large());
    }
    Ok(bytes)
}

/// The file's own name, with anything that could break a line shown as `?`.
fn display_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "receipt".into())
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// `^[A-Za-z0-9._-]+$`: safe to print inside a shell command line.
pub(crate) fn shell_safe_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

pub(crate) fn same_file(a: &str, b: &str) -> bool {
    a.trim().trim_start_matches("./") == b.trim().trim_start_matches("./")
}

/// Function names the finding records for its own file: the scope of each
/// trace step in that file, also by its last `.` / `::` segment (a
/// `Class.method` scope matches a receipt for `method`). Empty when the
/// finding records none.
fn recorded_functions(f: &Finding) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for step in f.trace.iter().filter(|s| same_file(&s.file, &f.file)) {
        let scope = step.scope.trim();
        if scope.is_empty() {
            continue;
        }
        let last = scope.rsplit(['.', ':']).next().unwrap_or(scope).trim();
        for name in [scope, last] {
            if !name.is_empty() && !out.iter().any(|n| n == name) {
                out.push(name.to_string());
            }
        }
    }
    out
}

fn outcome_key(o: TargetPocOutcome) -> &'static str {
    match o {
        TargetPocOutcome::EffectObserved => "effect_observed",
        TargetPocOutcome::EffectAbsent => "effect_absent",
        TargetPocOutcome::Inconclusive => "inconclusive",
    }
}

/// The receipt names the finding's file (path only).
pub(crate) fn check_file_path(target_file: &str, f: &Finding) -> Result<(), String> {
    if !same_file(target_file, &f.file) {
        return Err(format!(
            "receipt target_file {:?} does not match the finding's file {:?}; refusing to attach it",
            target_file, f.file
        ));
    }
    Ok(())
}

/// The receipt's file hash is the finding's recorded `file_hash`. Both are
/// the lowercase hex SHA-256 of the file bytes; a missing hash on either side
/// is a refusal, never a match.
pub(crate) fn check_file_hash(target_file_sha256: Option<&str>, f: &Finding) -> Result<(), String> {
    let Some(recorded) = f
        .file_hash
        .as_deref()
        .map(str::trim)
        .filter(|h| !h.is_empty())
    else {
        return Err(format!(
            "the finding records no file_hash for {:?}, so the receipt cannot be tied to the audited version of the file; refusing to attach it",
            f.file
        ));
    };
    match target_file_sha256.map(str::trim) {
        Some(h) if h.eq_ignore_ascii_case(recorded) => Ok(()),
        Some(_) => Err(format!(
            "receipt is for a different version of the file: its target_file_sha256 does not match the finding's recorded file_hash for {:?}; refusing to attach it",
            f.file
        )),
        None => Err(
            "receipt has no target_file_sha256, so it cannot be tied to the audited version of the file; refusing to attach it"
                .into(),
        ),
    }
}

/// The receipt's function is one the finding records for its file, when the
/// finding records any.
pub(crate) fn check_function(target_function: &str, f: &Finding) -> Result<(), String> {
    let functions = recorded_functions(f);
    if !functions.is_empty() && !functions.iter().any(|n| n == target_function.trim()) {
        return Err(format!(
            "receipt target_function {:?} does not match the function the finding records ({}); refusing to attach it",
            target_function,
            functions.join(", ")
        ));
    }
    Ok(())
}

/// File, file version and (when recorded) function of a receipt against
/// this finding. Shared with the retest delivery package.
pub(crate) fn check_file_binding(
    target_file: &str,
    target_file_sha256: Option<&str>,
    target_function: Option<&str>,
    f: &Finding,
) -> Result<(), String> {
    check_file_path(target_file, f)?;
    check_file_hash(target_file_sha256, f)?;
    match target_function {
        Some(function) => check_function(function, f),
        None => Ok(()),
    }
}

/// Everything that ties a parsed receipt to this finding.
fn check_binding(parsed: &TargetPocReceipt, f: &Finding) -> Result<(), String> {
    check_file_binding(
        &parsed.target_file,
        parsed.target_file_sha256.as_deref(),
        Some(&parsed.target_function),
        f,
    )?;
    // The outcome: re-derived from the phases with the rule `reproduce`
    // itself uses; the stored value is not trusted.
    let Some(class) = classify_finding_target(f) else {
        return Err(
            "the finding's weakness has no reproduce oracle, so the receipt outcome cannot be re-derived from its phases; refusing to attach it"
                .into(),
        );
    };
    let (derived, reason) = parsed
        .validate_stored_with_finding(Some(class), Some(f))
        .map_err(|error| format!("{error}; refusing to attach as effect_observed"))?;
    if derived != TargetPocOutcome::EffectObserved {
        let why = reason.map(|r| format!(" ({r})")).unwrap_or_default();
        return Err(format!(
            "receipt outcome is {}{why}, not effect_observed; refusing to attach it",
            outcome_key(derived)
        ));
    }
    Ok(())
}

/// Read and check the receipt (and the optional bundle) for this finding.
pub fn load(receipt: &Path, bundle: Option<&Path>, f: &Finding) -> Result<ReceiptNote, String> {
    let bytes = read_capped_bytes(receipt, "receipt")?;
    let parsed: TargetPocReceipt = serde_json::from_slice(&bytes).map_err(|e| {
        format!(
            "receipt {} is not a reproduce receipt: {e}",
            receipt.display()
        )
    })?;
    check_binding(&parsed, f)?;
    let bundle = match bundle {
        Some(p) => {
            let b = read_capped_bytes(p, "receipt bundle")?;
            Some(BundleNote {
                file: display_name(p),
                sha256: sha256_hex(&b),
            })
        }
        None => None,
    };
    Ok(ReceiptNote {
        file: display_name(receipt),
        sha256: sha256_hex(&bytes),
        outcome: "effect_observed".into(),
        replays: parsed.replays.as_ref().map(|s| (s.observed, s.requested)),
        bundle,
    })
}

impl ReceiptNote {
    /// True when a file name is replaced by a placeholder in the command.
    fn names_hidden(&self) -> bool {
        !shell_safe_name(&self.file)
            || self
                .bundle
                .as_ref()
                .is_some_and(|b| !shell_safe_name(&b.file))
    }

    /// Text of the verification command (not run by this tool). A file name
    /// outside `[A-Za-z0-9._-]+` is replaced by a placeholder.
    pub fn verify_command(&self) -> Option<String> {
        self.bundle.as_ref().map(|b| {
            let receipt = if shell_safe_name(&self.file) {
                self.file.as_str()
            } else {
                RECEIPT_PLACEHOLDER
            };
            let bundle = if shell_safe_name(&b.file) {
                b.file.as_str()
            } else {
                BUNDLE_PLACEHOLDER
            };
            format!("vettalon receipt verify {receipt} --key <public key> --bundle {bundle}")
        })
    }

    pub(super) fn render_en(&self) -> String {
        let mut s = format!(
            "Reproduce receipt: {}\nReceipt SHA-256: {}{}\nReceipt outcome: {}",
            self.file,
            self.sha256,
            self.replays
                .map(|(k, n)| format!(" (replays observed: {k}/{n})"))
                .unwrap_or_default(),
            self.outcome
        );
        if let Some(b) = &self.bundle {
            s.push_str(&format!(
                "\nReceipt bundle: {}\nBundle SHA-256: {}",
                b.file, b.sha256
            ));
        }
        s.push_str(
            "\nReceipt signature: not verified by the drafting tool (it only quoted the file).",
        );
        s.push_str("\nVerifying the signature confirms the receipt bytes and the signer only; it does not prove the outcome or conclusion.");
        if let Some(cmd) = self.verify_command() {
            s.push_str(&format!("\nTo verify the receipt: {cmd}"));
            if self.names_hidden() {
                s.push_str(
                    "\n(A file name was not shown in the command because it contains unsafe characters.)",
                );
            }
        }
        s
    }

    pub(super) fn render_zh(&self) -> String {
        let mut s = format!(
            "重現收據：{}\n收據 SHA-256：{}{}\n收據結果：{}",
            self.file,
            self.sha256,
            self.replays
                .map(|(k, n)| format!("（重播觀察到：{k}/{n}）"))
                .unwrap_or_default(),
            self.outcome
        );
        if let Some(b) = &self.bundle {
            s.push_str(&format!(
                "\n收據套件：{}\n套件 SHA-256：{}",
                b.file, b.sha256
            ));
        }
        s.push_str("\n收據簽章：草稿工具未驗證（僅引用檔案）。");
        s.push_str("\n簽章驗證只確認收據內容與簽署者，不證明結果或結論正確。");
        if let Some(cmd) = self.verify_command() {
            s.push_str(&format!("\n驗證收據指令：{cmd}"));
            if self.names_hidden() {
                s.push_str("\n（檔名含不安全字元，未顯示於指令中。）");
            }
        }
        s
    }
}
