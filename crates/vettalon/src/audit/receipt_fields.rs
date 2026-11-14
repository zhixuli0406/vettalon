//! Shared field validation for receipt signing and delivery.

use super::target_poc::{PHASE_NAMES, TargetPocReceipt};
use super::verification_context::is_sha256;

/// Longest finding id accepted.
const FINDING_ID_MAX_CHARS: usize = 200;
/// Longest reason / version token copied into the record.
const TOKEN_MAX_BYTES: usize = 128;
/// Longest image reference copied into the record.
const IMAGE_MAX_BYTES: usize = 256;

/// Visible, trimmed, bounded, without control or invisible characters.
pub(crate) fn check_finding_id(id: &str) -> Result<(), String> {
    let ok = vettalon_contract::visible_text::is_visible_text(id, FINDING_ID_MAX_CHARS)
        && !id
            .chars()
            .any(|c| c.is_control() || crate::disclose::is_invisible(c));
    if ok {
        Ok(())
    } else {
        Err(format!(
            "finding id {id:?} is empty, longer than {FINDING_ID_MAX_CHARS} characters or has control or invisible characters"
        ))
    }
}

pub(crate) fn check_hash(value: Option<&str>, label: &str) -> Result<(), String> {
    match value {
        Some(hash) if !is_sha256(hash) => Err(format!("{label} is not a lowercase hex sha256")),
        _ => Ok(()),
    }
}

/// A reason or version token: `[A-Za-z0-9_.:/-]{1,128}` (`variants/1`).
pub(crate) fn check_token(value: Option<&str>, label: &str) -> Result<(), String> {
    let ok = |token: &str| {
        (1..=TOKEN_MAX_BYTES).contains(&token.len())
            && token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'/' | b'-'))
    };
    match value {
        Some(token) if !ok(token) => Err(format!("{label} is not a plain token")),
        _ => Ok(()),
    }
}

/// Every reproduce receipt field the record copies is a well-formed hash,
/// token or image reference (titles and paths are sanitised instead).
pub(crate) fn check_receipt_fields(receipt: &TargetPocReceipt, label: &str) -> Result<(), String> {
    for (what, value) in [
        ("target_file_sha256", &receipt.target_file_sha256),
        ("source_sha256", &receipt.source_sha256),
        ("adapter_sha256", &receipt.adapter_sha256),
        ("target_plan_sha256", &receipt.target_plan_sha256),
        ("harness_sha256", &receipt.harness_sha256),
    ] {
        check_hash(value.as_deref(), &format!("{label} {what}"))?;
    }
    check_image(receipt.image_id.as_deref(), &format!("{label} image_id"))?;
    check_token(receipt.reason.as_deref(), &format!("{label} reason"))?;
    let summary = receipt.replay_summary();
    for run in &summary.runs {
        check_token(run.reason.as_deref(), &format!("{label} replay reason"))?;
    }
    for phase in summary
        .runs
        .iter()
        .flat_map(|run| run.phases.iter())
        .chain(&receipt.phases)
    {
        if !PHASE_NAMES.contains(&phase.name.as_str()) {
            return Err(format!(
                "{label} has a phase that is not one of the three protocol phases"
            ));
        }
        check_hash(
            phase.transcript_sha256.as_deref(),
            &format!("{label} phase transcript_sha256"),
        )?;
        check_token(phase.reason.as_deref(), &format!("{label} phase reason"))?;
    }
    if let Some(event) = &receipt.verification_event {
        check_hash(
            Some(event.ir.binding.harness_sha256.as_str()),
            &format!("{label} event harness_sha256"),
        )?;
        check_token(
            Some(event.ir.binding.policy_version.as_str()),
            &format!("{label} event policy_version"),
        )?;
    }
    if let Some(runtime) = &receipt.runtime {
        check_token(
            Some(runtime.node_version.as_str()),
            &format!("{label} node_version"),
        )?;
    }
    Ok(())
}

/// An image reference: 1..=256 printable ASCII bytes, no spaces.
pub(crate) fn check_image(value: Option<&str>, label: &str) -> Result<(), String> {
    match value {
        Some(image)
            if image.is_empty()
                || image.len() > IMAGE_MAX_BYTES
                || !image.bytes().all(|b| b.is_ascii_graphic()) =>
        {
            Err(format!("{label} is not a plain image reference"))
        }
        _ => Ok(()),
    }
}
