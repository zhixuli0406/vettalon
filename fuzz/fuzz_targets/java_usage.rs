//! The name-based Java usage analyzer behind `vettalon cbom-check` (the Java
//! counterpart of `py_usage`). Input: the bytes of one `Main.java` file, in a
//! one-file project whose only entries are the launcher `main` methods.
//!
//! Invariants checked beyond "no panic":
//! - every returned line is within `1..=lines + 1`, where `lines` is the
//!   number of lines of the input;
//! - when the lexer's code view of the input (comments and literal contents
//!   blanked) holds a reflection word as a whole identifier (or an identifier
//!   starting with `ScriptEngine`), no line is labelled `not_observed`. The
//!   guard is computed by the analyzer (`java_usage_one` returns it); a
//!   reflection word inside a string or comment does not trigger it.
//! - every line labelled `not_observed` has an innermost member and enclosing
//!   types without any annotation (`java_usage_one` returns the check as
//!   `annotation_rule_ok`).

#![no_main]

use libfuzzer_sys::fuzz_target;
use vettalon::audit::fuzzing::java_usage_one;

/// Lines as the analyzer counts them (JLS 3.4): CR, LF and CRLF each end a
/// line, and a non-empty unterminated tail is one more.
fn terminated_lines(b: &[u8]) -> u32 {
    let mut n = 0u32;
    let mut pending = false;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\r' => {
                n += 1;
                if b.get(i + 1) == Some(&b'\n') {
                    i += 1;
                }
                pending = false;
            }
            b'\n' => {
                n += 1;
                pending = false;
            }
            _ => pending = true,
        }
        i += 1;
    }
    n + u32::from(pending)
}

fuzz_target!(|data: &[u8]| {
    let (lines, triggered, annotation_rule_ok) = java_usage_one(data);
    let line_count = terminated_lines(data);
    for (line, label) in &lines {
        assert!(*line >= 1 && *line <= line_count.saturating_add(1));
        assert!(matches!(*label, "reachable" | "not_observed" | "unknown"));
    }
    if triggered {
        assert!(lines.iter().all(|(_, label)| *label != "not_observed"));
    }
    assert!(annotation_rule_ok);
});
