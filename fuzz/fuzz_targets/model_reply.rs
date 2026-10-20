//! The model-reply contract: the finder's candidate array, the verifier's
//! verdict, and the zero-LLM pre-check that grounds a candidate's file/line
//! claims before anything is shown to a verifier. A model reply is untrusted
//! (the audited repository can prompt-inject the model).
//!
//! Input: `<file content> \0 <model reply>`. The file content is served as
//! `src/app.rs`, the only path in the simulated audit prompt.
//!
//! Invariants checked beyond "no panic":
//! - the fence stripper returns a substring of the reply;
//! - a candidate that passes the pre-check names a prompt path and a line
//!   for which every context-window helper returns a window, so a verifier is
//!   never shown "no code" for a claim the pre-check accepted;
//! - the plain and the numbered window agree on in/out of range;
//! - a verifier's corrected line that passes the file/line check also yields
//!   a window.

#![no_main]

use std::collections::HashSet;

use libfuzzer_sys::fuzz_target;
use vettalon::audit::fuzzing::{
    LineOracle, centered_window, check_candidate, check_file_and_line, extract_context_window,
    numbered_context_window, parse_ai_candidates, parse_verdict,
};
use vettalon_contract::safe_path::SafeRepoPath;
use vettalon_contract::strict_json::strip_outer_fence;

const PROMPT_FILE: &str = "src/app.rs";
const WINDOW_BUDGET: usize = 4096;

struct OneFile<'a>(&'a str);

impl LineOracle for OneFile<'_> {
    fn line_count(&self, path: &SafeRepoPath) -> Option<usize> {
        (path.as_str() == PROMPT_FILE).then(|| self.0.lines().count())
    }
}

fn assert_windows(content: &str, line: Option<u32>) {
    assert!(extract_context_window(content, line, 2).is_some());
    assert!(numbered_context_window(content, line, 2).is_some());
    assert!(centered_window(content, line, WINDOW_BUDGET).is_some());
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let (content, reply) = text.split_once('\0').unwrap_or(("", &text));
    let oracle = OneFile(content);

    assert!(reply.contains(strip_outer_fence(reply)));

    if let Ok(candidates) = parse_ai_candidates(reply) {
        let prompt_paths: HashSet<String> = [PROMPT_FILE.to_string()].into();
        for c in &candidates {
            let violations = check_candidate(
                &c.file,
                c.line,
                &c.trace,
                &c.threat_model,
                &prompt_paths,
                &oracle,
            );
            let plain = extract_context_window(content, c.line, 2);
            let numbered = numbered_context_window(content, c.line, 2);
            assert_eq!(plain.is_some(), numbered.is_some());
            if violations.is_empty() {
                assert_eq!(c.file, PROMPT_FILE);
                assert_windows(content, c.line);
                assert!(!c.trace.is_empty());
            }
        }
    }

    if let Ok(verdict) = parse_verdict(reply) {
        if let Some(line) = verdict.corrected_line
            && check_file_and_line(PROMPT_FILE, Some(line), &oracle).is_empty()
        {
            assert_windows(content, Some(line));
        }
        for step in verdict.corrected_trace.iter().flatten() {
            if check_file_and_line(&step.file, Some(step.line), &oracle).is_empty() {
                assert_windows(content, Some(step.line));
            }
        }
    }
});
