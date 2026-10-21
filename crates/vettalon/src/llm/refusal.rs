//! Refusal detection.
//!
//! Every prompt in this tool demands a single JSON value. A reply that is
//! not JSON and reads like a refusal is classified as one, so the unit is
//! recorded as not reviewed (never silently counted as "no findings"). A JSON reply is never a refusal, even
//! if a string inside it contains refusal words (e.g. a finding about an
//! "access denied" check).

/// Phrases that open or carry a refusal, lowercase. Matched only against
/// non-JSON replies.
const REFUSAL_MARKERS: &[&str] = &[
    "i can't help",
    "i cannot help",
    "i can't assist",
    "i cannot assist",
    "i won't",
    "i will not",
    "i'm not able to",
    "i am not able to",
    "i'm unable to",
    "i am unable to",
    "i can't provide",
    "i cannot provide",
    "i must decline",
    "i'm sorry, but",
    "i apologize, but",
    "against my guidelines",
    "violates my",
    "not comfortable",
    "我不會",
    "我無法",
    "我不能",
    "無法協助",
    "無法提供",
    "我没法",
    "我无法",
    "无法协助",
    "抱歉，我",
    "很抱歉",
    // Provider-side safety filters that answer in place of the model
    // (seen 2026-10-20 from Gemini through the agy CLI).
    "blocked by gemini's filters",
    "this request was blocked by",
];

/// `true` when `reply` is not a JSON value and contains a refusal marker
/// within its first 600 bytes (refusals lead with the refusal).
pub fn looks_like_refusal(reply: &str) -> bool {
    let t = reply.trim();
    if t.is_empty() || looks_like_json(t) {
        return false;
    }
    let head = crate::util::truncate_bytes(t, 600).to_lowercase();
    REFUSAL_MARKERS.iter().any(|m| head.contains(m))
}

fn looks_like_json(t: &str) -> bool {
    let body = t
        .strip_prefix("```json")
        .or_else(|| t.strip_prefix("```"))
        .unwrap_or(t)
        .trim_start();
    (body.starts_with('{') || body.starts_with('['))
        && serde_json::from_str::<serde_json::Value>(
            body.trim_end().trim_end_matches("```").trim_end(),
        )
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn english_and_chinese_refusals_are_detected() {
        assert!(looks_like_refusal(
            "I'm sorry, but I can't help with exploit code."
        ));
        assert!(looks_like_refusal("I cannot assist with that request."));
        assert!(looks_like_refusal(
            "我不會只回傳指定的那一行 JSON。請直接說明你想完成的事。"
        ));
        assert!(looks_like_refusal("很抱歉，這個請求我無法協助。"));
        assert!(looks_like_refusal(
            "This request was blocked by Gemini's filters. They can occasionally trigger by mistake on safe coding, security, or biology-related queries."
        ));
    }

    #[test]
    fn json_is_never_a_refusal_even_with_refusal_words_inside() {
        assert!(!looks_like_refusal(
            r#"{"reason":"I cannot assist; access denied branch"}"#
        ));
        assert!(!looks_like_refusal("```json\n{\"candidates\": []}\n```"));
    }

    #[test]
    fn ordinary_prose_and_empty_are_not_refusals() {
        assert!(!looks_like_refusal(""));
        assert!(!looks_like_refusal("Here is the analysis you asked for."));
    }
}
