//! Conservative exhaustion detection and a scan-local model breaker.

use super::{LlmCaller, LlmError, ModelHandle, Result};
use std::collections::BTreeMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

/// Only call on failed process output. Exact provider phrases avoid treating
/// transient rate limits, context limits and filesystem quotas as exhaustion.
pub(crate) fn cli_exhausted(program: &str, text: &str, prompt: &str) -> bool {
    let program = std::path::Path::new(program)
        .file_stem()
        .and_then(|p| p.to_str())
        .unwrap_or("");
    let text = text.to_lowercase().replace('’', "'");
    let prompt = prompt.to_lowercase().replace('’', "'");
    let phrases: &[&str] = match program {
        "claude" => &[
            "you've hit your limit",
            "your credit balance is too low to access the anthropic api",
        ],
        "codex" => &["usage_limit_reached", "you've hit your usage limit"],
        "grok" => &[
            "you hit your weekly limit",
            "you hit your free usage limit",
            "you've reached your free grok build usage limit",
            "usage balance exhausted",
            "usage_pool_exhausted",
            "usage_limit_reached",
        ],
        _ => return false,
    };
    phrases
        .iter()
        .any(|p| text.contains(p) && !prompt.contains(p))
}

/// OpenAI-compatible exhaustion has an explicit error code/type. A 429 or
/// a message merely discussing quota is insufficient.
pub(crate) fn http_exhausted(body: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    ["code", "type"]
        .iter()
        .any(|field| value["error"][field].as_str() == Some("insufficient_quota"))
}

/// One scan's per-model state. Calls are concurrent; once exhaustion is
/// observed, later calls for the same id are rejected before reaching a caller.
#[derive(Clone, Default)]
pub struct UsageLimits(Arc<Mutex<BTreeMap<String, Arc<AtomicBool>>>>);

impl UsageLimits {
    pub fn wrap(&self, model: &ModelHandle) -> ModelHandle {
        let state = self
            .0
            .lock()
            .expect("usage-limit map poisoned")
            .entry(model.id.clone())
            .or_default()
            .clone();
        ModelHandle {
            id: model.id.clone(),
            family: model.family.clone(),
            caller: Arc::new(LimitedCaller {
                id: model.id.clone(),
                inner: model.caller.clone(),
                state,
            }),
        }
    }

    pub fn models(&self) -> Vec<String> {
        self.0
            .lock()
            .expect("usage-limit map poisoned")
            .iter()
            .filter(|(_, state)| state.load(Ordering::SeqCst))
            .map(|(id, _)| id.clone())
            .collect()
    }
}

struct LimitedCaller {
    id: String,
    inner: Arc<dyn LlmCaller>,
    state: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl LlmCaller for LimitedCaller {
    async fn complete(&self, prompt: &str) -> Result<String> {
        if self.state.load(Ordering::SeqCst) {
            return Err(LlmError::UsageLimit(self.id.clone()));
        }
        let result = self.inner.complete(prompt).await;
        if matches!(result, Err(LlmError::UsageLimit(_))) {
            self.state.store(true, Ordering::SeqCst);
            return Err(LlmError::UsageLimit(self.id.clone()));
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::{LlmCaller, LlmError, ModelHandle};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn usage_limit_provider_patterns_exclude_transient_limits() {
        for (provider, text) in [
            ("claude", "You've hit your limit · resets 5pm"),
            (
                "claude",
                "Your credit balance is too low to access the Anthropic API",
            ),
            ("codex", r#"{"error":{"type":"usage_limit_reached"}}"#),
            ("codex", "You've hit your usage limit. Try again later."),
            ("grok", "You hit your weekly limit."),
            ("grok", "usage balance exhausted"),
            ("grok", "usage_pool_exhausted"),
        ] {
            assert!(cli_exhausted(provider, text, ""), "{provider}: {text}");
        }
        for provider in ["claude", "codex", "grok", "custom"] {
            for text in [
                "HTTP 429 Too Many Requests",
                "rate_limit_exceeded",
                "global_rate_limit",
                "concurrency_limit",
                "disk quota exceeded",
                "context limit exceeded",
                "usage limit",
                "quota exceeded",
            ] {
                assert!(!cli_exhausted(provider, text, ""), "{provider}: {text}");
            }
        }
        assert!(!cli_exhausted("grok", "You've hit your limit", ""));
        assert!(http_exhausted(r#"{"error":{"code":"insufficient_quota"}}"#));
        assert!(!http_exhausted(
            r#"{"error":{"code":"rate_limit_exceeded","message":"insufficient_quota example"}}"#
        ));
        assert!(!http_exhausted("insufficient_quota"));
    }

    #[test]
    fn prompt_phrases_are_excluded_with_same_case_and_apostrophe_folding() {
        assert!(!cli_exhausted(
            "claude",
            "You've hit your limit",
            "YOU’VE HIT YOUR LIMIT"
        ));
        assert!(!cli_exhausted(
            "codex",
            "usage_limit_reached",
            "USAGE_LIMIT_REACHED"
        ));
        assert!(cli_exhausted(
            "grok",
            "usage_pool_exhausted; usage_limit_reached",
            "usage_limit_reached"
        ));
    }

    struct Limited(Arc<AtomicUsize>);
    #[async_trait::async_trait]
    impl LlmCaller for Limited {
        async fn complete(&self, _: &str) -> crate::llm::Result<String> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(LlmError::UsageLimit("exhausted".into()))
        }
    }

    #[tokio::test]
    async fn usage_limit_breaker_is_shared_by_id_and_scoped_to_run() {
        let count = Arc::new(AtomicUsize::new(0));
        let model = ModelHandle {
            id: "m".into(),
            family: "f".into(),
            caller: Arc::new(Limited(count.clone())),
        };
        let breaker = UsageLimits::default();
        let a = breaker.wrap(&model);
        let b = breaker.wrap(&model);
        assert!(matches!(
            a.caller.complete("p").await,
            Err(LlmError::UsageLimit(_))
        ));
        assert!(matches!(
            b.caller.complete("p").await,
            Err(LlmError::UsageLimit(_))
        ));
        assert_eq!(count.load(Ordering::SeqCst), 1);
        let mut other = model.clone();
        other.id = "other".into();
        let _ = breaker.wrap(&other).caller.complete("p").await;
        let _ = UsageLimits::default()
            .wrap(&model)
            .caller
            .complete("p")
            .await;
        assert_eq!(count.load(Ordering::SeqCst), 3);
        assert_eq!(breaker.models(), vec!["m", "other"]);
    }

    struct Overlap(tokio::sync::Barrier);
    #[async_trait::async_trait]
    impl LlmCaller for Overlap {
        async fn complete(&self, _: &str) -> crate::llm::Result<String> {
            self.0.wait().await;
            Ok("ok".into())
        }
    }

    #[tokio::test]
    async fn same_model_calls_overlap() {
        let model = ModelHandle {
            id: "m".into(),
            family: "f".into(),
            caller: Arc::new(Overlap(tokio::sync::Barrier::new(2))),
        };
        let breaker = UsageLimits::default();
        let a = breaker.wrap(&model);
        let b = breaker.wrap(&model);
        let (a, b) = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            tokio::join!(a.caller.complete("a"), b.caller.complete("b"))
        })
        .await
        .expect("same-model calls should overlap");
        assert!(a.is_ok());
        assert!(b.is_ok());
    }
}
