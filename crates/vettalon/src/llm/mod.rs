//! Model backends. Every audit step talks to a model through the one-method
//! [`LlmCaller`] trait, so no step ever hardcodes a vendor.
//!
//! Backends:
//! - [`cli::CliCaller`]: subscription CLIs (`claude -p`, `codex exec`,
//!   `grok -p`) run headless with tools disabled, in an empty temp dir.
//! - [`http::OpenAiCompatCaller`]: any OpenAI-compatible `chat/completions`
//!   endpoint (OpenRouter, DeepSeek, Qwen, GLM, Gemini's compat endpoint…)
//!   and local Ollama (`http://localhost:11434/v1`).
//!
//! Refusals are first-class: a reply that is a refusal instead of the JSON
//! the contract asks for becomes [`LlmError::Refused`]. The unit is NOT sent
//! to another model; it is recorded as a coverage gap (`[refused:<model>]`
//! in the report) so the operator sees exactly what was not reviewed and
//! decides what to do about it.

pub mod cli;
pub mod container;
pub mod http;
pub mod refusal;

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde::Serialize;

pub type Result<T> = std::result::Result<T, LlmError>;

#[derive(Debug, Clone, thiserror::Error)]
pub enum LlmError {
    /// Transport / process / HTTP failure.
    #[error("{0}")]
    Executor(String),
    /// The model answered, but with a refusal instead of the requested work.
    #[error("model refused: {0}")]
    Refused(String),
}

#[async_trait]
pub trait LlmCaller: Send + Sync {
    async fn complete(&self, prompt: &str) -> Result<String>;
}

/// One configured model, ready to call.
#[derive(Clone)]
pub struct ModelHandle {
    pub id: String,
    /// Vendor family (`anthropic`, `openai`, `xai`, `qwen`, …). Verifiers are
    /// picked from a different family than the finders of a finding.
    pub family: String,
    pub caller: Arc<dyn LlmCaller>,
}

impl std::fmt::Debug for ModelHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelHandle")
            .field("id", &self.id)
            .field("family", &self.family)
            .finish()
    }
}

/// One refusal, as recorded in the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct RefusalEvent {
    pub model: String,
    pub step: String,
    pub excerpt: String,
}

/// Shared, append-only refusal log for one run.
#[derive(Debug, Clone, Default)]
pub struct RefusalLog(Arc<Mutex<Vec<RefusalEvent>>>);

impl RefusalLog {
    pub fn push(&self, e: RefusalEvent) {
        if let Ok(mut v) = self.0.lock() {
            v.push(e);
        }
    }
    pub fn snapshot(&self) -> Vec<RefusalEvent> {
        self.0.lock().map(|v| v.clone()).unwrap_or_default()
    }
}

/// Calls one model for one pipeline step. A refusal is logged and returned
/// as an error unchanged (the step records the unit as not reviewed); it is
/// never retried elsewhere. Also counts calls, so a step can tell a model
/// verdict from a deterministic, zero-LLM one.
pub struct StepCaller {
    pub model: ModelHandle,
    pub step: &'static str,
    pub log: RefusalLog,
    pub calls: std::sync::atomic::AtomicUsize,
}

impl StepCaller {
    pub fn new(model: ModelHandle, step: &'static str, log: RefusalLog) -> Self {
        StepCaller {
            model,
            step,
            log,
            calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub fn call_count(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[async_trait]
impl LlmCaller for StepCaller {
    async fn complete(&self, prompt: &str) -> Result<String> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let r = self.model.caller.complete(prompt).await;
        if let Err(LlmError::Refused(excerpt)) = &r {
            self.log.push(RefusalEvent {
                model: self.model.id.clone(),
                step: self.step.to_string(),
                excerpt: crate::util::truncate_bytes(
                    &crate::util::mask_sensitive_text(excerpt),
                    200,
                )
                .to_string(),
            });
        }
        r
    }
}

/// Wraps a raw backend: turns a refusal-shaped reply into
/// [`LlmError::Refused`]. Applied by every backend constructor.
pub struct RefusalAware<C> {
    pub inner: C,
}

#[async_trait]
impl<C: LlmCaller> LlmCaller for RefusalAware<C> {
    async fn complete(&self, prompt: &str) -> Result<String> {
        let text = self.inner.complete(prompt).await?;
        if refusal::looks_like_refusal(&text) {
            return Err(LlmError::Refused(
                crate::util::truncate_bytes(text.trim(), 400).to_string(),
            ));
        }
        Ok(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(Result<String>);
    #[async_trait]
    impl LlmCaller for Fixed {
        async fn complete(&self, _p: &str) -> Result<String> {
            self.0.clone()
        }
    }

    fn handle(id: &str, r: Result<String>) -> ModelHandle {
        ModelHandle {
            id: id.into(),
            family: id.into(),
            caller: Arc::new(Fixed(r)),
        }
    }

    #[tokio::test]
    async fn step_caller_logs_refusal_and_does_not_retry() {
        let log = RefusalLog::default();
        let c = StepCaller::new(
            handle("a", Err(LlmError::Refused("no".into()))),
            "audit",
            log.clone(),
        );
        assert!(matches!(c.complete("p").await, Err(LlmError::Refused(_))));
        assert_eq!(c.call_count(), 1);
        let ev = log.snapshot();
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].model, "a");
        assert_eq!(ev[0].step, "audit");
    }

    #[tokio::test]
    async fn step_caller_passes_success_and_transport_errors_through() {
        let log = RefusalLog::default();
        let ok = StepCaller::new(handle("a", Ok("{}".into())), "audit", log.clone());
        assert_eq!(ok.complete("p").await.unwrap(), "{}");
        let err = StepCaller::new(
            handle("b", Err(LlmError::Executor("t".into()))),
            "audit",
            log.clone(),
        );
        assert!(matches!(
            err.complete("p").await,
            Err(LlmError::Executor(_))
        ));
        assert!(log.snapshot().is_empty());
    }

    #[tokio::test]
    async fn refusal_aware_flags_refusals_but_passes_json() {
        let r = RefusalAware {
            inner: Fixed(Ok("I'm sorry, but I can't help with that.".into())),
        };
        assert!(matches!(r.complete("p").await, Err(LlmError::Refused(_))));
        let ok = RefusalAware {
            inner: Fixed(Ok(r#"{"candidates":[]}"#.into())),
        };
        assert!(ok.complete("p").await.is_ok());
    }
}
