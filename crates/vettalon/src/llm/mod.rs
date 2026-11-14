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
pub mod spend;
pub mod usage_limit;

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde::Serialize;

pub type Result<T> = std::result::Result<T, LlmError>;

#[derive(Debug, Clone, thiserror::Error)]
pub enum LlmError {
    /// Transport / process / HTTP failure.
    #[error("{0}")]
    Executor(String),
    /// Provider allowance exhausted, distinct from transient rate limiting.
    #[error("provider_usage_limit: {0}")]
    UsageLimit(String),
    /// The model answered, but with a refusal instead of the requested work.
    #[error("model refused: {0}")]
    Refused(String),
    /// The spend guard stopped the call before it was sent to any model.
    #[error("spend guard: {0}")]
    BudgetRefused(String),
}

/// Token usage reported by a provider for one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Usage {
    pub input: u64,
    pub cached_input: u64,
    pub output: u64,
    pub reasoning: Option<u64>,
}

/// A completion result together with whatever metering the backend saw.
#[derive(Debug, Clone)]
pub struct Metered {
    pub result: Result<String>,
    pub usage: Option<Usage>,
    pub http_status: Option<u16>,
}

/// Static facts about a configured model, used for cost accounting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeterInfo {
    pub api_model: String,
    pub max_output_tokens: u32,
    /// Name of the environment variable the API key is read from, if any.
    /// Only the name: the value is never stored here.
    pub api_key_env: Option<String>,
}

#[async_trait]
pub trait LlmCaller: Send + Sync {
    async fn complete(&self, prompt: &str) -> Result<String>;

    /// Like [`complete`](Self::complete) but also reports usage and HTTP
    /// status when the backend knows them. Default: no metering.
    async fn complete_metered(&self, prompt: &str) -> Metered {
        Metered {
            result: self.complete(prompt).await,
            usage: None,
            http_status: None,
        }
    }

    fn meter_info(&self) -> Option<MeterInfo> {
        None
    }
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

/// P2-1: one model call, as recorded for the optional `--trace` output. No
/// prompt or reply text is kept — only sizes, timing and outcome — so a trace
/// is safe to keep and share and never leaks source or secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct TraceEvent {
    pub step: String,
    pub model: String,
    pub family: String,
    pub prompt_bytes: usize,
    pub reply_bytes: usize,
    pub latency_ms: u64,
    /// `"ok"` | `"refused"` | `"error"` | `"budget_refused"` (spend guard
    /// did not let the call go out).
    pub outcome: String,
    /// On `"error"`: the error text, secret-masked and cut to 200 bytes, so a
    /// benchmark harness can tell a rate limit from a crash. Never the
    /// prompt or reply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cached_input_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_micro_usd: Option<u64>,
    /// `"provider"` when usage was parsed, `"missing"` when the call returned
    /// without usage. Under a spend guard: `"provider"` (charged from usage,
    /// or a 400/401/403/404/413/422/429 without usage refunded) |
    /// `"charged_worst_case"`. Never set on `"budget_refused"` (no call).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    /// Spend guard only, when usage is known: `true` when the provider
    /// reported more output tokens than `max_output_tokens`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub over_cap_output: Option<bool>,
}

/// What the spend guard charged for one call, for the trace.
struct SpendNote {
    cost_micro_usd: u64,
    tag: &'static str,
    over_cap_output: Option<bool>,
}

/// Shared, append-only LLM-call trace for one run (P2-1). The default is
/// DISABLED (inner `None`): `push` is a no-op and nothing is allocated, so an
/// ordinary run carries no tracing cost. A recording log is made explicitly
/// with [`TraceLog::recording`], only when `--trace` was requested.
#[derive(Debug, Clone, Default)]
pub struct TraceLog(Option<Arc<Mutex<Vec<TraceEvent>>>>);

impl TraceLog {
    /// A log that records. Used only when the run was asked to trace.
    pub fn recording() -> Self {
        TraceLog(Some(Arc::new(Mutex::new(Vec::new()))))
    }
    pub fn push(&self, e: TraceEvent) {
        if let Some(inner) = &self.0
            && let Ok(mut v) = inner.lock()
        {
            v.push(e);
        }
    }
    pub fn snapshot(&self) -> Vec<TraceEvent> {
        self.0
            .as_ref()
            .and_then(|i| i.lock().ok().map(|v| v.clone()))
            .unwrap_or_default()
    }
    pub fn is_empty(&self) -> bool {
        self.0
            .as_ref()
            .map(|i| i.lock().map(|v| v.is_empty()).unwrap_or(true))
            .unwrap_or(true)
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
    usage_limited: std::sync::atomic::AtomicBool,
    /// P2-1: optional per-call trace. Default is an empty, unattached log.
    pub trace: TraceLog,
    /// Optional run-wide spend cap. `None` = no accounting (default).
    spend: Option<Arc<spend::SpendGuard>>,
}

impl StepCaller {
    pub fn new(model: ModelHandle, step: &'static str, log: RefusalLog) -> Self {
        StepCaller {
            model,
            step,
            log,
            calls: std::sync::atomic::AtomicUsize::new(0),
            usage_limited: std::sync::atomic::AtomicBool::new(false),
            trace: TraceLog::default(),
            spend: None,
        }
    }

    /// Attach a run's trace log so every call this step makes is recorded.
    pub fn with_trace(mut self, trace: TraceLog) -> Self {
        self.trace = trace;
        self
    }

    /// Put every call this step makes under `guard`: the worst case is
    /// reserved before the call and the call is not made when it does not
    /// fit, the backend is not metered, or the model has no price.
    pub fn with_spend(mut self, guard: Arc<spend::SpendGuard>) -> Self {
        self.spend = Some(guard);
        self
    }

    /// A call the spend guard stopped before it reached the model. Not
    /// counted in `calls`.
    fn budget_refused(&self, prompt: &str, message: String) -> Metered {
        self.trace.push(TraceEvent {
            step: self.step.to_string(),
            model: self.model.id.clone(),
            family: self.model.family.clone(),
            prompt_bytes: prompt.len(),
            reply_bytes: 0,
            latency_ms: 0,
            outcome: "budget_refused".to_string(),
            error: Some(crate::util::truncate_bytes(&message, 200).to_string()),
            input_tokens: None,
            cached_input_tokens: None,
            output_tokens: None,
            reasoning_tokens: None,
            cost_micro_usd: Some(0),
            usage: None,
            http_status: None,
            over_cap_output: None,
        });
        Metered {
            result: Err(LlmError::BudgetRefused(message)),
            usage: None,
            http_status: None,
        }
    }

    async fn complete_guarded(&self, guard: &spend::SpendGuard, prompt: &str) -> Metered {
        let Some(info) = self.model.caller.meter_info() else {
            return self.budget_refused(
                prompt,
                "spend guard requires a metered HTTP backend".to_string(),
            );
        };
        let worst = match guard.reserve(&info.api_model, prompt.len(), info.max_output_tokens) {
            Ok(w) => w,
            Err(r) => return self.budget_refused(prompt, r.to_string()),
        };
        // Settles as worst case if this future is dropped mid-call.
        let reservation = spend::Reservation::new(guard, info.api_model.clone(), worst);
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let started = std::time::Instant::now();
        let m = self.model.caller.complete_metered(prompt).await;
        let outcome = spend::SettleOutcome::from_response(m.usage, m.http_status);
        let over_cap_output = m
            .usage
            .map(|u| spend::SpendGuard::over_cap(&u, info.max_output_tokens));
        let (cost_micro_usd, tag) = reservation.settle(outcome);
        self.record(
            prompt,
            started,
            m,
            Some(SpendNote {
                cost_micro_usd,
                tag,
                over_cap_output,
            }),
        )
    }

    /// Trace, refusal-log and pass through one completed call.
    fn record(
        &self,
        prompt: &str,
        started: std::time::Instant,
        m: Metered,
        spend: Option<SpendNote>,
    ) -> Metered {
        let (usage, http_status) = (m.usage, m.http_status);
        let r = m.result;
        if matches!(r, Err(LlmError::UsageLimit(_))) {
            self.usage_limited
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        let (outcome, reply_bytes, error) = match &r {
            Ok(s) => ("ok", s.len(), None),
            Err(LlmError::Refused(_)) => ("refused", 0, None),
            Err(LlmError::Executor(e) | LlmError::UsageLimit(e) | LlmError::BudgetRefused(e)) => (
                "error",
                0,
                Some(
                    crate::util::truncate_bytes(&crate::util::mask_sensitive_text(e), 200)
                        .to_string(),
                ),
            ),
        };
        let (cost_micro_usd, usage_tag, over_cap_output) = match spend {
            Some(n) => (
                Some(n.cost_micro_usd),
                Some(n.tag.to_string()),
                n.over_cap_output,
            ),
            None => (
                None,
                if usage.is_some() {
                    Some("provider".to_string())
                } else if r.is_ok() || matches!(r, Err(LlmError::Refused(_))) {
                    Some("missing".to_string())
                } else {
                    None
                },
                None,
            ),
        };
        self.trace.push(TraceEvent {
            step: self.step.to_string(),
            model: self.model.id.clone(),
            family: self.model.family.clone(),
            prompt_bytes: prompt.len(),
            reply_bytes,
            latency_ms: started.elapsed().as_millis() as u64,
            outcome: outcome.to_string(),
            error,
            input_tokens: usage.map(|u| u.input),
            cached_input_tokens: usage.map(|u| u.cached_input),
            output_tokens: usage.map(|u| u.output),
            reasoning_tokens: usage.and_then(|u| u.reasoning),
            cost_micro_usd,
            usage: usage_tag,
            http_status,
            over_cap_output,
        });
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
        Metered {
            result: r,
            usage,
            http_status,
        }
    }

    pub fn usage_limited(&self) -> bool {
        self.usage_limited.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn call_count(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[async_trait]
impl LlmCaller for StepCaller {
    async fn complete(&self, prompt: &str) -> Result<String> {
        self.complete_metered(prompt).await.result
    }

    fn meter_info(&self) -> Option<MeterInfo> {
        self.model.caller.meter_info()
    }

    async fn complete_metered(&self, prompt: &str) -> Metered {
        if let Some(guard) = &self.spend {
            return self.complete_guarded(guard, prompt).await;
        }
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let started = std::time::Instant::now();
        let m = self.model.caller.complete_metered(prompt).await;
        self.record(prompt, started, m, None)
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
        self.complete_metered(prompt).await.result
    }

    fn meter_info(&self) -> Option<MeterInfo> {
        self.inner.meter_info()
    }

    async fn complete_metered(&self, prompt: &str) -> Metered {
        let mut m = self.inner.complete_metered(prompt).await;
        if let Ok(text) = &m.result
            && refusal::looks_like_refusal(text)
        {
            m.result = Err(LlmError::Refused(
                crate::util::truncate_bytes(text.trim(), 400).to_string(),
            ));
        }
        m
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
    async fn step_caller_traces_calls_without_keeping_text() {
        let trace = TraceLog::recording();
        let ok = StepCaller::new(
            handle("m", Ok("hello".into())),
            "audit",
            RefusalLog::default(),
        )
        .with_trace(trace.clone());
        ok.complete("a prompt").await.unwrap();
        let refused = StepCaller::new(
            handle("m", Err(LlmError::Refused("no".into()))),
            "verify",
            RefusalLog::default(),
        )
        .with_trace(trace.clone());
        let _ = refused.complete("p").await;

        let ev = trace.snapshot();
        assert_eq!(ev.len(), 2);
        assert_eq!(ev[0].step, "audit");
        assert_eq!(ev[0].outcome, "ok");
        assert_eq!(ev[0].prompt_bytes, "a prompt".len());
        assert_eq!(ev[0].reply_bytes, "hello".len());
        assert_eq!(ev[1].step, "verify");
        assert_eq!(ev[1].outcome, "refused");
        assert_eq!(ev[1].reply_bytes, 0);
    }

    struct Metering(Option<Usage>, String);
    #[async_trait]
    impl LlmCaller for Metering {
        async fn complete(&self, _p: &str) -> Result<String> {
            Ok(self.1.clone())
        }
        async fn complete_metered(&self, p: &str) -> Metered {
            Metered {
                result: self.complete(p).await,
                usage: self.0,
                http_status: Some(200),
            }
        }
    }

    #[tokio::test]
    async fn step_caller_traces_usage_provider_and_missing() {
        let trace = TraceLog::recording();
        let u = Usage {
            input: 11,
            cached_input: 3,
            output: 7,
            reasoning: Some(2),
        };
        let h = ModelHandle {
            id: "m".into(),
            family: "f".into(),
            caller: Arc::new(Metering(Some(u), "hi".into())),
        };
        StepCaller::new(h, "audit", RefusalLog::default())
            .with_trace(trace.clone())
            .complete("p")
            .await
            .unwrap();
        StepCaller::new(handle("m", Ok("hi".into())), "audit", RefusalLog::default())
            .with_trace(trace.clone())
            .complete("p")
            .await
            .unwrap();
        let ev = trace.snapshot();
        assert_eq!(ev[0].usage.as_deref(), Some("provider"));
        assert_eq!(ev[0].input_tokens, Some(11));
        assert_eq!(ev[0].cached_input_tokens, Some(3));
        assert_eq!(ev[0].output_tokens, Some(7));
        assert_eq!(ev[0].reasoning_tokens, Some(2));
        assert_eq!(ev[0].http_status, Some(200));
        assert_eq!(ev[1].usage.as_deref(), Some("missing"));
        assert_eq!(ev[1].input_tokens, None);
        let json = serde_json::to_string(&ev[1]).unwrap();
        assert!(!json.contains("tokens") && !json.contains("http_status"));
    }

    #[tokio::test]
    async fn refusal_aware_keeps_usage() {
        let u = Usage {
            input: 1,
            cached_input: 0,
            output: 2,
            reasoning: None,
        };
        let r = RefusalAware {
            inner: Metering(Some(u), "I'm sorry, but I can't help with that.".into()),
        };
        let m = r.complete_metered("p").await;
        assert!(matches!(m.result, Err(LlmError::Refused(_))));
        assert_eq!(m.usage, Some(u));
        assert_eq!(m.http_status, Some(200));
    }

    #[tokio::test]
    async fn step_caller_without_trace_records_nothing() {
        let c = StepCaller::new(handle("m", Ok("{}".into())), "audit", RefusalLog::default());
        c.complete("p").await.unwrap();
        assert!(c.trace.is_empty(), "an unattached trace stays empty");
    }

    #[tokio::test]
    async fn step_caller_without_guard_trace_json_is_unchanged() {
        let trace = TraceLog::recording();
        StepCaller::new(handle("m", Ok("hi".into())), "audit", RefusalLog::default())
            .with_trace(trace.clone())
            .complete("p")
            .await
            .unwrap();
        let _ = StepCaller::new(
            handle("m", Err(LlmError::Executor("boom".into()))),
            "audit",
            RefusalLog::default(),
        )
        .with_trace(trace.clone())
        .complete("p")
        .await;
        let mut ev = trace.snapshot();
        for e in &mut ev {
            e.latency_ms = 0;
        }
        assert_eq!(
            serde_json::to_string(&ev[0]).unwrap(),
            r#"{"step":"audit","model":"m","family":"m","prompt_bytes":1,"reply_bytes":2,"latency_ms":0,"outcome":"ok","usage":"missing"}"#
        );
        assert_eq!(
            serde_json::to_string(&ev[1]).unwrap(),
            r#"{"step":"audit","model":"m","family":"m","prompt_bytes":1,"reply_bytes":0,"latency_ms":0,"outcome":"error","error":"boom"}"#
        );
    }

    /// Metered fake that counts how often it is actually called.
    struct Fake {
        calls: Arc<std::sync::atomic::AtomicUsize>,
        info: Option<MeterInfo>,
        result: Result<String>,
        usage: Option<Usage>,
        status: Option<u16>,
    }
    #[async_trait]
    impl LlmCaller for Fake {
        async fn complete(&self, p: &str) -> Result<String> {
            self.complete_metered(p).await.result
        }
        fn meter_info(&self) -> Option<MeterInfo> {
            self.info.clone()
        }
        async fn complete_metered(&self, _p: &str) -> Metered {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Metered {
                result: self.result.clone(),
                usage: self.usage,
                http_status: self.status,
            }
        }
    }

    fn fake(
        metered: bool,
        result: Result<String>,
        usage: Option<Usage>,
        status: Option<u16>,
    ) -> (ModelHandle, Arc<std::sync::atomic::AtomicUsize>) {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let h = ModelHandle {
            id: "judge".into(),
            family: "f".into(),
            caller: Arc::new(Fake {
                calls: calls.clone(),
                info: metered.then(|| MeterInfo {
                    api_model: "api-m".into(),
                    max_output_tokens: 100,
                    api_key_env: None,
                }),
                result,
                usage,
                status,
            }),
        };
        (h, calls)
    }

    /// in 1, cached 0.1, out 10 micro-USD per token.
    fn spend_guard(cap_usd: f64) -> Arc<spend::SpendGuard> {
        let t = spend::PriceTable::parse(
            br#"{"schema":"vettalon.prices/1","retrieved":"2026-11-12","source":[],
            "models":{"api-m":{"input":1,"cached_input":0.1,"output":10}}}"#,
        )
        .unwrap();
        Arc::new(spend::SpendGuard::new(cap_usd, t).unwrap())
    }

    fn guarded(h: ModelHandle, g: &Arc<spend::SpendGuard>, trace: &TraceLog) -> StepCaller {
        StepCaller::new(h, "verify", RefusalLog::default())
            .with_trace(trace.clone())
            .with_spend(g.clone())
    }

    #[tokio::test]
    async fn spend_guard_refused_call_never_reaches_the_model() {
        let trace = TraceLog::recording();
        // cap 1000 micro; worst for "p" = 257 + 100 * 10 = 1257.
        let g = spend_guard(0.001);
        let (h, calls) = fake(true, Ok("{}".into()), None, Some(200));
        let c = guarded(h, &g, &trace);
        let e = c.complete("p").await.unwrap_err();
        assert!(e.to_string().contains("spend cap reached"), "{e}");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(c.call_count(), 0);
        assert_eq!(g.spent_micro(), 0);
        let ev = trace.snapshot();
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].outcome, "budget_refused");
        assert_eq!(ev[0].cost_micro_usd, Some(0));
        // L5: no call was attempted, so no usage tag and no token fields.
        assert_eq!(ev[0].usage, None);
        let json = serde_json::to_string(&ev[0]).unwrap();
        assert!(
            !json.contains("\"usage\"")
                && !json.contains("tokens")
                && !json.contains("http_status"),
            "{json}"
        );
    }

    #[tokio::test]
    async fn spend_guard_settles_by_status_and_usage() {
        let trace = TraceLog::recording();
        let g = spend_guard(1.0);
        let u = Usage {
            input: 300,
            cached_input: 0,
            output: 10,
            reasoning: None,
        };
        // 4xx with usage: charged from usage (300 + 100), not refunded.
        let (h, _) = fake(
            true,
            Err(LlmError::Executor("400".into())),
            Some(u),
            Some(400),
        );
        let _ = guarded(h, &g, &trace).complete("p").await;
        assert_eq!(g.spent_micro(), 400);
        // 408 without usage: may have run, worst case (257 + 1000).
        let (h, _) = fake(true, Err(LlmError::Executor("408".into())), None, Some(408));
        let _ = guarded(h, &g, &trace).complete("p").await;
        assert_eq!(g.spent_micro(), 400 + 1257);
        // 409 and 499 without usage: worst case too.
        for s in [409, 499] {
            let (h, _) = fake(true, Err(LlmError::Executor("x".into())), None, Some(s));
            let _ = guarded(h, &g, &trace).complete("p").await;
        }
        assert_eq!(g.spent_micro(), 400 + 3 * 1257);
        // 429 without usage: rejected before inference, refunded.
        let (h, _) = fake(true, Err(LlmError::Executor("429".into())), None, Some(429));
        let _ = guarded(h, &g, &trace).complete("p").await;
        assert_eq!(g.spent_micro(), 400 + 3 * 1257);
        assert_eq!(g.calls_charged_worst_case(), 3);
        let ev = trace.snapshot();
        let tags: Vec<_> = ev.iter().map(|e| e.usage.as_deref().unwrap()).collect();
        assert_eq!(
            tags,
            [
                "provider",
                "charged_worst_case",
                "charged_worst_case",
                "charged_worst_case",
                "provider"
            ]
        );
        assert_eq!(ev[0].http_status, Some(400));
        assert_eq!(ev[0].input_tokens, Some(300));
    }

    #[tokio::test]
    async fn spend_guard_trips_after_a_call_billed_above_its_reservation() {
        let trace = TraceLog::recording();
        let g = spend_guard(1.0);
        // Reserved 257 + 1000; billed 1 + 500 * 10 = 5001.
        let u = Usage {
            input: 1,
            cached_input: 0,
            output: 500,
            reasoning: Some(450),
        };
        let (h, calls) = fake(true, Ok("{}".into()), Some(u), Some(200));
        let c = guarded(h, &g, &trace);
        c.complete("p").await.unwrap();
        assert!(g.is_tripped());
        assert!(!g.exceeded_cap());
        assert_eq!(g.over_reservation_calls(), 1);
        // Headroom remains, but nothing more goes out.
        let e = c.complete("p").await.unwrap_err();
        assert!(matches!(e, LlmError::BudgetRefused(_)), "{e}");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(g.spent_micro(), 5001);
        let ev = trace.snapshot();
        assert_eq!(ev[1].outcome, "budget_refused");
    }

    #[tokio::test]
    async fn spend_guard_requires_metered_backend_and_a_price() {
        let trace = TraceLog::recording();
        let g = spend_guard(1.0);
        let (h, calls) = fake(false, Ok("{}".into()), None, Some(200));
        let e = guarded(h, &g, &trace).complete("p").await.unwrap_err();
        assert!(
            e.to_string().contains("requires a metered HTTP backend"),
            "{e}"
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);

        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let h = ModelHandle {
            id: "judge".into(),
            family: "f".into(),
            caller: Arc::new(Fake {
                calls: calls.clone(),
                info: Some(MeterInfo {
                    api_model: "unpriced".into(),
                    max_output_tokens: 100,
                    api_key_env: None,
                }),
                result: Ok("{}".into()),
                usage: None,
                status: Some(200),
            }),
        };
        let e = guarded(h, &g, &trace).complete("p").await.unwrap_err();
        assert!(e.to_string().contains("no price for model"), "{e}");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        let ev = trace.snapshot();
        assert!(ev.iter().all(|e| e.outcome == "budget_refused"));
        assert_eq!(g.spent_micro(), 0);
    }

    #[tokio::test]
    async fn spend_guard_charges_usage_worst_case_and_refunds_4xx() {
        let trace = TraceLog::recording();
        let g = spend_guard(1.0);
        let u = Usage {
            input: 500,
            cached_input: 100,
            output: 50,
            reasoning: None,
        };
        let (h, calls) = fake(true, Ok("{}".into()), Some(u), Some(200));
        guarded(h, &g, &trace).complete("p").await.unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        // 400 + 10 + 500.
        assert_eq!(g.spent_micro(), 910);

        // ok without usage: worst case (257 + 1000) kept.
        let (h, _) = fake(true, Ok("{}".into()), None, Some(200));
        guarded(h, &g, &trace).complete("p").await.unwrap();
        assert_eq!(g.spent_micro(), 910 + 1257);
        // transport failure, no status: worst case.
        let (h, _) = fake(true, Err(LlmError::Executor("t".into())), None, None);
        let _ = guarded(h, &g, &trace).complete("p").await;
        // 5xx: worst case.
        let (h, _) = fake(true, Err(LlmError::Executor("5".into())), None, Some(503));
        let _ = guarded(h, &g, &trace).complete("p").await;
        assert_eq!(g.spent_micro(), 910 + 3 * 1257);
        assert_eq!(g.calls_charged_worst_case(), 3);
        // 4xx: refunded.
        let (h, _) = fake(true, Err(LlmError::Executor("4".into())), None, Some(429));
        let _ = guarded(h, &g, &trace).complete("p").await;
        assert_eq!(g.spent_micro(), 910 + 3 * 1257);

        let ev = trace.snapshot();
        let tags: Vec<_> = ev.iter().map(|e| e.usage.as_deref().unwrap()).collect();
        assert_eq!(
            tags,
            [
                "provider",
                "charged_worst_case",
                "charged_worst_case",
                "charged_worst_case",
                "provider"
            ]
        );
        let costs: Vec<_> = ev.iter().map(|e| e.cost_micro_usd.unwrap()).collect();
        assert_eq!(costs, [910, 1257, 1257, 1257, 0]);
        assert_eq!(ev[0].over_cap_output, Some(false));
        assert_eq!(ev[1].over_cap_output, None);
    }

    #[tokio::test]
    async fn spend_guard_flags_output_over_max_tokens() {
        let trace = TraceLog::recording();
        let g = spend_guard(1.0);
        let u = Usage {
            input: 1,
            cached_input: 0,
            output: 101,
            reasoning: Some(90),
        };
        let (h, _) = fake(true, Ok("{}".into()), Some(u), Some(200));
        guarded(h, &g, &trace).complete("p").await.unwrap();
        let ev = trace.snapshot();
        assert_eq!(ev[0].over_cap_output, Some(true));
        assert_eq!(ev[0].cost_micro_usd, Some(1 + 1010));
        let json = serde_json::to_string(&ev[0]).unwrap();
        assert!(json.contains(r#""over_cap_output":true"#), "{json}");
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
