//! OpenAI-compatible `POST {base_url}/chat/completions`. Covers OpenRouter,
//! DeepSeek, Qwen (DashScope compat), GLM, Gemini's OpenAI endpoint, Groq,
//! Together, Mistral, xAI and local Ollama / llama.cpp / vLLM servers.

use std::time::Duration;

use async_trait::async_trait;
use serde_json::json;

use super::{LlmCaller, LlmError, MeterInfo, Metered, Result, Usage};

/// Largest response body accepted from an endpoint.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct HttpSpec {
    /// e.g. `https://openrouter.ai/api/v1`, `http://localhost:11434/v1`.
    pub base_url: String,
    pub model: String,
    /// Read from the environment at call time; never stored in config.
    pub api_key_env: Option<String>,
    pub max_tokens: u32,
    pub temperature: f32,
    pub token_limit_param: crate::config::TokenLimitParam,
    pub omit_temperature: bool,
    pub reasoning_effort: Option<crate::config::ReasoningEffort>,
    pub max_output_tokens_worst: Option<u32>,
    pub timeout: Duration,
}

pub struct OpenAiCompatCaller {
    pub spec: HttpSpec,
    pub client: reqwest::Client,
}

impl OpenAiCompatCaller {
    pub fn new(spec: HttpSpec) -> std::result::Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(spec.timeout)
            .build()
            .map_err(|e| format!("cannot build HTTP client: {e}"))?;
        Ok(OpenAiCompatCaller { spec, client })
    }

    pub fn endpoint(&self) -> String {
        format!(
            "{}/chat/completions",
            self.spec.base_url.trim_end_matches('/')
        )
    }

    pub fn body(&self, prompt: &str) -> serde_json::Value {
        let mut body = json!({
            "model": self.spec.model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": false,
        });
        body[self.spec.token_limit_param.as_str()] = json!(self.spec.max_tokens);
        if !self.spec.omit_temperature {
            body["temperature"] = json!(self.spec.temperature);
        }
        if let Some(effort) = self.spec.reasoning_effort {
            body["reasoning_effort"] = json!(effort);
        }
        body
    }
}

#[async_trait]
impl LlmCaller for OpenAiCompatCaller {
    async fn complete(&self, prompt: &str) -> Result<String> {
        self.complete_metered(prompt).await.result
    }

    fn meter_info(&self) -> Option<MeterInfo> {
        Some(MeterInfo {
            api_model: self.spec.model.clone(),
            max_output_tokens: super::spend::effective_output_ceiling(
                self.spec.max_tokens,
                self.spec.max_output_tokens_worst,
            ),
            api_key_env: self.spec.api_key_env.clone(),
        })
    }

    async fn complete_metered(&self, prompt: &str) -> Metered {
        let fail = |e: LlmError, http_status: Option<u16>| Metered {
            result: Err(e),
            usage: None,
            http_status,
        };
        let mut req = self.client.post(self.endpoint()).json(&self.body(prompt));
        if let Some(var) = &self.spec.api_key_env {
            let key = match std::env::var(var) {
                Ok(k) => k,
                Err(_) => {
                    return fail(
                        LlmError::Executor(format!("environment variable {var} is not set")),
                        None,
                    );
                }
            };
            req = req.bearer_auth(key);
        }
        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                // reqwest errors embed the URL; some gateways carry keys in it.
                return fail(
                    LlmError::Executor(format!("request failed: {}", e.without_url())),
                    None,
                );
            }
        };
        let status = resp.status();
        let code = Some(status.as_u16());
        let bytes = match read_capped(resp, MAX_RESPONSE_BYTES).await {
            Ok(b) => b,
            // The reply is unusable and its usage unknown: drop the status so
            // the spend guard keeps the worst-case charge instead of refunding.
            Err(e) => return fail(e, None),
        };
        let text = String::from_utf8_lossy(&bytes).to_string();
        let (result, usage) = decode_metered(status, &text);
        Metered {
            result,
            usage,
            http_status: code,
        }
    }
}

/// Read the body chunk by chunk, refusing it as soon as it is known to be
/// larger than `cap` (declared `Content-Length` or bytes received), so an
/// oversized reply is never buffered whole.
async fn read_capped(mut resp: reqwest::Response, cap: usize) -> Result<Vec<u8>> {
    if let Some(n) = resp.content_length()
        && n > cap as u64
    {
        return Err(LlmError::Executor(format!(
            "response too large ({n} bytes declared)"
        )));
    }
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if buf.len().saturating_add(chunk.len()) > cap {
                    return Err(LlmError::Executor(format!(
                        "response too large (over {cap} bytes)"
                    )));
                }
                buf.extend_from_slice(&chunk);
            }
            Ok(None) => return Ok(buf),
            Err(e) => {
                // reqwest errors embed the URL; some gateways carry keys in it.
                return Err(LlmError::Executor(format!(
                    "cannot read response: {}",
                    e.without_url()
                )));
            }
        }
    }
}

/// Classify only provider errors; successful model content bypasses detection.
#[cfg(test)]
fn decode_response(status: reqwest::StatusCode, text: &str) -> Result<String> {
    decode_metered(status, text).0
}

fn decode_metered(status: reqwest::StatusCode, text: &str) -> (Result<String>, Option<Usage>) {
    if !status.is_success() {
        // An error reply may still report what was billed; the body was
        // already bounded by MAX_RESPONSE_BYTES.
        let usage = serde_json::from_str::<serde_json::Value>(text)
            .ok()
            .and_then(|v| parse_usage(&v));
        if super::usage_limit::http_exhausted(text) {
            return (
                Err(LlmError::UsageLimit("insufficient_quota".into())),
                usage,
            );
        }
        return (
            Err(LlmError::Executor(format!(
                "HTTP {status}: {}",
                crate::util::truncate_bytes(&crate::util::mask_sensitive_text(text), 400)
            ))),
            usage,
        );
    }
    parse_reply_metered(text)
}

/// Pull `choices[0].message.content`. A provider-side refusal field
/// (`message.refusal`, OpenAI) is surfaced as [`LlmError::Refused`].
pub fn parse_reply(body: &str) -> Result<String> {
    parse_reply_metered(body).0
}

/// [`parse_reply`] plus the usage from the same parsed body (also on the
/// refusal and content-filter paths).
pub fn parse_reply_metered(body: &str) -> (Result<String>, Option<Usage>) {
    let v: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            return (
                Err(LlmError::Executor(format!("response is not JSON: {e}"))),
                None,
            );
        }
    };
    let usage = parse_usage(&v);
    let msg = &v["choices"][0]["message"];
    if let Some(r) = msg["refusal"].as_str()
        && !r.trim().is_empty()
    {
        return (
            Err(LlmError::Refused(
                crate::util::truncate_bytes(r, 400).to_string(),
            )),
            usage,
        );
    }
    if v["choices"][0]["finish_reason"].as_str() == Some("content_filter") {
        return (
            Err(LlmError::Refused("provider content filter".into())),
            usage,
        );
    }
    let result = msg["content"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| LlmError::Executor("response has no choices[0].message.content".into()));
    (result, usage)
}

/// Read an optional non-negative integer at `path`. `Err` when present but
/// not a non-negative JSON integer.
fn uint(v: &serde_json::Value, path: &[&str]) -> std::result::Result<Option<u64>, ()> {
    let mut cur = v;
    for k in path {
        match cur.get(k) {
            Some(n) => cur = n,
            None => return Ok(None),
        }
    }
    match cur {
        serde_json::Value::Null => Ok(None),
        n => n.as_u64().map(Some).ok_or(()),
    }
}

/// Extract provider-reported token usage from a response body.
pub fn parse_usage(v: &serde_json::Value) -> Option<Usage> {
    fn go(v: &serde_json::Value) -> std::result::Result<Option<Usage>, ()> {
        if !v.get("usage").is_some_and(|u| u.is_object()) {
            return Ok(None);
        }
        let prompt = uint(v, &["usage", "prompt_tokens"])?;
        let input = match prompt {
            Some(p) => p,
            None => {
                let Some(i) = uint(v, &["usage", "input_tokens"])? else {
                    return Ok(None);
                };
                let read = uint(v, &["usage", "cache_read_input_tokens"])?.unwrap_or(0);
                let create = uint(v, &["usage", "cache_creation_input_tokens"])?.unwrap_or(0);
                i.saturating_add(read).saturating_add(create)
            }
        };
        let cached = match uint(v, &["usage", "prompt_tokens_details", "cached_tokens"])? {
            Some(c) => c,
            None => uint(v, &["usage", "cache_read_input_tokens"])?.unwrap_or(0),
        };
        let nested_reasoning = uint(
            v,
            &["usage", "completion_tokens_details", "reasoning_tokens"],
        )?;
        let top_reasoning = uint(v, &["usage", "reasoning_tokens"])?;
        let reasoning = nested_reasoning.or(top_reasoning);
        let total = uint(v, &["usage", "total_tokens"])?;

        let completion = match uint(v, &["usage", "completion_tokens"])? {
            Some(c) => Some(c),
            None => uint(v, &["usage", "output_tokens"])?,
        };
        let mut output = completion;
        if let (Some(t), Some(p)) = (total, prompt) {
            let d = t.saturating_sub(p);
            output = Some(output.map_or(d, |o| o.max(d)));
        }
        if total.is_none()
            && nested_reasoning.is_none()
            && let (Some(c), Some(r)) = (completion, top_reasoning)
        {
            let s = c.saturating_add(r);
            output = Some(output.map_or(s, |o| o.max(s)));
        }
        let Some(output) = output else {
            return Ok(None);
        };
        Ok(Some(Usage {
            input,
            cached_input: cached,
            output,
            reasoning,
        }))
    }
    go(v).ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller(base: &str) -> OpenAiCompatCaller {
        OpenAiCompatCaller::new(HttpSpec {
            base_url: base.into(),
            model: "m".into(),
            api_key_env: None,
            max_tokens: 100,
            temperature: 0.0,
            token_limit_param: Default::default(),
            omit_temperature: false,
            reasoning_effort: None,
            max_output_tokens_worst: None,
            timeout: Duration::from_secs(1),
        })
        .unwrap()
    }

    #[test]
    fn endpoint_joins_without_double_slash() {
        assert_eq!(
            caller("http://localhost:11434/v1/").endpoint(),
            "http://localhost:11434/v1/chat/completions"
        );
    }

    #[test]
    fn body_has_model_and_single_user_message() {
        let b = caller("http://x").body("hi");
        assert_eq!(b["model"], "m");
        assert_eq!(b["messages"][0]["role"], "user");
        assert_eq!(b["messages"][0]["content"], "hi");
        assert_eq!(b["stream"], false);
    }

    #[test]
    fn body_supports_per_model_parameters_and_separate_billing_ceiling() {
        let mut c = caller("http://x");
        let default = c.body("hi");
        assert_eq!(default["max_tokens"], 100);
        assert_eq!(default["temperature"], 0.0);
        assert!(default.get("max_completion_tokens").is_none());
        assert!(default.get("reasoning_effort").is_none());
        assert_eq!(c.meter_info().unwrap().max_output_tokens, 100);
        c.spec.token_limit_param = crate::config::TokenLimitParam::MaxCompletionTokens;
        c.spec.omit_temperature = true;
        c.spec.reasoning_effort = Some(crate::config::ReasoningEffort::Low);
        c.spec.max_output_tokens_worst = Some(8192);
        let body = c.body("hi");
        assert_eq!(body["max_completion_tokens"], 100);
        assert!(body.get("max_tokens").is_none());
        assert!(body.get("temperature").is_none());
        assert_eq!(body["reasoning_effort"], "low");
        assert!(body.get("max_output_tokens_worst").is_none());
        assert_eq!(c.meter_info().unwrap().max_output_tokens, 8192);
    }

    #[test]
    fn parse_reply_content_refusal_and_filter() {
        assert_eq!(
            parse_reply(r#"{"choices":[{"message":{"content":"{}"}}]}"#).unwrap(),
            "{}"
        );
        assert!(matches!(
            parse_reply(r#"{"choices":[{"message":{"content":null,"refusal":"no"}}]}"#),
            Err(LlmError::Refused(_))
        ));
        assert!(matches!(
            parse_reply(
                r#"{"choices":[{"finish_reason":"content_filter","message":{"content":""}}]}"#
            ),
            Err(LlmError::Refused(_))
        ));
        assert!(matches!(parse_reply("nope"), Err(LlmError::Executor(_))));
    }

    #[test]
    fn usage_limit_http_requires_error_status_and_quota_code() {
        for (status, body, limited) in [
            (429, r#"{"error":{"code":"insufficient_quota"}}"#, true),
            (429, r#"{"error":{"type":"insufficient_quota"}}"#, true),
            (429, r#"{"error":{"code":"rate_limit_exceeded"}}"#, false),
            (
                200,
                r#"{"choices":[{"message":{"content":"insufficient_quota"}}]}"#,
                false,
            ),
            (200, r#"{"error":{"code":"insufficient_quota"}}"#, false),
        ] {
            let result = decode_response(reqwest::StatusCode::from_u16(status).unwrap(), body);
            assert_eq!(
                matches!(result, Err(LlmError::UsageLimit(_))),
                limited,
                "{result:?}"
            );
            if status == 200 && body.contains("choices") {
                assert_eq!(result.unwrap(), "insufficient_quota");
            }
        }
    }

    fn usage_of(s: &str) -> Option<Usage> {
        parse_usage(&serde_json::from_str(s).unwrap())
    }

    #[test]
    fn parse_usage_fixtures() {
        // OpenAI: cached + reasoning nested; reasoning is inside completion.
        assert_eq!(
            usage_of(
                r#"{"usage":{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150,
                "prompt_tokens_details":{"cached_tokens":40},
                "completion_tokens_details":{"reasoning_tokens":30}}}"#
            ),
            Some(Usage {
                input: 100,
                cached_input: 40,
                output: 50,
                reasoning: Some(30)
            })
        );
        // Anthropic-compat.
        assert_eq!(
            usage_of(r#"{"usage":{"prompt_tokens":7,"completion_tokens":3,"total_tokens":10}}"#),
            Some(Usage {
                input: 7,
                cached_input: 0,
                output: 3,
                reasoning: None
            })
        );
        // Anthropic native with cache fields.
        assert_eq!(
            usage_of(
                r#"{"usage":{"input_tokens":10,"output_tokens":20,
                "cache_read_input_tokens":5,"cache_creation_input_tokens":2}}"#
            ),
            Some(Usage {
                input: 17,
                cached_input: 5,
                output: 20,
                reasoning: None
            })
        );
        // xAI: top-level reasoning, total = prompt + completion + reasoning.
        assert_eq!(
            usage_of(
                r#"{"usage":{"prompt_tokens":10,"completion_tokens":5,
                "reasoning_tokens":20,"total_tokens":35}}"#
            ),
            Some(Usage {
                input: 10,
                cached_input: 0,
                output: 25,
                reasoning: Some(20)
            })
        );
        // Top-level reasoning, no total: completion + reasoning.
        assert_eq!(
            usage_of(
                r#"{"usage":{"prompt_tokens":10,"completion_tokens":5,"reasoning_tokens":20}}"#
            )
            .map(|u| u.output),
            Some(25)
        );
        // Gemini-like: total exceeds prompt + completion.
        assert_eq!(
            usage_of(r#"{"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":40}}"#)
                .map(|u| u.output),
            Some(30)
        );
        // Missing / invalid.
        assert_eq!(usage_of(r#"{"choices":[]}"#), None);
        assert_eq!(
            usage_of(r#"{"usage":{"prompt_tokens":-1,"completion_tokens":5}}"#),
            None
        );
        assert_eq!(
            usage_of(r#"{"usage":{"prompt_tokens":"10","completion_tokens":5}}"#),
            None
        );
        assert_eq!(
            usage_of(r#"{"usage":{"prompt_tokens":10,"completion_tokens":5.5}}"#),
            None
        );
        assert_eq!(usage_of(r#"{"usage":{"prompt_tokens":10}}"#), None);
    }

    #[test]
    fn usage_survives_refusal_paths() {
        let u = r#","usage":{"prompt_tokens":4,"completion_tokens":1}"#;
        let (r, usage) = parse_reply_metered(&format!(
            r#"{{"choices":[{{"message":{{"content":null,"refusal":"no"}}}}]{u}}}"#
        ));
        assert!(matches!(r, Err(LlmError::Refused(_))));
        assert_eq!(usage.map(|u| u.input), Some(4));
        let (r, usage) = parse_reply_metered(&format!(
            r#"{{"choices":[{{"finish_reason":"content_filter","message":{{"content":""}}}}]{u}}}"#
        ));
        assert!(matches!(r, Err(LlmError::Refused(_))));
        assert!(usage.is_some());
    }

    #[test]
    fn error_status_bodies_keep_their_usage() {
        let body =
            r#"{"error":{"message":"bad"},"usage":{"prompt_tokens":12,"completion_tokens":3}}"#;
        for status in [400, 408, 429, 500] {
            let (r, usage) = decode_metered(reqwest::StatusCode::from_u16(status).unwrap(), body);
            assert!(matches!(r, Err(LlmError::Executor(_))), "{r:?}");
            assert_eq!(
                usage.map(|u| (u.input, u.output)),
                Some((12, 3)),
                "{status}"
            );
        }
        // Quota exhaustion keeps usage too.
        let (r, usage) = decode_metered(
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            r#"{"error":{"code":"insufficient_quota"},"usage":{"prompt_tokens":1,"completion_tokens":0}}"#,
        );
        assert!(matches!(r, Err(LlmError::UsageLimit(_))));
        assert_eq!(usage.map(|u| u.input), Some(1));
        // Non-JSON or usage-less error bodies: no usage.
        assert!(
            decode_metered(reqwest::StatusCode::BAD_GATEWAY, "<html>")
                .1
                .is_none()
        );
        assert!(
            decode_metered(reqwest::StatusCode::BAD_REQUEST, r#"{"error":{}}"#)
                .1
                .is_none()
        );
    }

    /// One-shot local server: reads one request, writes `head`, then the
    /// `chunks` (chunked encoding when `chunked`). Write errors (client hung
    /// up) are ignored.
    async fn one_shot(head: &'static str, chunked: bool, chunks: Vec<Vec<u8>>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            let head_end = loop {
                if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break p + 4;
                }
                match sock.read(&mut tmp).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                }
            };
            let want: usize = String::from_utf8_lossy(&buf[..head_end])
                .to_lowercase()
                .lines()
                .find_map(|l| {
                    l.strip_prefix("content-length:")
                        .map(|v| v.trim().to_string())
                })
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            while buf.len() < head_end + want {
                match sock.read(&mut tmp).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                }
            }
            if sock.write_all(head.as_bytes()).await.is_err() {
                return;
            }
            for data in chunks {
                let r = if chunked {
                    let mut frame = format!("{:x}\r\n", data.len()).into_bytes();
                    frame.extend_from_slice(&data);
                    frame.extend_from_slice(b"\r\n");
                    sock.write_all(&frame).await
                } else {
                    sock.write_all(&data).await
                };
                if r.is_err() {
                    return;
                }
            }
            if chunked {
                let _ = sock.write_all(b"0\r\n\r\n").await;
            }
            let _ = sock.shutdown().await;
        });
        format!("http://{addr}/v1")
    }

    fn local_caller(base: &str) -> OpenAiCompatCaller {
        let mut c = caller(base);
        c.spec.timeout = Duration::from_secs(20);
        // Never route the loopback test through a proxy from the environment.
        c.client = reqwest::Client::builder()
            .no_proxy()
            .timeout(c.spec.timeout)
            .build()
            .unwrap();
        c
    }

    #[tokio::test]
    async fn an_oversized_streamed_body_is_aborted() {
        // Chunked, no Content-Length: 9 MiB in 64 KiB chunks.
        let base = one_shot(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            true,
            vec![vec![b'a'; 64 * 1024]; 9 * 16],
        )
        .await;
        let m = local_caller(&base).complete_metered("p").await;
        let e = m.result.unwrap_err();
        assert!(e.to_string().contains("response too large"), "{e}");
        assert!(m.usage.is_none());
        assert_eq!(m.http_status, None);
    }

    #[tokio::test]
    async fn a_refundable_status_with_an_oversized_body_keeps_no_status() {
        let base = one_shot(
            "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            true,
            vec![vec![b'a'; 64 * 1024]; 9 * 16],
        )
        .await;
        let m = local_caller(&base).complete_metered("p").await;
        assert!(m.result.is_err());
        assert!(m.usage.is_none());
        assert_eq!(m.http_status, None, "guard must keep the worst-case charge");
    }

    #[tokio::test]
    async fn a_declared_oversized_body_is_refused_before_reading() {
        let base = one_shot(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 9000000\r\nConnection: close\r\n\r\n",
            false,
            vec![vec![b'a'; 1024]],
        )
        .await;
        let e = local_caller(&base).complete("p").await.unwrap_err();
        assert!(e.to_string().contains("bytes declared"), "{e}");
    }

    #[tokio::test]
    async fn a_body_within_the_cap_is_read_in_chunks() {
        let base = one_shot(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            true,
            vec![
                br#"{"choices":[{"message":{"content":"#.to_vec(),
                br#""ok"}}],"usage":{"prompt_tokens":2,"completion_tokens":1}}"#.to_vec(),
            ],
        )
        .await;
        let m = local_caller(&base).complete_metered("p").await;
        assert_eq!(m.result.unwrap(), "ok");
        assert_eq!(m.usage.map(|u| (u.input, u.output)), Some((2, 1)));
    }

    #[tokio::test]
    async fn missing_api_key_env_is_reported() {
        let mut c = caller("http://127.0.0.1:9");
        c.spec.api_key_env = Some("VETTALON_TEST_DEFINITELY_UNSET".into());
        let e = c.complete("p").await.unwrap_err();
        assert!(e.to_string().contains("VETTALON_TEST_DEFINITELY_UNSET"));
    }
}
