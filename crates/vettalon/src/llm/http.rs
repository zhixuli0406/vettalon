//! OpenAI-compatible `POST {base_url}/chat/completions`. Covers OpenRouter,
//! DeepSeek, Qwen (DashScope compat), GLM, Gemini's OpenAI endpoint, Groq,
//! Together, Mistral, xAI and local Ollama / llama.cpp / vLLM servers.

use std::time::Duration;

use async_trait::async_trait;
use serde_json::json;

use super::{LlmCaller, LlmError, Result};

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
        format!("{}/chat/completions", self.spec.base_url.trim_end_matches('/'))
    }

    pub fn body(&self, prompt: &str) -> serde_json::Value {
        json!({
            "model": self.spec.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": self.spec.max_tokens,
            "temperature": self.spec.temperature,
            "stream": false,
        })
    }
}

#[async_trait]
impl LlmCaller for OpenAiCompatCaller {
    async fn complete(&self, prompt: &str) -> Result<String> {
        let mut req = self.client.post(self.endpoint()).json(&self.body(prompt));
        if let Some(var) = &self.spec.api_key_env {
            let key = std::env::var(var).map_err(|_| {
                LlmError::Executor(format!("environment variable {var} is not set"))
            })?;
            req = req.bearer_auth(key);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| {
                // reqwest errors embed the URL; some gateways carry keys in it.
                LlmError::Executor(format!("request failed: {}", e.without_url()))
            })?;
        let status = resp.status();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| LlmError::Executor(format!("cannot read response: {}", e.without_url())))?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(LlmError::Executor(format!("response too large ({} bytes)", bytes.len())));
        }
        let text = String::from_utf8_lossy(&bytes).to_string();
        if !status.is_success() {
            return Err(LlmError::Executor(format!(
                "HTTP {status}: {}",
                crate::util::truncate_bytes(&crate::util::mask_sensitive_text(&text), 400)
            )));
        }
        parse_reply(&text)
    }
}

/// Pull `choices[0].message.content`. A provider-side refusal field
/// (`message.refusal`, OpenAI) is surfaced as [`LlmError::Refused`].
pub fn parse_reply(body: &str) -> Result<String> {
    let v: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| LlmError::Executor(format!("response is not JSON: {e}")))?;
    let msg = &v["choices"][0]["message"];
    if let Some(r) = msg["refusal"].as_str()
        && !r.trim().is_empty()
    {
        return Err(LlmError::Refused(crate::util::truncate_bytes(r, 400).to_string()));
    }
    if v["choices"][0]["finish_reason"].as_str() == Some("content_filter") {
        return Err(LlmError::Refused("provider content filter".into()));
    }
    msg["content"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| LlmError::Executor("response has no choices[0].message.content".into()))
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
            parse_reply(r#"{"choices":[{"finish_reason":"content_filter","message":{"content":""}}]}"#),
            Err(LlmError::Refused(_))
        ));
        assert!(matches!(parse_reply("nope"), Err(LlmError::Executor(_))));
    }

    #[tokio::test]
    async fn missing_api_key_env_is_reported() {
        let mut c = caller("http://127.0.0.1:9");
        c.spec.api_key_env = Some("VETTALON_TEST_DEFINITELY_UNSET".into());
        let e = c.complete("p").await.unwrap_err();
        assert!(e.to_string().contains("VETTALON_TEST_DEFINITELY_UNSET"));
    }
}
