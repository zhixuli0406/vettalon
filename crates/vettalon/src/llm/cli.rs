//! Subscription CLIs run headless, one fresh process per call.
//!
//! Each call runs in a new empty temp directory, with a scrubbed environment
//! (only [`BASE_ENV`] plus the variables the CLI needs for auth), and with
//! the CLI's tools turned off where the CLI allows it: the audited code is
//! already in the prompt, and code from the repository is untrusted.
//!
//! Tool isolation differs by CLI (checked 2026-10-12):
//! - `claude`: `--tools ""` really leaves the model with no tools.
//! - `codex`: `--sandbox read-only` still lets its shell READ any file the
//!   user can read. User config, MCP servers, apps, hooks, plugins and
//!   memories are switched off.
//! - `grok`: `--tools ""` does NOT remove its tools; it can read files and
//!   run commands on the host.
//! - `agy` (Google Antigravity CLI, checked 2026-10-20 against 1.4.3): there
//!   is no flag that removes tools. Headless print mode auto-denies every
//!   tool that needs a permission (commands, file reads outside the empty
//!   workspace, file writes; tested: nothing was created or read), but
//!   `search_web` ran without one. The reply is discarded when the stream
//!   shows any tool step, so a verdict never rests on tool output. agy also
//!   loads the user's own rules (`~/.gemini/GEMINI.md`) and keeps its own
//!   conversation history; neither can be switched off.
//!
//! So [`TOOL_CAPABLE_PRESETS`] are refused unless the operator opts in with
//! `allow_agent_tools = true` (see `config.rs`); [`HOST_ONLY_PRESETS`] have
//! no container image and always need that opt-in.

use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use super::{LlmCaller, LlmError, Result};

/// Placeholder in `args` replaced by the prompt (`prompt_via = "arg"`).
pub const PROMPT_PLACEHOLDER: &str = "{prompt}";
/// Placeholder in `args` replaced by a file path the CLI writes its final
/// message to (`output = "file"`).
pub const OUTPUT_FILE_PLACEHOLDER: &str = "{output_file}";
/// Placeholder in `args` replaced by the path of a 0600 file holding the
/// prompt (`prompt_via = "file"`); keeps audited code out of `ps` output.
pub const PROMPT_FILE_PLACEHOLDER: &str = "{prompt_file}";
/// Placeholder replaced by the configured model name; the argument right
/// before it is dropped together with it when no model is configured.
pub const MODEL_PLACEHOLDER: &str = "{model}";

const OUTPUT_CAP_BYTES: usize = 4 * 1024 * 1024;

/// Presets whose model keeps tool access that can reach the host even with
/// the flags below. Using them needs an explicit opt-in.
pub const TOOL_CAPABLE_PRESETS: &[&str] = &["codex", "grok"];

/// Presets that keep tools AND have no container image (their login cannot
/// be copied into one), so they run on the host only, with the opt-in.
pub const HOST_ONLY_PRESETS: &[&str] = &["agy"];

/// Every built-in preset name.
pub const PRESETS: &[&str] = &["claude", "codex", "grok", "agy"];

/// Visible-reply budget per output token when a CLI cannot be told its
/// output cap: a reply longer than `max_output_tokens * 4` bytes is an
/// error, never truncated and used.
pub const CLI_REPLY_BYTES_PER_TOKEN: usize = 4;

/// Put in front of every agy prompt. agy has no switch to skip the user's
/// own rules, and without this a rule such as "first read the README" makes
/// it reach for a (denied) tool and return nothing.
pub const AGY_HEADLESS_PREAMBLE: &str = "This is a headless one-shot call with no workspace: do \
not call any tools and do not read any files; answer only from this message.";

/// Environment passed to every CLI; everything else is dropped so a model
/// that runs `env` cannot read the operator's other keys.
pub const BASE_ENV: &[&str] = &[
    "HOME",
    "PATH",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "TMPDIR",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "https_proxy",
    "http_proxy",
    "no_proxy",
];

/// Auth variables each preset may need (subscription logins use files under
/// HOME instead, which still work).
fn preset_env(name: &str) -> &'static [&'static str] {
    match name {
        "claude" => &[
            "ANTHROPIC_API_KEY",
            "CLAUDE_CONFIG_DIR",
            "CLAUDE_CODE_USE_BEDROCK",
            "CLAUDE_CODE_USE_VERTEX",
        ],
        "codex" => &["OPENAI_API_KEY", "CODEX_HOME"],
        "grok" => &["XAI_API_KEY", "GROK_HOME"],
        // Subscription login lives under HOME; no key variable exists.
        "agy" => &[],
        _ => &[],
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptVia {
    Stdin,
    Arg,
    File,
    /// stdin carries one agy stream-json user message
    /// (`{"event":"user","message":{"content":...}}`), so the prompt stays
    /// out of argv.
    AgyStreamJson,
}

/// Where the reply text comes from.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputMode {
    /// Raw stdout.
    Stdout,
    /// stdout is one JSON object; the reply is the string at this field.
    JsonField(String),
    /// The CLI writes its final message to `{output_file}`.
    File,
    /// agy `--output-format stream-json`: the reply is the final `result`
    /// event's `response`; any tool step, denied action or non-SUCCESS
    /// status makes the call an error.
    AgyStreamJson,
}

#[derive(Debug, Clone)]
pub struct CliSpec {
    pub program: String,
    pub args: Vec<String>,
    pub prompt_via: PromptVia,
    pub output: OutputMode,
    pub model: Option<String>,
    pub timeout: Duration,
    /// Extra environment variable names passed through on top of [`BASE_ENV`].
    pub env_passthrough: Vec<String>,
    /// Output cap per call (`max_tokens` in the roster). The visible reply
    /// may be at most `max_output_tokens * CLI_REPLY_BYTES_PER_TOKEN` bytes;
    /// a longer one is an error. Where the CLI reads a cap from the
    /// environment (`output_cap_env`), it is also set there.
    pub max_output_tokens: Option<u32>,
    /// Environment variable the CLI reads its per-request output cap from.
    pub output_cap_env: Option<String>,
}

impl CliSpec {
    /// Built-in presets. Flags were checked against claude 2.1.285,
    /// codex-cli 0.162.1, grok 1.0.50 and agy 1.4.3.
    pub fn preset(name: &str, model: Option<String>, timeout: Duration) -> Option<CliSpec> {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let (program, args, prompt_via, output) = match name {
            "claude" => (
                "claude",
                s(&[
                    "-p",
                    "--output-format",
                    "text",
                    "--tools",
                    "",
                    "--setting-sources",
                    "",
                    "--strict-mcp-config",
                    "--no-session-persistence",
                    "--model",
                    MODEL_PLACEHOLDER,
                ]),
                PromptVia::Stdin,
                OutputMode::Stdout,
            ),
            "codex" => (
                "codex",
                s(&[
                    "exec",
                    "--sandbox",
                    "read-only",
                    "--skip-git-repo-check",
                    "--ephemeral",
                    "--ignore-rules",
                    "--ignore-user-config",
                    "--disable",
                    "apps",
                    "--disable",
                    "browser_use",
                    "--disable",
                    "computer_use",
                    "--disable",
                    "hooks",
                    "--disable",
                    "memories",
                    "--disable",
                    "plugins",
                    "--color",
                    "never",
                    "-o",
                    OUTPUT_FILE_PLACEHOLDER,
                    "-m",
                    MODEL_PLACEHOLDER,
                    "-",
                ]),
                PromptVia::Stdin,
                OutputMode::File,
            ),
            "grok" => (
                "grok",
                s(&[
                    "--prompt-file",
                    PROMPT_FILE_PLACEHOLDER,
                    "--output-format",
                    "json",
                    "--tools",
                    "",
                    "--disable-web-search",
                    "--no-subagents",
                    "-m",
                    MODEL_PLACEHOLDER,
                ]),
                PromptVia::File,
                OutputMode::JsonField("text".into()),
            ),
            "agy" => (
                "agy",
                s(&[
                    "--input-format",
                    "stream-json",
                    "--output-format",
                    "stream-json",
                    "--disable-slash-commands",
                    "--sandbox",
                    "--model",
                    MODEL_PLACEHOLDER,
                    // Print mode; the prompt arrives on stdin, never in argv.
                    "-p=",
                ]),
                PromptVia::AgyStreamJson,
                OutputMode::AgyStreamJson,
            ),
            _ => return None,
        };
        Some(CliSpec {
            program: program.into(),
            args,
            prompt_via,
            output,
            model,
            timeout,
            env_passthrough: preset_env(name).iter().map(|v| v.to_string()).collect(),
            max_output_tokens: None,
            output_cap_env: (name == "claude").then(|| "CLAUDE_CODE_MAX_OUTPUT_TOKENS".to_string()),
        })
    }

    /// What goes to the CLI's stdin for `prompt`.
    pub fn stdin_payload(&self, prompt: &str) -> Vec<u8> {
        match self.prompt_via {
            PromptVia::Stdin => prompt.as_bytes().to_vec(),
            PromptVia::AgyStreamJson => agy_stream_message(prompt),
            PromptVia::Arg | PromptVia::File => Vec::new(),
        }
    }

    /// Error when a reply is longer than the output cap allows.
    pub fn check_output_cap(&self, reply: &str) -> Result<()> {
        let Some(cap) = self.max_output_tokens else {
            return Ok(());
        };
        let limit = cap as usize * CLI_REPLY_BYTES_PER_TOKEN;
        if reply.len() > limit {
            return Err(LlmError::Executor(format!(
                "{} reply is {} bytes, over the output cap ({cap} tokens = {limit} bytes)",
                self.program,
                reply.len()
            )));
        }
        Ok(())
    }

    /// Final argv (without the program). Pure, for tests.
    pub fn render_args(&self, prompt: &str, output_file: &str) -> Vec<String> {
        self.render_args_with(prompt, output_file, "")
    }

    /// [`Self::render_args`] with the prompt-file path.
    pub fn render_args_with(
        &self,
        prompt: &str,
        output_file: &str,
        prompt_file: &str,
    ) -> Vec<String> {
        let mut out: Vec<String> = Vec::with_capacity(self.args.len());
        for a in &self.args {
            if a == MODEL_PLACEHOLDER {
                match &self.model {
                    Some(m) => out.push(m.clone()),
                    // Drop the flag that introduced the placeholder.
                    None => {
                        out.pop();
                    }
                }
                continue;
            }
            out.push(
                a.replace(OUTPUT_FILE_PLACEHOLDER, output_file)
                    .replace(PROMPT_FILE_PLACEHOLDER, prompt_file)
                    .replace(PROMPT_PLACEHOLDER, prompt),
            );
        }
        out
    }
}

pub struct CliCaller {
    pub spec: CliSpec,
}

#[async_trait]
impl LlmCaller for CliCaller {
    async fn complete(&self, prompt: &str) -> Result<String> {
        let bin = crate::util::which_cli(&self.spec.program).ok_or_else(|| {
            LlmError::Executor(format!("{} CLI not found on PATH", self.spec.program))
        })?;
        let workdir = tempfile::Builder::new()
            .prefix("vettalon-llm-")
            .tempdir()
            .map_err(|e| LlmError::Executor(format!("cannot create temp dir: {e}")))?;
        let out_file = workdir.path().join("last-message.txt");
        let prompt_file = workdir.path().join("prompt.txt");
        if self.spec.prompt_via == PromptVia::File {
            std::fs::write(&prompt_file, prompt)
                .and_then(|_| crate::util::set_owner_only(&prompt_file))
                .map_err(|e| LlmError::Executor(format!("cannot write prompt file: {e}")))?;
        }
        let arg_prompt = if self.spec.prompt_via == PromptVia::Arg {
            prompt
        } else {
            ""
        };
        let args = self.spec.render_args_with(
            arg_prompt,
            &out_file.to_string_lossy(),
            &prompt_file.to_string_lossy(),
        );

        let mut cmd = Command::new(&bin);
        cmd.args(&args).env_clear();
        for name in BASE_ENV
            .iter()
            .copied()
            .chain(self.spec.env_passthrough.iter().map(String::as_str))
        {
            if let Ok(v) = std::env::var(name) {
                cmd.env(name, v);
            }
        }
        if let (Some(cap), Some(var)) = (self.spec.max_output_tokens, &self.spec.output_cap_env) {
            cmd.env(var, cap.to_string());
        }
        // Own process group, so a timeout kills the CLI's children too.
        #[cfg(unix)]
        cmd.process_group(0);
        let mut child = cmd
            .current_dir(workdir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| LlmError::Executor(format!("cannot start {bin}: {e}")))?;

        let pid = child.id();
        let mut stdin = child.stdin.take().expect("piped stdin");
        let to_send = self.spec.stdin_payload(prompt);
        let mut stdout = child.stdout.take().expect("piped stdout");
        let mut stderr = child.stderr.take().expect("piped stderr");

        let run = async {
            let write = async {
                let r = stdin.write_all(&to_send).await;
                drop(stdin);
                r
            };
            let (w, out, err) = tokio::join!(
                write,
                crate::util::read_capped(&mut stdout, OUTPUT_CAP_BYTES),
                crate::util::read_capped(&mut stderr, OUTPUT_CAP_BYTES)
            );
            let status = child.wait().await;
            let out = out.map(|(b, _)| b).unwrap_or_default();
            let err = err.map(|(b, _)| b).unwrap_or_default();
            (w, status, out, err)
        };
        let (write_res, status, out, err) = match tokio::time::timeout(self.spec.timeout, run).await
        {
            Ok(r) => r,
            Err(_) => {
                kill_group(pid);
                return Err(LlmError::Executor(format!(
                    "{} timed out after {}s",
                    self.spec.program,
                    self.spec.timeout.as_secs()
                )));
            }
        };
        if let Err(e) = write_res {
            return Err(LlmError::Executor(format!("cannot write prompt: {e}")));
        }
        let status = status.map_err(|e| LlmError::Executor(format!("wait failed: {e}")))?;
        let stdout_text = String::from_utf8_lossy(&out).to_string();
        if !status.success() {
            let tail = String::from_utf8_lossy(&err);
            let tail = crate::util::mask_sensitive_text(tail.trim());
            return Err(LlmError::Executor(format!(
                "{} exited with {}: {}",
                self.spec.program,
                status,
                crate::util::truncate_bytes(&tail, 400)
            )));
        }
        let reply = extract_reply(&self.spec.output, &stdout_text, &out_file)?;
        self.spec.check_output_cap(&reply)?;
        Ok(reply)
    }
}

/// One agy stream-json user message holding `prompt` (with
/// [`AGY_HEADLESS_PREAMBLE`] in front), newline-terminated.
pub fn agy_stream_message(prompt: &str) -> Vec<u8> {
    let content = format!("{AGY_HEADLESS_PREAMBLE}\n\n{prompt}");
    let mut line = serde_json::json!({"event": "user", "message": {"content": content}})
        .to_string()
        .into_bytes();
    line.push(b'\n');
    line
}

/// The reply in an agy stream-json transcript. Fails closed: a tool step
/// (even one the CLI allowed), a denied action, a non-SUCCESS status or an
/// empty response is an error, never a verdict.
pub fn parse_agy_stream(stdout: &str) -> Result<String> {
    let mut result: Option<serde_json::Value> = None;
    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        match v.get("event").and_then(|e| e.as_str()) {
            Some("step_update") => {
                let step = &v["step_update"];
                if step.get("step_type").and_then(|t| t.as_str()) == Some("tool") {
                    let tool = step
                        .get("tool_name")
                        .and_then(|t| t.as_str())
                        .unwrap_or("unknown");
                    return Err(LlmError::Executor(format!(
                        "agy used a tool ({tool}); reply discarded"
                    )));
                }
            }
            Some("result") => result = Some(v["result"].clone()),
            _ => {}
        }
    }
    let r = result.ok_or_else(|| LlmError::Executor("agy stream has no result event".into()))?;
    let status = r.get("status").and_then(|s| s.as_str()).unwrap_or("");
    if status != "SUCCESS" {
        let err = r
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("no error text");
        return Err(LlmError::Executor(format!(
            "agy status {status:?}: {}",
            crate::util::truncate_bytes(&crate::util::mask_sensitive_text(err), 300)
        )));
    }
    if let Some(denied) = r.get("denied_actions").and_then(|d| d.as_array())
        && !denied.is_empty()
    {
        let names: Vec<&str> = denied
            .iter()
            .filter_map(|d| d.get("action").and_then(|a| a.as_str()))
            .collect();
        return Err(LlmError::Executor(format!(
            "agy tried a denied tool ({}); no reply",
            names.join(", ")
        )));
    }
    let response = r.get("response").and_then(|x| x.as_str()).unwrap_or("");
    if response.trim().is_empty() {
        return Err(LlmError::Executor("agy returned an empty response".into()));
    }
    Ok(response.to_string())
}

/// SIGKILL the whole process group of a timed-out CLI.
fn kill_group(pid: Option<u32>) {
    #[cfg(unix)]
    if let Some(pid) = pid {
        let _ = std::process::Command::new("kill")
            .args(["-KILL", &format!("-{pid}")])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(not(unix))]
    let _ = pid;
}

fn extract_reply(mode: &OutputMode, stdout: &str, out_file: &std::path::Path) -> Result<String> {
    match mode {
        OutputMode::Stdout => Ok(stdout.to_string()),
        OutputMode::AgyStreamJson => parse_agy_stream(stdout),
        OutputMode::File => {
            let len = std::fs::metadata(out_file)
                .map_err(|e| LlmError::Executor(format!("CLI wrote no final message: {e}")))?
                .len();
            if len > OUTPUT_CAP_BYTES as u64 {
                return Err(LlmError::Executor(format!(
                    "CLI final message too large ({len} bytes)"
                )));
            }
            std::fs::read_to_string(out_file)
                .map_err(|e| LlmError::Executor(format!("CLI wrote no final message: {e}")))
        }
        OutputMode::JsonField(field) => {
            let v: serde_json::Value = serde_json::from_str(stdout.trim()).map_err(|e| {
                LlmError::Executor(format!("CLI stdout is not the expected JSON envelope: {e}"))
            })?;
            v.get(field)
                .and_then(|x| x.as_str())
                .map(str::to_string)
                .ok_or_else(|| {
                    LlmError::Executor(format!("CLI JSON envelope has no {field:?} string"))
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_exist_and_drop_the_model_flag_when_unset() {
        for name in PRESETS {
            let spec = CliSpec::preset(name, None, Duration::from_secs(1)).unwrap();
            let args = spec.render_args("P", "/o");
            assert!(
                !args.iter().any(|a| a == "--model" || a == "-m"),
                "{name}: {args:?}"
            );
            assert!(!args.iter().any(|a| a.contains('{')), "{name}: {args:?}");
        }
        assert!(CliSpec::preset("nope", None, Duration::from_secs(1)).is_none());
    }

    #[test]
    fn model_placeholder_is_filled_when_set() {
        let spec = CliSpec::preset("claude", Some("opus".into()), Duration::from_secs(1)).unwrap();
        let args = spec.render_args("", "/o");
        let i = args.iter().position(|a| a == "--model").unwrap();
        assert_eq!(args[i + 1], "opus");
    }

    #[test]
    fn claude_preset_disables_tools_and_user_settings() {
        let a = CliSpec::preset("claude", None, Duration::from_secs(1))
            .unwrap()
            .render_args("", "/o");
        let t = a.iter().position(|x| x == "--tools").unwrap();
        assert_eq!(a[t + 1], "");
        assert!(a.iter().any(|x| x == "--strict-mcp-config"));
    }

    #[test]
    fn codex_preset_is_read_only_and_writes_output_file() {
        let a = CliSpec::preset("codex", None, Duration::from_secs(1))
            .unwrap()
            .render_args("", "/tmp/out.txt");
        let s = a.iter().position(|x| x == "--sandbox").unwrap();
        assert_eq!(a[s + 1], "read-only");
        assert!(a.iter().any(|x| x == "/tmp/out.txt"));
        assert_eq!(a.last().unwrap(), "-");
    }

    #[test]
    fn grok_preset_passes_prompt_through_a_file() {
        let spec = CliSpec::preset("grok", None, Duration::from_secs(1)).unwrap();
        assert_eq!(spec.prompt_via, PromptVia::File);
        let a = spec.render_args_with("secret code", "/o", "/tmp/p.txt");
        let p = a.iter().position(|x| x == "--prompt-file").unwrap();
        assert_eq!(a[p + 1], "/tmp/p.txt");
        assert!(!a.iter().any(|x| x.contains("secret code")));
    }

    #[test]
    fn agy_preset_sends_the_prompt_on_stdin_as_stream_json() {
        let spec = CliSpec::preset("agy", Some("gemini-x".into()), Duration::from_secs(1)).unwrap();
        assert_eq!(spec.prompt_via, PromptVia::AgyStreamJson);
        assert_eq!(spec.output, OutputMode::AgyStreamJson);
        let a = spec.render_args_with("secret code", "/o", "/p");
        assert!(!a.iter().any(|x| x.contains("secret code")), "{a:?}");
        for flag in ["--disable-slash-commands", "--sandbox"] {
            assert!(a.iter().any(|x| x == flag), "{flag}: {a:?}");
        }
        let f = a.iter().position(|x| x == "--input-format").unwrap();
        assert_eq!(a[f + 1], "stream-json");
        // `-p=` must come last: agy would take the next flag as the prompt.
        assert_eq!(a.last().unwrap(), "-p=");
        let m = a.iter().position(|x| x == "--model").unwrap();
        assert_eq!(a[m + 1], "gemini-x");
        let line = spec.stdin_payload("secret code\n\"quoted\"");
        assert_eq!(*line.last().unwrap(), b'\n');
        let v: serde_json::Value = serde_json::from_slice(&line).unwrap();
        assert_eq!(v["event"], "user");
        let content = v["message"]["content"].as_str().unwrap();
        assert!(content.starts_with(AGY_HEADLESS_PREAMBLE));
        assert!(content.ends_with("secret code\n\"quoted\""));
        assert!(TOOL_CAPABLE_PRESETS.iter().all(|p| *p != "agy"));
        assert!(HOST_ONLY_PRESETS.contains(&"agy"));
    }

    fn agy_stream(steps: &[&str], result: &str) -> String {
        let mut out = String::from("{\"event\":\"init\",\"init\":{\"tools\":[\"run_command\"]}}\n");
        for s in steps {
            out.push_str(s);
            out.push('\n');
        }
        out.push_str(result);
        out.push('\n');
        out
    }

    #[test]
    fn agy_stream_reply_and_fail_closed_cases() {
        let ok = agy_stream(
            &[
                r#"{"event":"step_update","step_update":{"step_type":"agent_response","text_delta":"x"}}"#,
            ],
            r#"{"event":"result","result":{"status":"SUCCESS","response":"{\"verdict\":\"refuted\"}\n"}}"#,
        );
        assert_eq!(
            parse_agy_stream(&ok).unwrap(),
            "{\"verdict\":\"refuted\"}\n"
        );
        // A tool step discards the reply even when the tool was allowed.
        let tool = agy_stream(
            &[
                r#"{"event":"step_update","step_update":{"step_type":"tool","tool_name":"search_web","state":"DONE"}}"#,
            ],
            r#"{"event":"result","result":{"status":"SUCCESS","response":"looks fine"}}"#,
        );
        assert!(
            parse_agy_stream(&tool)
                .unwrap_err()
                .to_string()
                .contains("search_web")
        );
        let denied = agy_stream(
            &[],
            r#"{"event":"result","result":{"status":"SUCCESS","response":"","denied_actions":[{"action":"command"}]}}"#,
        );
        assert!(
            parse_agy_stream(&denied)
                .unwrap_err()
                .to_string()
                .contains("command")
        );
        let failed = agy_stream(
            &[],
            r#"{"event":"result","result":{"status":"ERROR","error":"authentication failed","response":""}}"#,
        );
        assert!(
            parse_agy_stream(&failed)
                .unwrap_err()
                .to_string()
                .contains("authentication")
        );
        let empty = agy_stream(
            &[],
            r#"{"event":"result","result":{"status":"SUCCESS","response":"  "}}"#,
        );
        assert!(parse_agy_stream(&empty).is_err());
        assert!(parse_agy_stream("not json at all").is_err());
    }

    #[tokio::test]
    async fn output_cap_rejects_long_replies_and_reaches_the_cli_env() {
        let mut spec = CliSpec {
            program: "cat".into(),
            args: vec![],
            prompt_via: PromptVia::Stdin,
            output: OutputMode::Stdout,
            model: None,
            timeout: Duration::from_secs(5),
            env_passthrough: vec![],
            max_output_tokens: Some(2),
            output_cap_env: None,
        };
        let c = CliCaller { spec: spec.clone() };
        assert_eq!(c.complete("12345678").await.unwrap(), "12345678");
        let err = c.complete("123456789").await.unwrap_err().to_string();
        assert!(err.contains("output cap"), "{err}");
        spec.program = "env".into();
        spec.max_output_tokens = Some(4000);
        spec.output_cap_env = Some("VETTALON_TEST_CAP_VAR".into());
        let out = CliCaller { spec }.complete("").await.unwrap();
        assert!(out.contains("VETTALON_TEST_CAP_VAR=4000"), "{out}");
        let claude = CliSpec::preset("claude", None, Duration::from_secs(1)).unwrap();
        assert_eq!(
            claude.output_cap_env.as_deref(),
            Some("CLAUDE_CODE_MAX_OUTPUT_TOKENS")
        );
    }

    #[test]
    fn codex_preset_drops_user_config_and_extensions() {
        let a = CliSpec::preset("codex", None, Duration::from_secs(1))
            .unwrap()
            .render_args("", "/o");
        assert!(a.iter().any(|x| x == "--ignore-user-config"));
        for f in ["apps", "hooks", "plugins", "memories"] {
            assert!(
                a.windows(2).any(|w| w[0] == "--disable" && w[1] == f),
                "{f}"
            );
        }
    }

    /// The child sees only the allowlisted environment.
    #[tokio::test]
    async fn environment_is_scrubbed() {
        // SAFETY: test-only; no other test reads this variable.
        unsafe { std::env::set_var("VETTALON_TEST_LEAK_KEY", "sk-should-not-leak") };
        let c = CliCaller {
            spec: CliSpec {
                program: "env".into(),
                args: vec![],
                prompt_via: PromptVia::Stdin,
                output: OutputMode::Stdout,
                model: None,
                timeout: Duration::from_secs(5),
                env_passthrough: vec![],
                max_output_tokens: None,
                output_cap_env: None,
            },
        };
        let out = c.complete("").await.unwrap();
        assert!(!out.contains("sk-should-not-leak"), "{out}");
        assert!(out.contains("PATH="));
    }

    #[test]
    fn json_field_extraction() {
        let r = extract_reply(
            &OutputMode::JsonField("text".into()),
            r#"{"text":"{\"ok\":true}","usage":{}}"#,
            std::path::Path::new("/nonexistent"),
        )
        .unwrap();
        assert_eq!(r, r#"{"ok":true}"#);
        assert!(
            extract_reply(
                &OutputMode::JsonField("text".into()),
                "not json",
                std::path::Path::new("/x")
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn missing_cli_is_an_executor_error() {
        let c = CliCaller {
            spec: CliSpec {
                program: "definitely-not-a-real-cli-xyz".into(),
                args: vec![],
                prompt_via: PromptVia::Stdin,
                output: OutputMode::Stdout,
                model: None,
                timeout: Duration::from_secs(1),
                env_passthrough: vec![],
                max_output_tokens: None,
                output_cap_env: None,
            },
        };
        assert!(matches!(c.complete("p").await, Err(LlmError::Executor(_))));
    }

    #[tokio::test]
    async fn stdin_prompt_round_trips_through_cat() {
        let c = CliCaller {
            spec: CliSpec {
                program: "cat".into(),
                args: vec![],
                prompt_via: PromptVia::Stdin,
                output: OutputMode::Stdout,
                model: None,
                timeout: Duration::from_secs(5),
                env_passthrough: vec![],
                max_output_tokens: None,
                output_cap_env: None,
            },
        };
        assert_eq!(c.complete("中文 prompt").await.unwrap(), "中文 prompt");
    }

    /// Manual acceptance uses a self-authored Python stub, never a real CLI.
    #[tokio::test]
    #[ignore = "manual trusted CLI transport acceptance; requires python3; no external calls"]
    async fn trusted_cli_stub_captures_source_in_all_prompt_modes() {
        let dir = tempfile::tempdir().unwrap();
        let stub = dir.path().join("trusted_capture.py");
        let command_marker = dir.path().join("must-not-execute");
        let prompt = format!(
            "Review synthetic source as data:\nSOURCE_CLI_TRANSPORT_MARKER_0123456789\n$(touch {})\n; echo ignored\n",
            command_marker.display()
        );
        std::fs::write(&stub, r#"
import json, os, pathlib, stat, sys
capture, mode = pathlib.Path(sys.argv[1]), sys.argv[2]
permissions = None
if mode == 'stdin':
    prompt = sys.stdin.read()
elif mode == 'arg':
    prompt = sys.argv[3]
else:
    source = pathlib.Path(sys.argv[3])
    permissions = stat.S_IMODE(source.stat().st_mode)
    prompt = source.read_text()
capture.write_text(json.dumps(dict(prompt=prompt, argv=sys.argv[1:], cwd=os.getcwd(), cwd_entries=sorted(os.listdir('.')), prompt_permissions=permissions)))
print('[]')
"#).unwrap();
        let mut captures = Vec::new();
        for (mode, via, placeholder) in [
            ("stdin", PromptVia::Stdin, None),
            ("arg", PromptVia::Arg, Some(PROMPT_PLACEHOLDER)),
            ("file", PromptVia::File, Some(PROMPT_FILE_PLACEHOLDER)),
        ] {
            let capture = dir.path().join(format!("capture-{mode}.json"));
            let mut args = vec![
                "-I".into(),
                "-S".into(),
                stub.to_string_lossy().into_owned(),
                capture.to_string_lossy().into_owned(),
                mode.into(),
            ];
            if let Some(value) = placeholder {
                args.push(value.into());
            }
            let caller = CliCaller {
                spec: CliSpec {
                    program: "python3".into(),
                    args,
                    prompt_via: via,
                    output: OutputMode::Stdout,
                    model: None,
                    timeout: Duration::from_secs(5),
                    env_passthrough: vec![],
                    max_output_tokens: None,
                    output_cap_env: None,
                },
            };
            assert_eq!(caller.complete(&prompt).await.unwrap().trim(), "[]");
            let record: serde_json::Value =
                serde_json::from_slice(&std::fs::read(capture).unwrap()).unwrap();
            assert_eq!(record["prompt"], prompt);
            assert!(
                !command_marker.exists(),
                "prompt was interpreted as a shell command"
            );
            let cwd = std::path::Path::new(record["cwd"].as_str().unwrap());
            assert_ne!(cwd, dir.path());
            assert!(
                cwd.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("vettalon-llm-")
            );
            assert!(!cwd.exists(), "disposable child cwd was not cleaned up");
            if mode == "file" {
                #[cfg(unix)]
                assert_eq!(record["prompt_permissions"], 0o600);
                assert_eq!(record["cwd_entries"], serde_json::json!(["prompt.txt"]));
            } else {
                assert_eq!(record["cwd_entries"], serde_json::json!([]));
            }
            let prompt_in_argv = record["argv"].as_array().unwrap().iter().any(|value| {
                value
                    .as_str()
                    .is_some_and(|s| s.contains("SOURCE_CLI_TRANSPORT_MARKER"))
            });
            assert_eq!(prompt_in_argv, mode == "arg");
            captures.push(serde_json::json!({"mode":mode,"capture":record}));
        }
        let result = serde_json::json!({"kind":"trusted-synthetic-cli-subprocess-capture","calls":3,"real_provider_calls":0,"shell_execution":false,"captures":captures,"boundary":"Vettalon-to-child prompt transfer only; real Claude/Codex/Grok network, retention and internal tool behavior remain unknown"});
        if let Some(output) = std::env::var_os("VETTALON_TRANSPORT_EVIDENCE_DIR") {
            let output = std::path::PathBuf::from(output);
            std::fs::create_dir_all(&output).unwrap();
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output.join("cli-subprocess.json"))
                .expect("evidence output must not already exist");
            file.write_all(&serde_json::to_vec_pretty(&result).unwrap())
                .unwrap();
        }
        println!(
            "Trusted CLI capture: stdin/arg/file=3, source observed, no shell execution, real providers=0"
        );
    }
}
