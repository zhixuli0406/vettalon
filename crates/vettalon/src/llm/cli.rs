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
//!
//! So [`TOOL_CAPABLE_PRESETS`] are refused unless the operator opts in with
//! `allow_agent_tools = true` (see `config.rs`).

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
        _ => &[],
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptVia {
    Stdin,
    Arg,
    File,
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
}

impl CliSpec {
    /// Built-in presets. Flags were checked against claude 2.1.285,
    /// codex-cli 0.162.1 and grok 1.0.50.
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
        })
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
        let to_send = if self.spec.prompt_via == PromptVia::Stdin {
            prompt.as_bytes().to_vec()
        } else {
            Vec::new()
        };
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
        extract_reply(&self.spec.output, &stdout_text, &out_file)
    }
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
        for name in ["claude", "codex", "grok"] {
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
            },
        };
        assert_eq!(c.complete("中文 prompt").await.unwrap(), "中文 prompt");
    }
}
