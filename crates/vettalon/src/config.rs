//! `vettalon.toml`: the model roster.
//!
//! No model is hardcoded anywhere else. Without a config file the roster is
//! auto-detected from the CLIs on `PATH` whose tools can be fully disabled
//! (today: claude). CLIs that keep host access (codex, grok; see
//! `llm::cli`) are added through a config file; they run in the agents
//! container by default (`vettalon agents build`), or on the host with
//! `allow_agent_tools = true`. API keys are never stored in the file: a
//! model names the environment variable that holds its key (`api_key_env`).
//!
//! The config file is trusted code (it chooses programs to run and where
//! keys go), so it is never read from the repository being scanned.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::llm::cli::{CliCaller, CliSpec, OutputMode, PromptVia};
use crate::llm::http::{HttpSpec, OpenAiCompatCaller};
use crate::llm::{LlmCaller, ModelHandle, RefusalAware};

pub const DEFAULT_OLLAMA_URL: &str = "http://localhost:11434/v1";
const DEFAULT_TIMEOUT_SECS: u64 = 900;
const DEFAULT_MAX_TOKENS: u32 = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Hunts for vulnerabilities, one module at a time.
    Finder,
    /// Tries to refute other models' findings.
    Verifier,
    /// Writes PoC scripts for the sandbox.
    Poc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    Cli,
    Openai,
    Ollama,
}

// `skip_serializing_if` keeps the written TOML (and the JSON a GUI reads)
// free of empty/default fields, so a round-trip through the config editor
// does not bloat the file with `foo = null` noise.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelConfig {
    pub id: String,
    pub backend: Backend,
    /// Vendor family. Defaults from the CLI preset; required otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default = "default_roles")]
    pub roles: Vec<Role>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
    /// Required for CLIs whose model keeps tools that can read the host
    /// (codex, grok, any custom `program`): the operator accepts that a
    /// prompt injection in audited code could make it read local files.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_agent_tools: bool,
    /// Extra environment variable names passed to a CLI.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_passthrough: Vec<String>,
    // ── cli ──
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_via: Option<PromptVia>,
    /// `"stdout"`, `"file"`, or `"json:<field>"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    // ── openai / ollama ──
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key_env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn default_roles() -> Vec<Role> {
    vec![Role::Finder, Role::Verifier, Role::Poc]
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, rename = "model")]
    pub models: Vec<ModelConfig>,
    /// Optional metadata-only module ranker (TypeSafe Jev). Present only when
    /// the operator opts in via `--rank jev`; heuristic ranking itself is local.
    /// Cloud model calls and scanner database updates have separate network
    /// boundaries. Never holds a key value — only where to find one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jev: Option<JevSettings>,
}

/// Config for the Jev metadata-only ranker. Like a model's `api_key_env`,
/// this stores only where the key lives, never the key itself. The key is
/// resolved at call time and never logged or written back.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JevSettings {
    /// Name of the environment variable holding the API key (preferred).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key_env: Option<String>,
    /// Absolute path to a 0600 file holding the API key (used when
    /// `api_key_env` is unset or its variable is empty).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key_file: Option<PathBuf>,
    /// API base (default `https://api.typesafe.ai`). Must be https.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// Model id (default `jev-latest`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Rejected if present: a key must never be inlined into the config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
}

impl JevSettings {
    pub fn base_url(&self) -> &str {
        self.base_url
            .as_deref()
            .unwrap_or("https://api.typesafe.ai")
    }

    pub fn model(&self) -> &str {
        self.model.as_deref().unwrap_or("jev-latest")
    }

    /// Resolve the API key at call time: the env var if set and non-empty,
    /// else the key file (trimmed). Never cached, logged or serialized.
    pub fn resolve_key(&self) -> Result<String, String> {
        if let Some(var) = &self.api_key_env
            && let Ok(v) = std::env::var(var)
            && !v.trim().is_empty()
        {
            return Ok(v.trim().to_string());
        }
        if let Some(path) = &self.api_key_file {
            let raw = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read Jev key file {}: {e}", path.display()))?;
            let key = raw.trim().to_string();
            if key.is_empty() {
                return Err(format!("Jev key file {} is empty", path.display()));
            }
            return Ok(key);
        }
        Err("no Jev API key configured (set [jev].api_key_env or [jev].api_key_file)".to_string())
    }
}

fn preset_family(preset: &str) -> Option<&'static str> {
    match preset {
        "claude" => Some("anthropic"),
        "codex" => Some("openai"),
        "grok" => Some("xai"),
        _ => None,
    }
}

impl Config {
    pub fn parse(text: &str) -> Result<Config, String> {
        let cfg: Config = toml::from_str(text).map_err(|e| format!("invalid config: {e}"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load(path: &Path) -> Result<Config, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        Config::parse(&text)
    }

    /// Roster from the CLIs found on `PATH` whose tools can be disabled.
    /// Returns the tool-capable CLIs that were found but left out.
    pub fn autodetect() -> (Config, Vec<&'static str>) {
        let skipped: Vec<&'static str> = crate::llm::cli::TOOL_CAPABLE_PRESETS
            .iter()
            .copied()
            .filter(|p| crate::util::which_cli(p).is_some())
            .collect();
        let models = ["claude"]
            .iter()
            .filter(|p| crate::util::which_cli(p).is_some())
            .map(|p| ModelConfig {
                id: p.to_string(),
                backend: Backend::Cli,
                family: None,
                model: None,
                roles: default_roles(),
                timeout_secs: None,
                allow_agent_tools: false,
                env_passthrough: Vec::new(),
                preset: Some(p.to_string()),
                program: None,
                args: None,
                prompt_via: None,
                output: None,
                base_url: None,
                api_key_env: None,
                max_tokens: None,
                temperature: None,
            })
            .collect();
        (Config { models, jev: None }, skipped)
    }

    pub fn validate(&self) -> Result<(), String> {
        let mut ids = HashSet::new();
        for m in &self.models {
            if m.id.is_empty()
                || !m
                    .id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
            {
                return Err(format!(
                    "model id {:?} must be non-empty [A-Za-z0-9._-]",
                    m.id
                ));
            }
            if !ids.insert(m.id.as_str()) {
                return Err(format!("duplicate model id {:?}", m.id));
            }
            if m.roles.is_empty() {
                return Err(format!("model {:?} has no roles", m.id));
            }
            match m.backend {
                Backend::Cli => {
                    if m.preset.is_none() && m.program.is_none() {
                        return Err(format!("cli model {:?} needs `preset` or `program`", m.id));
                    }
                    // A custom program cannot be containerized automatically
                    // (the agents image has no such binary), so it may only
                    // run on the host, and only with the explicit opt-in.
                    if m.program.is_some() && !m.allow_agent_tools {
                        return Err(format!(
                            "model {:?}: a custom `program` keeps tools that can read this machine, and cannot run in \
                             the agents container; set `allow_agent_tools = true` to run it on the host and accept that risk",
                            m.id
                        ));
                    }
                    // A tool-capable preset (codex, grok) runs in the container
                    // by default; `allow_agent_tools = true` opts into host.
                    if let Some(prog) = &m.program
                        && !Path::new(prog).is_absolute()
                    {
                        return Err(format!(
                            "model {:?}: `program` must be an absolute path",
                            m.id
                        ));
                    }
                    if let Some(p) = &m.preset
                        && CliSpec::preset(p, None, Duration::from_secs(1)).is_none()
                    {
                        return Err(format!(
                            "model {:?}: unknown preset {p:?} (claude | codex | grok)",
                            m.id
                        ));
                    }
                    if let Some(o) = &m.output {
                        parse_output_mode(o).map_err(|e| format!("model {:?}: {e}", m.id))?;
                    }
                }
                Backend::Openai => {
                    if m.base_url.is_none() || m.model.is_none() {
                        return Err(format!(
                            "openai model {:?} needs `base_url` and `model`",
                            m.id
                        ));
                    }
                }
                Backend::Ollama => {
                    if m.model.is_none() {
                        return Err(format!("ollama model {:?} needs `model`", m.id));
                    }
                }
            }
            if let Some(url) = &m.base_url
                && !url_is_https_or_loopback(url)
            {
                return Err(format!(
                    "model {:?}: base_url must be https:// (http:// only for localhost)",
                    m.id
                ));
            }
            if let Some(var) = &m.api_key_env
                && !api_key_env_ok(var)
            {
                return Err(format!(
                    "model {:?}: api_key_env {var:?} must be an UPPER_SNAKE name ending in _API_KEY, _KEY or _TOKEN",
                    m.id
                ));
            }
            m.family()?;
        }
        if let Some(jev) = &self.jev {
            jev.validate()?;
        }
        Ok(())
    }
}

impl JevSettings {
    fn validate(&self) -> Result<(), String> {
        if self.api_key.is_some() {
            return Err(
                "[jev]: do not inline `api_key`; use `api_key_env` (env var name) or `api_key_file` (0600 path)"
                    .to_string(),
            );
        }
        if self.api_key_env.is_none() && self.api_key_file.is_none() {
            return Err(
                "[jev]: set `api_key_env` or `api_key_file` so a key can be found (never the key itself)"
                    .to_string(),
            );
        }
        if let Some(var) = &self.api_key_env
            && !api_key_env_ok(var)
        {
            return Err(format!(
                "[jev]: api_key_env {var:?} must be an UPPER_SNAKE name ending in _API_KEY, _KEY or _TOKEN"
            ));
        }
        if let Some(path) = &self.api_key_file {
            if !path.is_absolute() {
                return Err(format!(
                    "[jev]: api_key_file {} must be an absolute path",
                    path.display()
                ));
            }
            let meta = std::fs::metadata(path)
                .map_err(|e| format!("[jev]: cannot stat api_key_file {}: {e}", path.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if meta.permissions().mode() & 0o077 != 0 {
                    return Err(format!(
                        "[jev]: api_key_file {} must be 0600 (owner-only); run `chmod 600` on it",
                        path.display()
                    ));
                }
            }
            #[cfg(not(unix))]
            let _ = meta;
        }
        if let Some(url) = &self.base_url
            && !url.starts_with("https://")
        {
            return Err(format!("[jev]: base_url {url:?} must be https://"));
        }
        Ok(())
    }
}

/// Connectivity check prompt — harmless, asks only for a fixed JSON reply.
pub const PROBE_PROMPT: &str = "This is a connectivity check from a code-review tool. \
Respond with the JSON object {\"ok\": true} and no other text.";

/// One model's reachability, for a settings screen.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ModelStatus {
    pub id: String,
    pub family: String,
    pub roles: Vec<String>,
    /// `Some(true)` reachable, `Some(false)` failed, `None` not probed.
    pub reachable: Option<bool>,
    /// A short reply excerpt or error message.
    pub detail: String,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Finder => "finder",
            Role::Verifier => "verifier",
            Role::Poc => "poc",
        }
    }
}

impl Config {
    /// Build handles and, when `probe`, send each model [`PROBE_PROMPT`].
    /// Pure data out — no printing — so a GUI settings screen can render it.
    pub async fn model_statuses(&self, probe: bool) -> Result<Vec<ModelStatus>, String> {
        let handles = self.handles()?;
        let mut out = Vec::with_capacity(handles.len());
        for (m, roles) in &handles {
            let (reachable, detail) = if probe {
                match m.caller.complete(PROBE_PROMPT).await {
                    Ok(t) => (
                        Some(true),
                        crate::util::truncate_bytes(t.trim(), 120).to_string(),
                    ),
                    Err(e) => (
                        Some(false),
                        crate::util::truncate_bytes(&e.to_string(), 200).to_string(),
                    ),
                }
            } else {
                (None, String::new())
            };
            out.push(ModelStatus {
                id: m.id.clone(),
                family: m.family.clone(),
                roles: roles.iter().map(|r| r.as_str().to_string()).collect(),
                reachable,
                detail,
            });
        }
        Ok(out)
    }
}

impl Config {
    /// Finders, verifiers, PoC models and the roster for a deep scan —
    /// every model whose roles include each role (the CLI/GUI default).
    /// Shared by every front end that builds a roster without CLI flags.
    #[allow(clippy::type_complexity)]
    pub fn deep_roster(
        &self,
    ) -> Result<
        (
            Vec<ModelHandle>,
            Vec<ModelHandle>,
            Vec<ModelHandle>,
            Vec<crate::audit::schema::ModelInfo>,
        ),
        String,
    > {
        self.roster_for(&[], &[], &[])
    }

    /// Like [`deep_roster`], but an explicit, non-empty id list for a role
    /// restricts that role to exactly those models (an unknown id is an
    /// error). An empty list keeps the default "every model with the role".
    /// Shared by the CLI (`--finders`/`--verifiers`) and library callers.
    #[allow(clippy::type_complexity)]
    pub fn roster_for(
        &self,
        finders: &[String],
        verifiers: &[String],
        poc: &[String],
    ) -> Result<
        (
            Vec<ModelHandle>,
            Vec<ModelHandle>,
            Vec<ModelHandle>,
            Vec<crate::audit::schema::ModelInfo>,
        ),
        String,
    > {
        let all = self.handles()?;
        let roster = all
            .iter()
            .map(|(m, roles)| crate::audit::schema::ModelInfo {
                id: m.id.clone(),
                family: m.family.clone(),
                roles: roles.iter().map(|r| r.as_str().to_string()).collect(),
            })
            .collect();
        Ok((
            pick_role(&all, finders, Role::Finder)?,
            pick_role(&all, verifiers, Role::Verifier)?,
            pick_role(&all, poc, Role::Poc)?,
            roster,
        ))
    }

    /// Serialize the roster back to `vettalon.toml` text (used by the GUI
    /// config editor). Call [`validate`](Self::validate) first.
    pub fn to_toml(&self) -> Result<String, String> {
        toml::to_string_pretty(self).map_err(|e| format!("cannot serialize config: {e}"))
    }

    /// Validate, then write the roster to `path` as TOML with 0600 perms
    /// (it chooses programs to run, so it is secret-adjacent).
    pub fn save(&self, path: &Path) -> Result<(), String> {
        self.validate()?;
        let text = self.to_toml()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        crate::util::write_private(path, text.as_bytes())
            .map_err(|e| format!("cannot write {}: {e}", path.display()))
    }

    /// Build callable handles for every configured model.
    pub fn handles(&self) -> Result<Vec<(ModelHandle, Vec<Role>)>, String> {
        self.models
            .iter()
            .map(|m| Ok((m.handle()?, m.roles.clone())))
            .collect()
    }
}

/// Models for `role`: the given ids (an unknown id is an error), else every
/// model whose roles include it. Shared by the CLI and the GUI roster builder.
fn pick_role(
    all: &[(ModelHandle, Vec<Role>)],
    ids: &[String],
    role: Role,
) -> Result<Vec<ModelHandle>, String> {
    if ids.is_empty() {
        return Ok(all
            .iter()
            .filter(|(_, roles)| roles.contains(&role))
            .map(|(m, _)| m.clone())
            .collect());
    }
    let mut seen = HashSet::new();
    ids.iter()
        .filter(|id| seen.insert(id.as_str()))
        .map(|id| {
            all.iter()
                .find(|(m, _)| &m.id == id)
                .map(|(m, _)| m.clone())
                .ok_or_else(|| format!("unknown model id {id:?} for role {}", role.as_str()))
        })
        .collect()
}

fn url_is_https_or_loopback(url: &str) -> bool {
    if url.starts_with("https://") {
        return true;
    }
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    if rest.starts_with("[::1]") {
        return true;
    }
    let host = rest.split(['/', ':']).next().unwrap_or("");
    matches!(host, "localhost" | "127.0.0.1")
}

/// Limits which environment variable a config may send as a bearer token,
/// so a config cannot point `api_key_env` at e.g. `AWS_SECRET_ACCESS_KEY`.
fn api_key_env_ok(var: &str) -> bool {
    !var.is_empty()
        && var
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        && (var.ends_with("_API_KEY") || var.ends_with("_KEY") || var.ends_with("_TOKEN"))
        && !var.starts_with("AWS_")
}

fn parse_output_mode(s: &str) -> Result<OutputMode, String> {
    match s {
        "stdout" => Ok(OutputMode::Stdout),
        "file" => Ok(OutputMode::File),
        other => match other.strip_prefix("json:") {
            Some(f) if !f.is_empty() => Ok(OutputMode::JsonField(f.to_string())),
            _ => Err(format!(
                "output {other:?} must be stdout | file | json:<field>"
            )),
        },
    }
}

impl ModelConfig {
    pub fn family(&self) -> Result<String, String> {
        if let Some(f) = &self.family {
            if f.trim().is_empty() {
                return Err(format!("model {:?}: empty family", self.id));
            }
            return Ok(f.trim().to_lowercase());
        }
        self.preset
            .as_deref()
            .and_then(preset_family)
            .map(str::to_string)
            .ok_or_else(|| {
                format!(
                    "model {:?} needs `family` (e.g. qwen, deepseek, google)",
                    self.id
                )
            })
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS))
    }

    /// How a CLI model runs. A tool-capable preset (codex, grok) runs in the
    /// agents container unless `allow_agent_tools` opts into the host; every
    /// other CLI runs on the host (claude's tools are off; a custom program
    /// required the opt-in at validation time).
    fn isolation(&self) -> crate::llm::container::Isolation {
        use crate::llm::container::{self, ContainerSpec, Isolation};
        if self.backend != Backend::Cli || self.allow_agent_tools {
            return Isolation::Host;
        }
        match self.preset.as_deref() {
            Some(p) if crate::llm::cli::TOOL_CAPABLE_PRESETS.contains(&p) => {
                let home = container::host_home();
                let auth_files = container::preset_auth_files(p)
                    .into_iter()
                    .map(|rel| (home.join(&rel), rel))
                    .collect();
                Isolation::Container(ContainerSpec {
                    image: container::AGENTS_IMAGE.to_string(),
                    auth_files,
                })
            }
            _ => Isolation::Host,
        }
    }

    pub fn handle(&self) -> Result<ModelHandle, String> {
        let caller: Arc<dyn LlmCaller> = match self.backend {
            Backend::Cli => {
                let mut spec = match &self.preset {
                    Some(p) => CliSpec::preset(p, self.model.clone(), self.timeout())
                        .ok_or_else(|| format!("unknown preset {p:?}"))?,
                    None => CliSpec {
                        program: self.program.clone().unwrap_or_default(),
                        args: Vec::new(),
                        prompt_via: PromptVia::Stdin,
                        output: OutputMode::Stdout,
                        model: self.model.clone(),
                        timeout: self.timeout(),
                        env_passthrough: Vec::new(),
                    },
                };
                spec.env_passthrough
                    .extend(self.env_passthrough.iter().cloned());
                if let Some(p) = &self.program {
                    spec.program = p.clone();
                }
                if let Some(a) = &self.args {
                    spec.args = a.clone();
                }
                if let Some(v) = self.prompt_via {
                    spec.prompt_via = v;
                }
                if let Some(o) = &self.output {
                    spec.output = parse_output_mode(o)?;
                }
                match self.isolation() {
                    crate::llm::container::Isolation::Container(container) => {
                        Arc::new(RefusalAware {
                            inner: crate::llm::container::ContainerCliCaller { spec, container },
                        })
                    }
                    crate::llm::container::Isolation::Host => Arc::new(RefusalAware {
                        inner: CliCaller { spec },
                    }),
                }
            }
            Backend::Openai | Backend::Ollama => {
                let base_url = self
                    .base_url
                    .clone()
                    .unwrap_or_else(|| DEFAULT_OLLAMA_URL.into());
                let spec = HttpSpec {
                    base_url,
                    model: self.model.clone().unwrap_or_default(),
                    api_key_env: self.api_key_env.clone(),
                    max_tokens: self.max_tokens.unwrap_or(DEFAULT_MAX_TOKENS),
                    temperature: self.temperature.unwrap_or(0.0),
                    timeout: self.timeout(),
                };
                Arc::new(RefusalAware {
                    inner: OpenAiCompatCaller::new(spec)?,
                })
            }
        };
        Ok(ModelHandle {
            id: self.id.clone(),
            family: self.family()?,
            caller,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[[model]]
id = "claude"
backend = "cli"
preset = "claude"
model = "sonnet"

[[model]]
id = "qwen-local"
backend = "ollama"
family = "qwen"
model = "qwen2.5-coder:7b"
roles = ["finder"]

[[model]]
id = "deepseek"
backend = "openai"
family = "deepseek"
base_url = "https://api.deepseek.com/v1"
model = "deepseek-chat"
api_key_env = "DEEPSEEK_API_KEY"
roles = ["finder", "verifier"]
"#;

    #[tokio::test]
    async fn model_statuses_without_probe_lists_without_calling() {
        let c = Config::parse(SAMPLE).unwrap();
        let st = c.model_statuses(false).await.unwrap();
        assert_eq!(st.len(), 3);
        assert_eq!(st[0].id, "claude");
        assert!(
            st.iter().all(|s| s.reachable.is_none()),
            "no probe ⇒ no call"
        );
        assert_eq!(st[1].roles, vec!["finder"]);
    }

    #[test]
    fn sample_parses_and_families_resolve() {
        let c = Config::parse(SAMPLE).unwrap();
        assert_eq!(c.models.len(), 3);
        assert_eq!(c.models[0].family().unwrap(), "anthropic");
        assert_eq!(c.models[1].family().unwrap(), "qwen");
        assert_eq!(c.models[1].roles, vec![Role::Finder]);
        let hs = c.handles().unwrap();
        assert_eq!(hs[2].0.family, "deepseek");
    }

    #[test]
    fn tool_capable_presets_default_to_container_host_on_opt_in() {
        use crate::llm::container::Isolation;
        let grok = ModelConfig {
            id: "g".into(),
            backend: Backend::Cli,
            family: None,
            model: None,
            roles: default_roles(),
            timeout_secs: None,
            allow_agent_tools: false,
            env_passthrough: vec![],
            preset: Some("grok".into()),
            program: None,
            args: None,
            prompt_via: None,
            output: None,
            base_url: None,
            api_key_env: None,
            max_tokens: None,
            temperature: None,
        };
        assert!(matches!(grok.isolation(), Isolation::Container(_)));
        let mut host = grok.clone();
        host.allow_agent_tools = true;
        assert!(matches!(host.isolation(), Isolation::Host));
        let mut claude = grok.clone();
        claude.preset = Some("claude".into());
        assert!(
            matches!(claude.isolation(), Isolation::Host),
            "claude tools are off"
        );
        // The container spec carries the preset's auth file.
        if let Isolation::Container(c) = grok.isolation() {
            assert_eq!(c.auth_files.len(), 1);
            assert!(c.auth_files[0].1.ends_with("auth.json"));
        }
    }

    #[test]
    fn jev_config_accepts_both_key_modes_and_rejects_inline_key() {
        // env var mode
        assert!(Config::parse("[jev]\napi_key_env = \"TYPESAFE_API_KEY\"\n").is_ok());
        // inline key is rejected
        assert!(
            Config::parse("[jev]\napi_key = \"apikey_abc\"\n")
                .unwrap_err()
                .contains("inline")
        );
        // no key source at all
        assert!(
            Config::parse("[jev]\nmodel = \"jev-latest\"\n")
                .unwrap_err()
                .contains("api_key_env")
        );
        // bad env var name
        assert!(Config::parse("[jev]\napi_key_env = \"SECRET\"\n").is_err());
        // non-https base_url
        assert!(
            Config::parse(
                "[jev]\napi_key_env = \"X_API_KEY\"\nbase_url = \"http://api.typesafe.ai\"\n"
            )
            .unwrap_err()
            .contains("https")
        );
        // relative key file path
        assert!(
            Config::parse("[jev]\napi_key_file = \"rel/path.key\"\n")
                .unwrap_err()
                .contains("absolute")
        );
    }

    #[cfg(unix)]
    #[test]
    fn jev_key_file_must_be_0600_and_resolve_reads_it() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("typesafe.key");
        std::fs::write(&key, "apikey_secret_value\n").unwrap();
        // world-readable -> rejected
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let toml = format!("[jev]\napi_key_file = {:?}\n", key.display().to_string());
        assert!(Config::parse(&toml).unwrap_err().contains("0600"));
        // 0600 -> accepted, and resolve_key reads (trimmed) without logging it
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let cfg = Config::parse(&toml).unwrap();
        assert_eq!(
            cfg.jev.as_ref().unwrap().resolve_key().unwrap(),
            "apikey_secret_value"
        );
    }

    #[test]
    fn jev_to_toml_never_emits_a_key_value() {
        // Even if a key value somehow lived in memory, it is not written back.
        let cfg = Config::parse("[jev]\napi_key_env = \"TYPESAFE_API_KEY\"\n").unwrap();
        let out = cfg.to_toml().unwrap();
        assert!(out.contains("api_key_env"));
        assert!(!out.to_lowercase().contains("apikey_"));
    }

    #[test]
    fn inline_api_keys_are_rejected() {
        let bad = r#"
[[model]]
id = "x"
backend = "openai"
family = "x"
base_url = "https://e"
model = "m"
api_key = "sk-123"
"#;
        assert!(Config::parse(bad).is_err());
    }

    #[test]
    fn validation_errors() {
        let dup = "[[model]]\nid='a'\nbackend='cli'\npreset='claude'\n[[model]]\nid='a'\nbackend='cli'\npreset='claude'\n";
        assert!(Config::parse(dup).unwrap_err().contains("duplicate"));
        let nofam = "[[model]]\nid='a'\nbackend='ollama'\nmodel='m'\n";
        assert!(Config::parse(nofam).unwrap_err().contains("family"));
        // A tool-capable preset runs in the container by default (valid);
        // allow_agent_tools opts into host (also valid).
        let tools = "[[model]]\nid='g'\nbackend='cli'\npreset='grok'\n";
        assert!(Config::parse(tools).is_ok());
        assert!(Config::parse(&format!("{tools}allow_agent_tools = true\n")).is_ok());
        // A custom program can only run on the host, and needs the opt-in.
        let prog = "[[model]]\nid='g'\nbackend='cli'\nfamily='x'\nprogram='/usr/bin/foo'\n";
        assert!(
            Config::parse(prog)
                .unwrap_err()
                .contains("allow_agent_tools")
        );
        let http = "[[model]]\nid='a'\nbackend='openai'\nfamily='f'\nmodel='m'\nbase_url='http://evil.example/v1'\n";
        assert!(Config::parse(http).unwrap_err().contains("https"));
        let local = "[[model]]\nid='a'\nbackend='ollama'\nfamily='f'\nmodel='m'\nbase_url='http://localhost:11434/v1'\n";
        assert!(Config::parse(local).is_ok());
        assert!(url_is_https_or_loopback("http://[::1]:11434/v1"));
        assert!(!url_is_https_or_loopback("http://[2001:db8::1]/v1"));
        assert!(!url_is_https_or_loopback("http://localhost.evil.com/v1"));
        let aws = "[[model]]\nid='a'\nbackend='openai'\nfamily='f'\nmodel='m'\nbase_url='https://e'\napi_key_env='AWS_SECRET_ACCESS_KEY'\n";
        assert!(Config::parse(aws).unwrap_err().contains("api_key_env"));
        let rel =
            "[[model]]\nid='a'\nbackend='cli'\nfamily='f'\nprogram='sh'\nallow_agent_tools=true\n";
        assert!(Config::parse(rel).unwrap_err().contains("absolute"));
        let badpreset = "[[model]]\nid='a'\nbackend='cli'\npreset='gpt'\n";
        assert!(Config::parse(badpreset).unwrap_err().contains("preset"));
        let badid = "[[model]]\nid='a b'\nbackend='cli'\npreset='claude'\n";
        assert!(Config::parse(badid).is_err());
        let nourl = "[[model]]\nid='a'\nbackend='openai'\nfamily='f'\nmodel='m'\n";
        assert!(Config::parse(nourl).unwrap_err().contains("base_url"));
    }

    #[test]
    fn to_toml_round_trips_and_omits_defaults() {
        let c = Config::parse(SAMPLE).unwrap();
        let text = c.to_toml().unwrap();
        // Defaults must not leak into the written file.
        assert!(
            !text.contains("allow_agent_tools"),
            "false bool should be skipped"
        );
        assert!(!text.contains("= \"\""), "no empty-string noise");
        // Re-parsing the output yields the same roster.
        let c2 = Config::parse(&text).unwrap();
        assert_eq!(c2.models.len(), c.models.len());
        assert_eq!(c2.models[1].id, "qwen-local");
        assert_eq!(c2.models[1].family().unwrap(), "qwen");
        assert_eq!(
            c2.models[2].api_key_env.as_deref(),
            Some("DEEPSEEK_API_KEY")
        );
    }

    #[test]
    fn roster_for_selects_and_rejects_unknown() {
        let c = Config::parse(SAMPLE).unwrap();
        // Empty selection = every model with the role (claude + qwen + deepseek
        // can find; only claude + deepseek verify since qwen is finder-only).
        let (f, v, _p, _r) = c.roster_for(&[], &[], &[]).unwrap();
        assert_eq!(f.len(), 3);
        assert_eq!(v.len(), 2);
        // Explicit finder selection restricts to exactly that model.
        let (f, _v, _p, _r) = c.roster_for(&["qwen-local".to_string()], &[], &[]).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].id, "qwen-local");
        // An unknown id is an error, not a silent drop.
        assert!(c.roster_for(&["ghost".to_string()], &[], &[]).is_err());
    }

    #[test]
    fn save_writes_valid_toml_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("config.toml");
        let c = Config::parse(SAMPLE).unwrap();
        c.save(&path).unwrap();
        assert!(Config::load(&path).is_ok(), "written file re-loads");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn custom_cli_output_mode() {
        let c = "[[model]]\nid='g'\nbackend='cli'\nfamily='google'\nprogram='/opt/homebrew/bin/gemini'\nallow_agent_tools=true\nargs=['-p','{prompt}']\nprompt_via='arg'\noutput='json:response'\n";
        let cfg = Config::parse(c).unwrap();
        assert!(cfg.handles().is_ok());
        let bad = "[[model]]\nid='g'\nbackend='cli'\nfamily='google'\nprogram='/x/gemini'\nallow_agent_tools=true\noutput='json:'\n";
        assert!(Config::parse(bad).is_err());
    }
}
