use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use vettalon::audit::schema::{ModelInfo, ProfileMode};
use vettalon::audit::{self, ScanOptions};
use vettalon::config::{Config, Role};
use vettalon::llm::ModelHandle;

#[derive(Parser)]
#[command(name = "vettalon", version, about = "Multi-model security audit for your own code")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct ScanArgs {
    /// Repository root.
    path: PathBuf,
    /// quick = OSS scanners only; deep = + AI audit and review.
    #[arg(long, default_value = "quick")]
    profile: String,
    /// Model roster (default: ~/.vettalon/config.toml, else the claude CLI
    /// if found on PATH). Never read from the scanned repository.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Comma-separated model ids to use as finders (overrides roles).
    #[arg(long, value_delimiter = ',')]
    finders: Vec<String>,
    /// Comma-separated model ids to use as verifiers (overrides roles).
    #[arg(long, value_delimiter = ',')]
    verifiers: Vec<String>,
    /// Ranked modules sent to the AI audit (the main cost guard). 0 = every
    /// module (full coverage, can be slow/expensive on a large repo).
    #[arg(long, default_value_t = 5)]
    max_modules: usize,
    /// Write the full JSON report here.
    #[arg(long)]
    report: Option<PathBuf>,
    /// Write a SARIF 2.1.0 file here.
    #[arg(long)]
    sarif: Option<PathBuf>,
    /// Exit 1 when a gated finding is at or above this severity.
    #[arg(long, default_value = "high")]
    fail_on: String,
    /// Also count needs_human findings toward --fail-on.
    #[arg(long)]
    fail_on_needs_human: bool,
    /// Also give the top N ranked modules a second, different-family finder.
    /// High-risk modules (git security hotspots, entry points) and modules
    /// with injection text are always cross-checked regardless of this.
    #[arg(long, default_value_t = 0)]
    cross_check_top: usize,
    /// Generate and run PoCs in a Docker sandbox (no network) for
    /// plausible High+ findings.
    #[arg(long)]
    poc: bool,
    /// Sandbox image for --poc (must already be pulled).
    #[arg(long, default_value = vettalon::sandbox::DEFAULT_POC_IMAGE)]
    poc_image: String,
    /// Keep a timestamped copy under ~/.vettalon/reports (enables
    /// carry-over of statuses on unchanged files next run).
    #[arg(long)]
    save: bool,
    /// Ignore the newest saved report for this repo.
    #[arg(long)]
    no_prior: bool,
}

// Parsed once at startup; boxing the big variant buys nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum Command {
    /// Scan a repository.
    Scan(ScanArgs),
    /// Validate a saved JSON report.
    Validate { report: PathBuf },
    /// Show the model roster; --probe sends each model a one-line check.
    Models {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        probe: bool,
    },
    /// Manage the container sandbox used for tool-capable CLIs (codex, grok).
    Agents {
        #[command(subcommand)]
        action: AgentsAction,
    },
    /// Draft a vulnerability report for a reviewed finding, in the format a
    /// reporting channel expects (GitHub advisory, project email, TWCERT/CC,
    /// HITCON ZeroDay). Drafts only — nothing is ever sent.
    Disclose {
        /// The JSON report written by `vettalon scan --report`.
        report: PathBuf,
        /// Finding id (or a unique prefix). Omit to list eligible findings.
        #[arg(long)]
        finding: Option<String>,
        /// ghsa | email | twcert | hitcon (default: the top recommendation).
        #[arg(long)]
        channel: Option<String>,
        /// Write the draft here instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum AgentsAction {
    /// Build the agent and egress-proxy images (needs network access).
    Build,
    /// Remove the egress proxy and the internal network.
    Stop,
}

fn home_dir() -> PathBuf {
    vettalon::util::vettalon_home()
}

/// The roster. Never read from the scanned repository: a config chooses
/// programs to run and where API keys go, so a repo-supplied one would be
/// code execution. `scan_root` is the repo being scanned (if any).
fn load_config(explicit: Option<&Path>, scan_root: Option<&Path>) -> Result<(Config, String), String> {
    let path = match explicit {
        Some(p) => Some(p.to_path_buf()),
        None => Some(home_dir().join("config.toml")).filter(|p| p.is_file()),
    };
    if let Some(p) = path {
        if let (Ok(cfg), Some(root)) = (std::fs::canonicalize(&p), scan_root.and_then(|r| std::fs::canonicalize(r).ok()))
            && cfg.starts_with(&root)
        {
            return Err(format!(
                "refusing config {}: it is inside the repository being scanned (a repo must not choose the programs and endpoints vettalon runs)",
                p.display()
            ));
        }
        return Ok((Config::load(&p)?, p.display().to_string()));
    }
    let (cfg, skipped) = Config::autodetect();
    if !skipped.is_empty() {
        eprintln!(
            "[vettalon] 提示：偵測到 {}，但這些 CLI 的工具無法完全關閉（可能讀取本機檔案），沒有設定檔時不會使用。\
要使用請在 ~/.vettalon/config.toml 加入；預設會在容器沙箱執行（先跑 `vettalon agents build`），或設 allow_agent_tools = true 直接在本機跑。",
            skipped.join("、")
        );
    }
    Ok((cfg, "auto-detected CLIs on PATH".into()))
}

fn role_name(r: Role) -> &'static str {
    match r {
        Role::Finder => "finder",
        Role::Verifier => "verifier",
        Role::Poc => "poc",
    }
}

/// Models for `role`: the ids given on the command line, else every model
/// whose roles include it.
fn pick(
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
    let mut seen = std::collections::HashSet::new();
    ids.iter()
        .filter(|id| seen.insert(id.as_str()))
        .map(|id| {
            all.iter()
                .find(|(m, _)| &m.id == id)
                .map(|(m, _)| m.clone())
                .ok_or_else(|| format!("unknown model id {id:?} for --{}s", role_name(role)))
        })
        .collect()
}


async fn cmd_models(config: Option<PathBuf>, probe: bool) -> i32 {
    let (cfg, source) = match load_config(config.as_deref(), None) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[vettalon] {e}");
            return 2;
        }
    };
    println!("模型清單來源：{source}");
    if cfg.models.is_empty() {
        println!("（沒有任何模型。請建立 vettalon.toml，或安裝 claude / codex / grok CLI）");
        return 0;
    }
    let statuses = match cfg.model_statuses(probe).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[vettalon] {e}");
            return 2;
        }
    };
    for s in &statuses {
        let status = match s.reachable {
            Some(true) => format!("OK（{}）", vettalon::util::truncate_bytes(&s.detail, 60)),
            Some(false) => format!("失敗：{}", vettalon::util::truncate_bytes(&s.detail, 160)),
            None => String::new(),
        };
        println!("  {:<14} family={:<10} roles={:<22} {status}", s.id, s.family, s.roles.join(","));
    }
    0
}

async fn cmd_scan(args: ScanArgs) -> i32 {
    let ScanArgs {
        path,
        profile,
        config,
        finders,
        verifiers,
        max_modules,
        cross_check_top,
        report,
        sarif,
        fail_on,
        fail_on_needs_human,
        poc,
        poc_image,
        save,
        no_prior,
    } = args;
    // Same parser the pipeline uses (case-insensitive), so `--profile Deep`
    // loads the roster too; a bad value is reported by the pipeline (exit 2).
    let deep = profile.parse::<ProfileMode>() == Ok(ProfileMode::Deep);
    let (finders, verifiers, poc_models, roster) = if deep {
        let (cfg, source) = match load_config(config.as_deref(), Some(&path)) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[vettalon] {e}");
                return 2;
            }
        };
        let all = match cfg.handles() {
            Ok(h) => h,
            Err(e) => {
                eprintln!("[vettalon] {e}");
                return 2;
            }
        };
        let picked = (
            pick(&all, &finders, Role::Finder),
            pick(&all, &verifiers, Role::Verifier),
            pick(&all, &[], Role::Poc),
        );
        let (f, v, p) = match picked {
            (Ok(f), Ok(v), Ok(p)) => (f, v, p),
            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
                eprintln!("[vettalon] {e}");
                return 2;
            }
        };
        let roster: Vec<ModelInfo> = all
            .iter()
            .map(|(m, roles)| ModelInfo {
                id: m.id.clone(),
                family: m.family.clone(),
                roles: roles.iter().map(|r| role_name(*r).to_string()).collect(),
            })
            .collect();
        let ids = |ms: &[ModelHandle]| ms.iter().map(|m| m.id.as_str()).collect::<Vec<_>>().join(", ");
        eprintln!(
            "[vettalon] 模型（{source}）：finder = {}；verifier = {}",
            ids(&f),
            ids(&v)
        );
        (f, v, p, roster)
    } else {
        (Vec::new(), Vec::new(), Vec::new(), Vec::new())
    };
    audit::set_poc_image(&poc_image);
    let opts = ScanOptions {
        repo_path: path,
        profile,
        report,
        sarif,
        fail_on,
        max_modules,
        poc,
        save,
        cross_check_top,
        fail_on_needs_human,
        no_prior,
        finders,
        verifiers,
        poc_models,
        roster,
    };
    audit::cmd_scan(&home_dir(), opts).await
}

fn cmd_disclose(input: PathBuf, finding: Option<String>, channel: Option<String>, out: Option<PathBuf>) -> i32 {
    use vettalon::disclose;
    let report = match audit::load_report_for_delivery(&input) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[vettalon] {e}");
            return 2;
        }
    };
    let Some(wanted) = finding else {
        let eligible: Vec<_> = report.findings.iter().filter(|f| disclose::eligible(f).is_ok()).collect();
        if eligible.is_empty() {
            println!("沒有可提交的項目（只有經覆核「需人工研判」或已確認的項目才產生提交草稿）。");
            return 0;
        }
        println!("可產生提交草稿的項目（--finding <id>）：");
        for f in eligible {
            let loc = f.line.map(|l| format!("{}:{l}", f.file)).unwrap_or_else(|| f.file.clone());
            println!("  {}  [{}] {}  ({loc})", f.id, f.severity.as_str(), f.title);
        }
        return 0;
    };
    let matches: Vec<&str> = report
        .findings
        .iter()
        .map(|f| f.id.as_str())
        .filter(|id| *id == wanted || id.starts_with(wanted.as_str()))
        .collect();
    let id = match matches.as_slice() {
        [one] => one.to_string(),
        [] => {
            eprintln!("[vettalon] 找不到 finding {wanted}");
            return 2;
        }
        _ => {
            eprintln!("[vettalon] {wanted} 對應到多個 finding，請給更長的 id");
            return 2;
        }
    };
    let channel = match channel.as_deref().map(str::parse::<disclose::Channel>).transpose() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[vettalon] {e}");
            return 2;
        }
    };
    let pkg = match disclose::prepare(&report, &id, channel) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[vettalon] {e}");
            return 2;
        }
    };
    eprintln!("通報管道建議：");
    for c in &pkg.channels {
        let mark = if c.channel == pkg.draft.channel { "→" } else { " " };
        eprintln!("  {mark} {}：{}", c.label, c.reason);
    }
    eprintln!("\n送出前請逐項確認（vettalon 不會替你送出）：");
    for item in &pkg.checklist {
        eprintln!("  [ ] {item}");
    }
    if let Some(s) = &pkg.draft.submit {
        eprintln!("\n提交位置：{s}");
    }
    eprintln!("建議公開日期：{}\n", pkg.draft.disclose_by);
    let text = format!("{}\n\n{}\n", pkg.draft.subject, pkg.draft.body);
    match out {
        Some(path) => match vettalon::util::write_private(&path, text.as_bytes()) {
            Ok(()) => {
                eprintln!("草稿已寫入：{}", path.display());
                0
            }
            Err(e) => {
                eprintln!("[vettalon] 無法寫入 {}：{e}", path.display());
                2
            }
        },
        None => {
            println!("{text}");
            0
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let code = match cli.command {
        Command::Scan(args) => cmd_scan(args).await,
        Command::Validate { report } => audit::cmd_validate(&report).await,
        Command::Disclose { report, finding, channel, out } => cmd_disclose(report, finding, channel, out),
        Command::Models { config, probe } => cmd_models(config, probe).await,
        Command::Agents { action } => {
            let r = match action {
                AgentsAction::Build => vettalon::llm::container::build_images().await,
                AgentsAction::Stop => vettalon::llm::container::teardown().await,
            };
            match r {
                Ok(()) => {
                    println!("完成");
                    0
                }
                Err(e) => {
                    eprintln!("[vettalon] {e}");
                    2
                }
            }
        }
    };
    ExitCode::from(code.clamp(0, 255) as u8)
}
