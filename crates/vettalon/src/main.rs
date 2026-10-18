use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use vettalon::audit::schema::{ModelInfo, ProfileMode};
use vettalon::audit::{self, ScanOptions};
use vettalon::config::{Config, Role};
use vettalon::llm::ModelHandle;

#[derive(Parser)]
#[command(
    name = "vettalon",
    version,
    about = "Multi-model security audit for your own code"
)]
struct Cli {
    /// Language of terminal output: `en` or `zh-TW`. Default: VETTALON_LANG,
    /// then the locale (LC_ALL, LC_MESSAGES, LANG); English otherwise.
    /// Reports and SARIF are the same in either language.
    #[arg(long, global = true, value_name = "LANG")]
    lang: Option<String>,
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
    /// Exit 1 when a gated finding is at or above this severity (`none` to
    /// disable). Default `high`, or `none` when a --gate is given.
    #[arg(long)]
    fail_on: Option<String>,
    /// Policy gate condition (repeatable); exit 1 when any fails. Example:
    /// "severity>=critical status=confirmed,needs_human cross_family count>0".
    /// Tokens: severity>=LEVEL, status=candidate|confirmed|needs_human,...,
    /// cross_family, count>N | count>=N.
    #[arg(long = "gate", value_name = "CONDITION")]
    gates: Vec<String>,
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
    /// Write a per-call LLM trace (JSON Lines) here: one line per model call
    /// with step, model, byte sizes, latency and outcome (no prompt or reply
    /// text). Useful for cost/latency review and benchmark regression checks.
    #[arg(long)]
    trace: Option<PathBuf>,
    /// Include source snapshot and locally assembled prompt SHA-256 receipts
    /// for each deep finder call in the report; never stores source text.
    #[arg(long)]
    source_receipts: bool,
    /// Overall wall-clock budget for the AI deep-audit, in seconds. When it
    /// runs out, pending modules are deferred and the run is marked incomplete
    /// instead of grinding on. Unset = no budget.
    #[arg(long)]
    time_budget: Option<u64>,
    /// Module ranker for the deep audit: `heuristic` (default, local ranking)
    /// or `jev` (TypeSafe Jev, metadata-only; requires a `[jev]` config
    /// block). Cloud models and scanner database updates may also use the network.
    #[arg(long, default_value = "heuristic")]
    rank: String,
}

#[derive(Subcommand)]
enum EvidenceAction {
    /// Check local artifact hashes and attach operator-supplied evidence to a new report.
    Attach {
        #[arg(long)]
        report: PathBuf,
        #[arg(long)]
        finding: String,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        artifact_root: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}

// Parsed once at startup; boxing the big variant buys nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum Command {
    /// Scan a repository.
    Scan(ScanArgs),
    /// Validate a saved JSON report.
    Validate { report: PathBuf },
    /// Attach local proof artifact references; no commands run and no verdict changes.
    Evidence {
        #[command(subcommand)]
        action: EvidenceAction,
    },
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
    /// Hunt for not-yet-disclosed vulnerabilities in a project's OSS
    /// dependencies (supply-chain mode). Audits dependency SOURCE with the
    /// deep engine, uses OSV to focus on what is NOT already a known CVE, and
    /// surfaces verified novelty candidates for responsible disclosure.
    Hunt(HuntArgs),
}

#[derive(Subcommand)]
enum AgentsAction {
    /// Build the agent and egress-proxy images (needs network access).
    Build,
    /// Remove the egress proxy and the internal network.
    Stop,
}

#[derive(clap::Args)]
struct HuntArgs {
    /// Project directory holding the lockfile(s): Cargo.lock,
    /// package-lock.json, requirements.txt, go.sum.
    path: PathBuf,
    /// Model roster (default: ~/.vettalon/config.toml, else detected CLIs).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Finder model ids (overrides roles).
    #[arg(long, value_delimiter = ',')]
    finders: Vec<String>,
    /// Verifier model ids (overrides roles).
    #[arg(long, value_delimiter = ',')]
    verifiers: Vec<String>,
    /// Maximum dependencies to fetch + audit (cost guard).
    #[arg(long, default_value_t = 20)]
    max_deps: usize,
    /// Audit transitive dependencies too (default: direct only).
    #[arg(long)]
    include_transitive: bool,
    /// Audit versions that already have a known CVE (default: skip them;
    /// SCA tools already track those).
    #[arg(long)]
    reaudit_known: bool,
    /// Ranked modules audited per dependency (passed to the deep audit).
    #[arg(long, default_value_t = 5)]
    max_modules: usize,
    /// Per-dependency wall-clock budget in seconds (fetch + audit). A slow
    /// dependency is recorded as timed-out and the hunt moves on.
    #[arg(long, default_value_t = 300)]
    dep_timeout: u64,
    /// Dependencies audited at the same time (1-4). Token use is unchanged;
    /// each model receives this many simultaneous calls, so lower it if a CLI
    /// account hits rate limits.
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u64).range(1..=vettalon::hunt::run::MAX_DEP_CONCURRENCY as u64))]
    dep_concurrency: u64,
    /// Run sandboxed PoCs for plausible High+ findings in each dependency.
    #[arg(long)]
    poc: bool,
    /// Sandbox image for --poc (must already be pulled).
    #[arg(long, default_value = vettalon::sandbox::DEFAULT_POC_IMAGE)]
    poc_image: String,
    /// Preview only: intake + OSV + selection, no fetch or audit (no model
    /// cost). Shows what a full hunt would audit.
    #[arg(long)]
    dry_run: bool,
    /// Write the full hunt report (JSON) here.
    #[arg(long)]
    report: Option<PathBuf>,
    /// Write upstream responsible-disclosure drafts for the novelty candidates
    /// into this directory (drafts only; nothing is ever sent).
    #[arg(long)]
    disclose_dir: Option<PathBuf>,
}

fn home_dir() -> PathBuf {
    vettalon::util::vettalon_home()
}

/// The roster. Never read from the scanned repository: a config chooses
/// programs to run and where API keys go, so a repo-supplied one would be
/// code execution. `scan_root` is the repo being scanned (if any).
fn load_config(
    explicit: Option<&Path>,
    scan_root: Option<&Path>,
) -> Result<(Config, String), String> {
    let path = match explicit {
        Some(p) => Some(p.to_path_buf()),
        None => Some(home_dir().join("config.toml")).filter(|p| p.is_file()),
    };
    if let Some(p) = path {
        if let (Ok(cfg), Some(root)) = (
            std::fs::canonicalize(&p),
            scan_root.and_then(|r| std::fs::canonicalize(r).ok()),
        ) && cfg.starts_with(&root)
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
            "[vettalon] {}",
            vettalon::tr!(
                "提示：偵測到 {}，但這些 CLI 的工具無法完全關閉（可能讀取本機檔案），沒有設定檔時不會使用。\
要使用請在 ~/.vettalon/config.toml 加入；預設會在容器沙箱執行（先跑 `vettalon agents build`），或設 allow_agent_tools = true 直接在本機跑。",
                "note: found {}, but their tools cannot be fully disabled (they may read local files), so they are not used without a config file. \
Add them to ~/.vettalon/config.toml: by default they run in the container sandbox (run `vettalon agents build` first), or set allow_agent_tools = true to run them directly.",
                skipped.join(vettalon::lang::pick("、", ", "))
            )
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
    println!(
        "{}",
        vettalon::tr!("模型清單來源：{source}", "Model roster: {source}")
    );
    if cfg.models.is_empty() {
        println!(
            "{}",
            vettalon::lang::pick(
                "（沒有任何模型。請建立 vettalon.toml，或安裝 claude / codex / grok CLI）",
                "(no models; create vettalon.toml or install the claude / codex / grok CLI)"
            )
        );
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
            Some(true) => vettalon::tr!(
                "OK（{}）",
                "OK ({})",
                vettalon::util::truncate_bytes(&s.detail, 60)
            ),
            Some(false) => vettalon::tr!(
                "失敗：{}",
                "failed: {}",
                vettalon::util::truncate_bytes(&s.detail, 160)
            ),
            None => String::new(),
        };
        println!(
            "  {:<14} family={:<10} roles={:<22} {status}",
            s.id,
            s.family,
            s.roles.join(",")
        );
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
        gates,
        fail_on_needs_human,
        poc,
        poc_image,
        save,
        no_prior,
        trace,
        source_receipts,
        time_budget,
        rank,
    } = args;
    let gates = match audit::gate::parse_all(&gates) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("[vettalon] {e}");
            return 2;
        }
    };
    let fail_on = fail_on.unwrap_or_else(|| if gates.is_empty() { "high" } else { "none" }.into());
    // Same parser the pipeline uses (case-insensitive), so `--profile Deep`
    // loads the roster too; a bad value is reported by the pipeline (exit 2).
    let deep = profile.parse::<ProfileMode>() == Ok(ProfileMode::Deep);
    let want_jev = rank.eq_ignore_ascii_case("jev");
    if !matches!(rank.to_ascii_lowercase().as_str(), "heuristic" | "jev") {
        eprintln!(
            "[vettalon] {}",
            vettalon::tr!(
                "--rank 必須是 heuristic 或 jev（收到 {rank:?}）",
                "--rank must be heuristic or jev (got {rank:?})"
            )
        );
        return 2;
    }
    if want_jev && !deep {
        eprintln!(
            "[vettalon] {}",
            vettalon::lang::pick(
                "--rank jev 只在 --profile deep 有效（quick 不跑 AI 審查）",
                "--rank jev only applies to --profile deep (quick runs no AI audit)"
            )
        );
        return 2;
    }
    let (finders, verifiers, poc_models, roster, rank_strategy) = if deep {
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
        let ids = |ms: &[ModelHandle]| {
            ms.iter()
                .map(|m| m.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        };
        eprintln!(
            "[vettalon] {}",
            vettalon::tr!(
                "模型（{source}）：finder = {}；verifier = {}",
                "models ({source}): finder = {}; verifier = {}",
                ids(&f),
                ids(&v)
            )
        );
        let rank_strategy = if want_jev {
            match &cfg.jev {
                Some(j) => {
                    // Fail fast: the operator asked for Jev, so a missing key
                    // or bad config is an error, not a silent fallback.
                    if let Err(e) = j.resolve_key() {
                        eprintln!("[vettalon] --rank jev: {e}");
                        return 2;
                    }
                    audit::RankStrategy::Jev(j.clone())
                }
                None => {
                    eprintln!(
                        "[vettalon] {}",
                        vettalon::lang::pick(
                            "--rank jev 需要 config 有 [jev] 區塊（api_key_env 或 api_key_file）",
                            "--rank jev needs a [jev] block in the config (api_key_env or api_key_file)"
                        )
                    );
                    return 2;
                }
            }
        } else {
            audit::RankStrategy::Heuristic
        };
        (f, v, p, roster, rank_strategy)
    } else {
        (
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            audit::RankStrategy::Heuristic,
        )
    };
    audit::set_poc_image(&poc_image);
    let opts = ScanOptions {
        repo_path: path,
        profile,
        report,
        sarif,
        fail_on,
        gates,
        max_modules,
        poc,
        save,
        cross_check_top,
        fail_on_needs_human,
        no_prior,
        rank: rank_strategy,
        trace,
        source_receipts,
        time_budget: time_budget.map(std::time::Duration::from_secs),
        finders,
        verifiers,
        poc_models,
        roster,
    };
    audit::cmd_scan(&home_dir(), opts).await
}

fn cmd_disclose(
    input: PathBuf,
    finding: Option<String>,
    channel: Option<String>,
    out: Option<PathBuf>,
) -> i32 {
    use vettalon::disclose;
    let report = match audit::load_report_for_delivery(&input) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[vettalon] {e}");
            return 2;
        }
    };
    let Some(wanted) = finding else {
        let eligible: Vec<_> = report
            .findings
            .iter()
            .filter(|f| disclose::eligible(f).is_ok())
            .collect();
        if eligible.is_empty() {
            println!(
                "{}",
                vettalon::lang::pick(
                    "沒有可提交的項目（只有經覆核「需人工研判」或已確認的項目才產生提交草稿）。",
                    "Nothing to report (drafts are only made for findings verified as needs-human-review or confirmed)."
                )
            );
            return 0;
        }
        println!(
            "{}",
            vettalon::lang::pick(
                "可產生提交草稿的項目（--finding <id>）：",
                "Findings you can draft a report for (--finding <id>):"
            )
        );
        for f in eligible {
            let loc = f
                .line
                .map(|l| format!("{}:{l}", f.file))
                .unwrap_or_else(|| f.file.clone());
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
            eprintln!(
                "[vettalon] {}",
                vettalon::tr!("找不到 finding {wanted}", "no finding {wanted}")
            );
            return 2;
        }
        _ => {
            eprintln!(
                "[vettalon] {}",
                vettalon::tr!(
                    "{wanted} 對應到多個 finding，請給更長的 id",
                    "{wanted} matches several findings; give a longer id"
                )
            );
            return 2;
        }
    };
    let channel = match channel
        .as_deref()
        .map(str::parse::<disclose::Channel>)
        .transpose()
    {
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
    eprintln!(
        "{}",
        vettalon::lang::pick("通報管道建議：", "Suggested channels:")
    );
    for c in &pkg.channels {
        let mark = if c.channel == pkg.draft.channel {
            "→"
        } else {
            " "
        };
        eprintln!(
            "  {mark} {}{}{}",
            c.label,
            vettalon::lang::pick("：", ": "),
            c.reason
        );
    }
    eprintln!(
        "\n{}",
        vettalon::lang::pick(
            "送出前請逐項確認（vettalon 不會替你送出）：",
            "Check each item before sending (vettalon never sends anything for you):"
        )
    );
    for item in &pkg.checklist {
        eprintln!("  [ ] {item}");
    }
    if let Some(s) = &pkg.draft.submit {
        eprintln!("\n{}", vettalon::tr!("提交位置：{s}", "Submit at: {s}"));
    }
    eprintln!(
        "{}\n",
        vettalon::tr!(
            "建議協調檢查日期：{}；公開另須核准",
            "Suggested coordination checkpoint: {}; publication requires separate approval",
            pkg.draft.disclose_by
        )
    );
    let text = format!("{}\n\n{}\n", pkg.draft.subject, pkg.draft.body);
    match out {
        Some(path) => match vettalon::util::write_private(&path, text.as_bytes()) {
            Ok(()) => {
                eprintln!(
                    "{}",
                    vettalon::tr!("草稿已寫入：{}", "Draft written: {}", path.display())
                );
                0
            }
            Err(e) => {
                eprintln!(
                    "[vettalon] {}",
                    vettalon::tr!("無法寫入 {}：{e}", "cannot write {}: {e}", path.display())
                );
                2
            }
        },
        None => {
            println!("{text}");
            0
        }
    }
}

/// `vettalon hunt`: supply-chain mode. Audits a project's OSS dependency
/// source for not-yet-disclosed vulnerabilities, focusing (by default) on
/// direct dependencies whose version OSV reports no known CVE for.
async fn cmd_hunt(args: HuntArgs) -> i32 {
    use vettalon::hunt::fetch::HttpSourceFetcher;
    use vettalon::hunt::osv::HttpOsvClient;
    use vettalon::hunt::run::{
        EngineAuditor, HuntOptions, disclosure_drafts, plan_hunt, render_plan, render_summary,
        run_hunt_with_progress,
    };

    let opts = HuntOptions {
        max_deps: args.max_deps,
        include_transitive: args.include_transitive,
        reaudit_known: args.reaudit_known,
        per_dep_timeout: std::time::Duration::from_secs(args.dep_timeout),
        dep_concurrency: args.dep_concurrency as usize,
    };
    let osv = HttpOsvClient::new();

    if args.dry_run {
        return match plan_hunt(&args.path, &opts, &osv).await {
            Ok(plan) => {
                print!("{}", render_plan(&plan));
                0
            }
            Err(e) => {
                eprintln!("[vettalon] {e}");
                2
            }
        };
    }

    // A real hunt audits each dependency with the deep engine, so resolve the
    // roster (same rules as `scan --profile deep`).
    let (cfg, source) = match load_config(args.config.as_deref(), Some(&args.path)) {
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
    let (finders, verifiers, poc_models) = match (
        pick(&all, &args.finders, Role::Finder),
        pick(&all, &args.verifiers, Role::Verifier),
        pick(&all, &[], Role::Poc),
    ) {
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
    eprintln!(
        "[vettalon] {}",
        vettalon::tr!(
            "模型（{source}）：finder = {}；verifier = {}",
            "models ({source}): finder = {}; verifier = {}",
            finders
                .iter()
                .map(|m| m.id.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            verifiers
                .iter()
                .map(|m| m.id.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        )
    );
    vettalon::audit::set_poc_image(&args.poc_image);

    let auditor = EngineAuditor {
        home: home_dir(),
        finders,
        verifiers,
        poc_models,
        roster,
        max_modules: args.max_modules,
        poc: args.poc,
    };
    let fetcher = HttpSourceFetcher::new();
    // Each dependency takes up to --dep-timeout and up to --dep-concurrency run
    // at once, so report progress per dependency to stderr (the JSON report is
    // stdout). Lines name the dependency because they interleave.
    struct CliHuntProgress {
        finished: std::sync::atomic::AtomicUsize,
    }
    impl vettalon::hunt::run::HuntProgress for CliHuntProgress {
        fn start(&self, i: usize, total: usize, t: &vettalon::hunt::DependencyTarget) {
            eprintln!(
                "[vettalon] {}",
                vettalon::tr!(
                    "({i}/{total}) 審查 {} {}@{} …",
                    "({i}/{total}) auditing {} {}@{} …",
                    t.ecosystem.as_str(),
                    t.name,
                    t.version
                )
            );
        }
        fn done(&self, _index: usize, total: usize, h: &vettalon::hunt::run::DependencyHunt) {
            let outcome = if !h.audited {
                vettalon::tr!(
                    "未完成（{}）",
                    "incomplete ({})",
                    h.error
                        .as_deref()
                        .unwrap_or_else(|| vettalon::lang::pick("原因不明", "reason unknown"))
                )
            } else {
                let novel = h
                    .findings
                    .iter()
                    .filter(|f| {
                        matches!(
                            f.status,
                            vettalon::audit::schema::FindingStatus::Confirmed
                                | vettalon::audit::schema::FindingStatus::NeedsHuman
                        )
                    })
                    .count();
                if novel > 0 {
                    vettalon::tr!(
                        "待人工候選 {novel}（OSV 狀態另列）",
                        "{novel} candidates for human review (see OSV status separately)"
                    )
                } else {
                    vettalon::lang::pick(
                        "已審範圍未提出候選（OSV 狀態另列）",
                        "no candidates in reviewed scope (see OSV status separately)",
                    )
                    .to_string()
                }
            };
            // The index is the plan position; with parallel audits they finish
            // out of order, so the line counts completions instead.
            let n = self
                .finished
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                + 1;
            eprintln!(
                "[vettalon] {}",
                vettalon::tr!(
                    "完成 {n}/{total}：{}@{} → {outcome}",
                    "done {n}/{total}: {}@{} → {outcome}",
                    h.target.name,
                    h.target.version
                )
            );
        }
    }
    match run_hunt_with_progress(
        &args.path,
        &opts,
        &osv,
        &fetcher,
        &auditor,
        &CliHuntProgress {
            finished: std::sync::atomic::AtomicUsize::new(0),
        },
    )
    .await
    {
        Ok(report) => {
            print!("{}", render_summary(&report));
            if let Some(path) = &args.report {
                match serde_json::to_string_pretty(&report) {
                    Ok(json) => match vettalon::util::write_private(path, json.as_bytes()) {
                        Ok(()) => eprintln!(
                            "[vettalon] {}",
                            vettalon::tr!("報告已寫入 {}", "report written: {}", path.display())
                        ),
                        Err(e) => {
                            eprintln!(
                                "[vettalon] {}",
                                vettalon::tr!(
                                    "無法寫入報告 {}：{e}",
                                    "cannot write the report {}: {e}",
                                    path.display()
                                )
                            );
                            return 2;
                        }
                    },
                    Err(e) => {
                        eprintln!(
                            "[vettalon] {}",
                            vettalon::tr!(
                                "報告序列化失敗：{e}",
                                "cannot serialise the report: {e}"
                            )
                        );
                        return 2;
                    }
                }
            }
            if let Some(dir) = &args.disclose_dir
                && let Err(error) = write_disclosure_drafts(
                    dir,
                    &disclosure_drafts(&report, chrono::Utc::now().date_naive()),
                )
            {
                eprintln!("[vettalon] {error}");
                return 2;
            }
            0
        }
        Err(e) => {
            eprintln!("[vettalon] {e}");
            2
        }
    }
}

/// Write each upstream disclosure draft to `<dir>/<dep>-<finding>.md` with the
/// pre-send checklist. Drafts only — nothing is sent.
fn write_disclosure_drafts(
    dir: &std::path::Path,
    drafts: &[vettalon::hunt::run::HuntDisclosure],
) -> Result<usize, String> {
    if drafts.is_empty() {
        eprintln!(
            "[vettalon] {}",
            vettalon::lang::pick(
                "沒有可揭露的新漏洞候選（需確認或 needs_human，且 OSV 查無已知）。",
                "no novelty candidates to disclose (they must be confirmed or needs_human and unknown to OSV)."
            )
        );
        return Ok(0);
    }
    std::fs::create_dir_all(dir).map_err(|e| {
        vettalon::tr!(
            "無法建立草稿目錄 {}：{e}",
            "cannot create the draft directory {}: {e}",
            dir.display()
        )
    })?;
    let safe = |s: &str| -> String {
        s.chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect()
    };
    let mut written = 0;
    for d in drafts {
        let name = format!("{}-{}.md", safe(&d.dependency), safe(&d.finding_id));
        let checklist = vettalon::disclose::CHECKLIST
            .iter()
            .map(|c| format!("- [ ] {c}"))
            .collect::<Vec<_>>()
            .join("\n");
        let content = format!(
            "# {}\n\n> 上游負責任揭露草稿（{}）。只是草稿，送出前請逐項確認下方清單。\n> 建議協調檢查日期：{}；公開另須核准{}\n\n{}\n\n---\n\n## 送出前檢查清單\n\n{checklist}\n",
            d.draft.subject,
            d.dependency,
            d.draft.disclose_by,
            d.draft
                .submit
                .as_deref()
                .map(|s| format!("\n> 送交位置：{s}"))
                .unwrap_or_default(),
            d.draft.body,
        );
        let path = dir.join(&name);
        match vettalon::util::write_private(&path, content.as_bytes()) {
            Ok(()) => written += 1,
            Err(e) => {
                return Err(vettalon::tr!(
                    "無法寫入草稿 {}：{e}（已保留 {written} 份成功草稿）",
                    "cannot write the draft {}: {e} ({written} completed drafts retained)",
                    path.display()
                ));
            }
        }
    }
    eprintln!(
        "[vettalon] {}",
        vettalon::tr!(
            "已寫入 {written} 份揭露草稿到 {}（草稿而已，不會自動送出）。",
            "wrote {written} disclosure drafts to {} (drafts only; nothing is sent).",
            dir.display()
        )
    );
    Ok(written)
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Some(l) = cli.lang.as_deref()
        && !matches!(l.to_ascii_lowercase().get(..2), Some("en" | "zh"))
    {
        eprintln!("[vettalon] --lang must be en or zh-TW (got {l:?})");
        return ExitCode::from(2);
    }
    vettalon::lang::set(vettalon::lang::detect(cli.lang.as_deref()));
    let code = match cli.command {
        Command::Scan(args) => cmd_scan(args).await,
        Command::Validate { report } => audit::cmd_validate(&report).await,
        Command::Evidence {
            action:
                EvidenceAction::Attach {
                    report,
                    finding,
                    manifest,
                    artifact_root,
                    output,
                },
        } => match audit::attach_proof_evidence(
            &report,
            &finding,
            &manifest,
            &artifact_root,
            &output,
        ) {
            Ok(()) => {
                println!(
                    "Attached operator-supplied artifact references; finding status unchanged: {}",
                    output.display()
                );
                if let Ok(attached) = audit::load_report_for_delivery(&output) {
                    println!(
                        "run_status={} incomplete_reason={:?}",
                        attached.run_status, attached.incomplete_reason
                    );
                    if let Some(record) = attached.findings.iter().find(|f| f.id == finding) {
                        println!("{}", record.proof_summary());
                    }
                }
                0
            }
            Err(error) => {
                eprintln!("proof attachment refused: {error}");
                2
            }
        },
        Command::Disclose {
            report,
            finding,
            channel,
            out,
        } => cmd_disclose(report, finding, channel, out),
        Command::Hunt(args) => cmd_hunt(args).await,
        Command::Models { config, probe } => cmd_models(config, probe).await,
        Command::Agents { action } => {
            let r = match action {
                AgentsAction::Build => vettalon::llm::container::build_images().await,
                AgentsAction::Stop => vettalon::llm::container::teardown().await,
            };
            match r {
                Ok(()) => {
                    println!("{}", vettalon::lang::pick("完成", "Done"));
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

#[cfg(test)]
mod hunt_intake_cli_tests {
    use super::*;

    #[tokio::test]
    async fn requested_hunt_report_write_failure_returns_error_for_valid_empty_source() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let config = dir.path().join("roster.toml");
        std::fs::write(&config, "model = []\n").unwrap();
        std::fs::write(
            project.join("Cargo.lock"),
            "version=3\n[[package]]\nname='own'\nversion='0.0.0'\n",
        )
        .unwrap();
        let report = dir.path().join("report-is-directory");
        std::fs::create_dir(&report).unwrap();
        let cli = Cli::try_parse_from([
            "vettalon",
            "hunt",
            project.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
            "--report",
            report.to_str().unwrap(),
        ])
        .unwrap();
        let Command::Hunt(args) = cli.command else {
            panic!("hunt parser");
        };
        assert_eq!(cmd_hunt(args).await, 2);
    }
    fn draft_fixture(id: &str) -> vettalon::hunt::run::HuntDisclosure {
        vettalon::hunt::run::HuntDisclosure {
            dependency: "fixture@1.0.0".into(),
            finding_id: id.into(),
            finding_title: "synthetic".into(),
            draft: vettalon::disclose::Draft {
                channel: vettalon::disclose::Channel::GithubAdvisory,
                subject: "Synthetic draft".into(),
                body: "Self-authored test only".into(),
                submit: None,
                disclose_by: "2026-12-01".into(),
            },
        }
    }

    #[test]
    fn written_disclosure_date_is_a_coordination_checkpoint_only() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            write_disclosure_drafts(dir.path(), &[draft_fixture("one")]).unwrap(),
            1
        );
        let text = std::fs::read_to_string(dir.path().join("fixture_1_0_0-one.md")).unwrap();
        assert!(text.contains("建議協調檢查日期：2026-12-01"));
        assert!(text.contains("公開另須核准"));
        assert!(!text.contains("建議公開時程"));
    }

    #[test]
    fn requested_disclosure_mkdir_failure_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let blocked = dir.path().join("file-not-directory");
        std::fs::write(&blocked, "preserve").unwrap();
        assert!(write_disclosure_drafts(&blocked, &[draft_fixture("one")]).is_err());
        assert_eq!(std::fs::read_to_string(&blocked).unwrap(), "preserve");
    }

    #[test]
    fn requested_disclosure_write_failure_preserves_already_written_drafts() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("fixture_1_0_0-two.md")).unwrap();
        assert!(
            write_disclosure_drafts(dir.path(), &[draft_fixture("one"), draft_fixture("two")])
                .is_err()
        );
        assert!(dir.path().join("fixture_1_0_0-one.md").is_file());
    }

    #[test]
    fn no_disclosure_candidates_is_success_without_creating_directory() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("not-needed");
        assert_eq!(write_disclosure_drafts(&output, &[]).unwrap(), 0);
        assert!(!output.exists());
    }
}
