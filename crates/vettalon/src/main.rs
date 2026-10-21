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
    /// Write a CycloneDX 1.6 VDR/VEX (JSON) of the dependency-advisory
    /// findings here. VEX states come only from recorded evidence; never
    /// `not_affected`.
    #[arg(long)]
    cyclonedx: Option<PathBuf>,
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
    /// Off by default. The top N ranked modules are audited by two finder
    /// families independently; candidates are merged when the same proposed
    /// fix changes both sink lines (else same sink location and CWE) and are
    /// refuted by a third family when the roster has one. Doubles the finder
    /// cost on those modules; the report records what the second family added
    /// (ensemble.dual_finder).
    #[arg(long, default_value_t = 0)]
    dual_finder_top: usize,
    /// Generate and run PoCs in a Docker sandbox (no network) for
    /// plausible High+ findings.
    #[arg(long)]
    poc: bool,
    /// Sandbox image for --poc (must already be pulled).
    #[arg(long, default_value = vettalon::sandbox::DEFAULT_POC_IMAGE)]
    poc_image: String,
    /// With --poc: shell command that runs this project's own tests, used to
    /// check a finding's suggested fix. Runs in the PoC sandbox (no network,
    /// read-only temporary copy of the tree, only /tmp writable). Overrides
    /// `[fix_check] test_command` in the config; never guessed.
    #[arg(long, value_name = "CMD")]
    fix_test_command: Option<String>,
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
    /// Independent refuter (verifier) runs for each finding of High severity
    /// and above, 1-5. All runs must agree: all plausible keeps needs_human
    /// (recorded as refuter_consistent), all refuted refutes, anything mixed
    /// stays candidate with verify_uncertain. Lower severities get one run.
    #[arg(long, default_value_t = audit::DEFAULT_REFUTER_RUNS, value_parser = parse_refuter_runs)]
    refuter_runs: usize,
    /// Correction calls (the reflector) when a finder reply breaks the JSON
    /// contract: 0 or 1 (default 1). 0 records the module as a parse
    /// failure with no second call, for runs that allow no automatic retry.
    #[arg(long, default_value_t = audit::DEFAULT_FINDER_PARSE_RETRIES as u64,
          value_parser = clap::value_parser!(u64).range(0..=audit::DEFAULT_FINDER_PARSE_RETRIES as u64))]
    finder_parse_retries: u64,
    /// Correction calls when a refuter reply breaks the reply contract
    /// (not JSON, plausible without blockers, refuted without a basis...):
    /// 0 or 1 (default 1). A reply that still breaks it is a verify error
    /// for that run, never a refutation.
    #[arg(long, default_value_t = audit::DEFAULT_VERIFIER_PARSE_RETRIES as u64,
          value_parser = clap::value_parser!(u64).range(0..=audit::DEFAULT_VERIFIER_PARSE_RETRIES as u64))]
    verifier_parse_retries: u64,
    /// Module ranker for the deep audit: `heuristic` (default, local ranking)
    /// or `jev` (TypeSafe Jev, metadata-only; requires a `[jev]` config
    /// block). Cloud models and scanner database updates may also use the network.
    #[arg(long, default_value = "heuristic")]
    rank: String,
    /// Two-stage ranking: `off` (default) or `cheap-model`. With
    /// `cheap-model`, after --rank a cheap model (--prescreen-model) scores
    /// each of the top --prescreen-pool audit units 1-5 from metadata and a
    /// short excerpt, and only the top --prescreen-top percent go on to the
    /// deep audit (still capped by --max-modules). Deep profile only. The
    /// excerpts go to that model's provider like any other model call.
    #[arg(long, default_value = "off", value_name = "off|cheap-model")]
    prescreen: String,
    /// Roster model id that scores units for --prescreen cheap-model
    /// (required then; pick a cheap one).
    #[arg(long, value_name = "ID")]
    prescreen_model: Option<String>,
    /// Audit units the prescreen scores (one model call each), 1-200.
    #[arg(long, default_value_t = vettalon::audit::prescreen::DEFAULT_POOL as u64, value_parser = clap::value_parser!(u64).range(1..=vettalon::audit::prescreen::MAX_POOL as u64))]
    prescreen_pool: u64,
    /// Percent of the prescreen pool that gets deep-audit budget, 1-100.
    #[arg(long, default_value_t = vettalon::audit::prescreen::DEFAULT_TOP_PERCENT, value_parser = clap::value_parser!(u8).range(1..=100))]
    prescreen_top: u8,
    /// Wall-clock cap in seconds for the finder step (from when it starts).
    /// Must be at least 60 and not above --time-budget.
    #[arg(long, value_name = "SECS")]
    finder_budget: Option<u64>,
    /// Wall-clock cap in seconds for the refuter (verifier) step; findings
    /// not yet reviewed when it runs out stay unverified and the run is
    /// incomplete. At least 60, not above --time-budget.
    #[arg(long, value_name = "SECS")]
    refuter_budget: Option<u64>,
    /// Wall-clock cap in seconds for the PoC step; no new PoC starts after
    /// it. At least 60, not above --time-budget.
    #[arg(long, value_name = "SECS")]
    poc_budget: Option<u64>,
}

#[derive(Args)]
struct VerifyArgs {
    /// Repository root the findings point into.
    path: PathBuf,
    /// Scan report or claims file to verify.
    #[arg(long)]
    input: PathBuf,
    /// Roster model id that reviews (exactly one).
    #[arg(long)]
    verifier: String,
    /// Model roster (default: ~/.vettalon/config.toml, else the claude CLI).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Independent refuter runs for High and above (1-5); lower severities
    /// get one.
    #[arg(long, default_value_t = audit::DEFAULT_REFUTER_RUNS, value_parser = parse_refuter_runs)]
    refuter_runs: usize,
    /// Correction calls when a refuter reply breaks the reply contract
    /// (not JSON, plausible without blockers, refuted without a basis...):
    /// 0 or 1 (default 1). A reply that still breaks it is a verify error
    /// for that run, never a refutation.
    #[arg(long, default_value_t = audit::DEFAULT_VERIFIER_PARSE_RETRIES as u64,
          value_parser = clap::value_parser!(u64).range(0..=audit::DEFAULT_VERIFIER_PARSE_RETRIES as u64))]
    verifier_parse_retries: u64,
    /// Write the result JSON (vettalon.verify/1) here.
    #[arg(long)]
    out: PathBuf,
    /// Per-call trace (JSON Lines), as `scan --trace`.
    #[arg(long)]
    trace: Option<PathBuf>,
    /// No extra refuter run starts after this many seconds (at least 60).
    #[arg(long, value_name = "SECS")]
    time_budget: Option<u64>,
}

/// Drafting options shared by `disclose` and `hunt --disclose-dir`.
#[derive(Args, Clone, Default)]
struct DraftArgs {
    /// Human reviewer pseudonym named in the draft's AI use statement
    /// (public on the draft). Default: `[disclosure] reviewer` in the config.
    /// Required: no reviewer, no draft.
    #[arg(long)]
    reviewer: Option<String>,
    /// Date of the human review, YYYY-MM-DD (default: today).
    #[arg(long, value_name = "DATE")]
    review_date: Option<String>,
    /// Also draft findings below the PoC evidence threshold (refuter-only),
    /// marked UNPROVEN. Scanner-only findings are never drafted.
    #[arg(long)]
    allow_unproven: bool,
    /// Draft body format: ghsa | minimal | kernel | email (default: the
    /// channel's own form).
    #[arg(long, value_name = "FORMAT")]
    format: Option<String>,
    /// Leave out the suggested-fix / patch section (for projects that do not
    /// accept tool-written patches).
    #[arg(long)]
    no_patch: bool,
    /// Run the pre-send duplicate check online: OSV, upstream GitHub commits
    /// touching the file (90 days) and open issues/PRs. Off: "not checked".
    #[arg(long)]
    check_duplicates: bool,
    /// Draft even though this project already has an unanswered draft; the
    /// reason is recorded in the throttle ledger.
    #[arg(long, value_name = "REASON")]
    force_throttle: Option<String>,
}

fn draft_options(
    a: &DraftArgs,
    config_reviewer: Option<&str>,
) -> Result<vettalon::disclose::DraftOptions, String> {
    let today = chrono::Local::now().date_naive();
    let reviewer = vettalon::disclose::Reviewer::resolve(
        a.reviewer.as_deref(),
        config_reviewer,
        a.review_date.as_deref(),
        today,
    )?;
    let mut o = vettalon::disclose::DraftOptions::new(reviewer, &home_dir());
    o.allow_unproven = a.allow_unproven;
    o.format = a
        .format
        .as_deref()
        .map(str::parse::<vettalon::disclose::DraftFormat>)
        .transpose()?;
    o.include_patch = !a.no_patch;
    if let Some(reason) = &a.force_throttle {
        if reason.trim().is_empty() {
            return Err("--force-throttle needs a reason".into());
        }
        o.force_throttle = Some(reason.clone());
    }
    Ok(o)
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
    /// Run the refuter on findings that already exist, with no finder call:
    /// a `scan --report` file (its unreviewed AI candidates) or a claims file
    /// (`{"schema": "vettalon.claims/1", "claims": [...]}`) from another tool.
    Verify(VerifyArgs),
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
    /// destination expects (GitHub advisory, minimal, Linux kernel, project
    /// email, TWCERT/CC, HITCON ZeroDay). Drafts only — nothing is ever sent.
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
        /// Config file holding `[disclosure] reviewer` (default:
        /// ~/.vettalon/config.toml).
        #[arg(long)]
        config: Option<PathBuf>,
        #[command(flatten)]
        draft: DraftArgs,
    },
    /// The per-project disclosure throttle ledger: list drafts, and close one
    /// when the maintainer answered (or it was never sent).
    DiscloseLedger {
        #[command(subcommand)]
        action: LedgerAction,
    },
    /// Hunt for not-yet-disclosed vulnerabilities in a project's OSS
    /// dependencies (supply-chain mode). Audits dependency SOURCE with the
    /// deep engine, uses OSV to focus on what is NOT already a known CVE, and
    /// surfaces verified novelty candidates for responsible disclosure.
    Hunt(HuntArgs),
    /// Turn a human-confirmed finding into a local Semgrep rule DRAFT for
    /// variant hunting (review required before use; never loaded or run).
    RuleDraft {
        /// A `scan --report` or `hunt --report` JSON file.
        report: PathBuf,
        /// Finding id (must be `confirmed`, i.e. human-triaged).
        #[arg(long)]
        finding: String,
        /// Output file (default: ~/.vettalon/semgrep-drafts/<id>.yaml). Never overwritten.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Local index of OpenSSF malicious-package (MAL-*) reports for
    /// `hunt --malicious-signals`.
    MalIndex {
        #[command(subcommand)]
        action: MalIndexAction,
    },
}

#[derive(Subcommand)]
enum MalIndexAction {
    /// Download the OSV export for one ecosystem and keep only MAL-* records.
    /// Reaches only osv-vulnerabilities.storage.googleapis.com.
    Update {
        /// npm | PyPI | crates.io | Go
        #[arg(long)]
        ecosystem: String,
        /// Refuse to install unless the archive SHA-256 matches.
        #[arg(long)]
        expect_sha256: Option<String>,
        /// Build from a local all.zip instead of downloading (offline).
        #[arg(long)]
        from_file: Option<PathBuf>,
        /// Index directory (default: ~/.vettalon/mal-index).
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Show which indexes are installed and whether their sidecar hashes verify.
    Status {
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum LedgerAction {
    /// Show every recorded draft.
    List,
    /// Close the open drafts of a project (the key `list` prints).
    Close {
        project: String,
        /// Only this finding id.
        #[arg(long)]
        finding: Option<String>,
        /// answered | withdrawn
        #[arg(long, default_value = "answered")]
        outcome: String,
        #[arg(long)]
        note: Option<String>,
    },
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
    /// Per-dependency wall-clock limit in seconds (fetch + audit), default
    /// 300. A slow dependency is recorded as timed-out and the hunt moves
    /// on. With --hunt-budget it caps a single dependency's share. At least 90.
    #[arg(long, value_name = "SECS")]
    dep_timeout: Option<u64>,
    /// Total hunt budget in dependency-seconds (each dependency's fetch +
    /// audit time, summed; concurrent dependencies overlap in wall clock).
    /// Each dependency gets remaining ÷ remaining dependencies when it
    /// starts, and time it does not use rolls forward. A dependency the
    /// budget can no longer fund (90 s) is deferred. Unset = a fixed
    /// --dep-timeout per dependency.
    #[arg(long, value_name = "SECS")]
    hunt_budget: Option<u64>,
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
    /// Candidate order before --max-deps: `default` (direct first, by name) or
    /// `risk` (exposure × reach × criticality, offline; breakdown printed).
    #[arg(long, default_value = "default", value_parser = ["default", "risk"])]
    dep_priority: String,
    /// JSON array of reachability verdicts ({ecosystem,name,version?,status:
    /// reachable|not-observed|unknown}) used by --dep-priority risk.
    #[arg(long)]
    reach_evidence: Option<PathBuf>,
    /// Give each finder bounded "variant seeds": OSV records for the package
    /// and upstream GitHub commits mentioning security/CVE/GHSA (api.github.com).
    #[arg(long)]
    variant_seeds: bool,
    /// Commit look-back window for --variant-seeds, in days.
    #[arg(long, default_value_t = 90, value_parser = clap::value_parser!(u32).range(1..=3650))]
    seed_days: u32,
    /// Rule-based malicious-package signals (release age, new install hooks,
    /// provenance change, MAL-ID, typosquat). Findings are always needs_human.
    #[arg(long)]
    malicious_signals: bool,
    /// Release-age cooldown for --malicious-signals, in hours.
    #[arg(long, default_value_t = 72)]
    cooldown_hours: u32,
    /// Package names exempt from the release-age rule (comma-separated).
    #[arg(long, value_delimiter = ',')]
    cooldown_exclude: Vec<String>,
    /// Cap on registry metadata lookups for --malicious-signals.
    #[arg(long, default_value_t = 100)]
    malicious_max_registry: usize,
    /// MAL-* index directory (default: ~/.vettalon/mal-index).
    #[arg(long)]
    mal_index_dir: Option<PathBuf>,
    #[command(flatten)]
    draft: DraftArgs,
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

/// `--refuter-runs`: 1..=MAX_REFUTER_RUNS (each run is one more model call).
fn parse_refuter_runs(s: &str) -> Result<usize, String> {
    let n: usize = s
        .parse()
        .map_err(|_| format!("not a whole number: {s:?}"))?;
    if (1..=audit::MAX_REFUTER_RUNS).contains(&n) {
        Ok(n)
    } else {
        Err(format!("must be 1-{}", audit::MAX_REFUTER_RUNS))
    }
}

async fn cmd_verify(a: VerifyArgs) -> i32 {
    use vettalon::audit::verify_only;
    let fail = |msg: String| {
        eprintln!("[vettalon] {msg}");
        2
    };
    if a.time_budget.is_some_and(|s| s < 60) {
        return fail("--time-budget must be at least 60 seconds".into());
    }
    let repo = match a.path.canonicalize() {
        Ok(p) if p.is_dir() => p,
        _ => return fail(format!("{} is not a directory", a.path.display())),
    };
    let input = match std::fs::read_to_string(&a.input)
        .map_err(|e| format!("cannot read {}: {e}", a.input.display()))
        .and_then(|t| verify_only::VerifyInput::parse(&t))
    {
        Ok(i) => i,
        Err(e) => return fail(e),
    };
    let (cfg, source) = match load_config(a.config.as_deref(), Some(&repo)) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let all = match cfg.handles() {
        Ok(h) => h,
        Err(e) => return fail(e),
    };
    let Some(verifier) = all
        .iter()
        .find(|(m, _)| m.id == a.verifier)
        .map(|(m, _)| m.clone())
    else {
        return fail(format!(
            "--verifier {:?} is not in the model roster ({source})",
            a.verifier
        ));
    };
    let families: std::collections::HashMap<String, String> = all
        .iter()
        .map(|(m, _)| (m.id.clone(), m.family.clone()))
        .collect();
    let trace = if a.trace.is_some() {
        vettalon::llm::TraceLog::recording()
    } else {
        vettalon::llm::TraceLog::default()
    };
    let deadline = a
        .time_budget
        .map(|s| std::time::Instant::now() + std::time::Duration::from_secs(s));
    let out = verify_only::run_verify(
        &repo,
        input,
        verify_only::VerifyOptions {
            verifier,
            families: &families,
            refuter_runs: a.refuter_runs,
            deadline,
            parse_retries: a.verifier_parse_retries as usize,
            trace: trace.clone(),
        },
    )
    .await;
    let json = match serde_json::to_string_pretty(&out) {
        Ok(j) => j,
        Err(e) => return fail(format!("cannot serialize the result: {e}")),
    };
    if let Err(e) = vettalon::util::write_private(&a.out, json.as_bytes()) {
        return fail(format!("cannot write {}: {e}", a.out.display()));
    }
    // The result is already on disk; a trace that cannot be written only warns.
    if let Some(path) = &a.trace {
        let mut lines = String::new();
        for e in trace.snapshot() {
            if let Ok(l) = serde_json::to_string(&e) {
                lines.push_str(&l);
                lines.push('\n');
            }
        }
        if let Err(e) = vettalon::util::write_private(path, lines.as_bytes()) {
            eprintln!("[vettalon] cannot write {}: {e}", path.display());
        }
    }
    eprintln!(
        "[vettalon] verify: {} reviewed, {} settled without a call, {} unverified, {} passed through, {} model call(s) -> {}",
        out.reviewed,
        out.zero_llm,
        out.unverified,
        out.passed_through,
        out.calls,
        a.out.display()
    );
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
        dual_finder_top,
        report,
        sarif,
        cyclonedx,
        fail_on,
        gates,
        fail_on_needs_human,
        poc,
        poc_image,
        fix_test_command,
        save,
        no_prior,
        trace,
        source_receipts,
        time_budget,
        refuter_runs,
        finder_parse_retries,
        verifier_parse_retries,
        rank,
        prescreen,
        prescreen_model,
        prescreen_pool,
        prescreen_top,
        finder_budget,
        refuter_budget,
        poc_budget,
    } = args;
    // Budget flags fail fast, before any scanner or model runs: a value
    // that cannot fund one call is a configuration error, not a budget.
    let budget = match vettalon::budget::validate_scan(vettalon::budget::ScanBudgetFlags {
        total: time_budget,
        finder: finder_budget,
        refuter: refuter_budget,
        poc: poc_budget,
    }) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[vettalon] {e}");
            return vettalon::budget::BUDGET_ERROR_EXIT;
        }
    };
    let want_prescreen = match prescreen.to_ascii_lowercase().as_str() {
        "off" => false,
        "cheap-model" => true,
        _ => {
            eprintln!(
                "[vettalon] {}",
                vettalon::tr!(
                    "--prescreen 必須是 off 或 cheap-model（收到 {prescreen:?}）",
                    "--prescreen must be off or cheap-model (got {prescreen:?})"
                )
            );
            return 2;
        }
    };
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
    if want_prescreen && !deep {
        eprintln!(
            "[vettalon] {}",
            vettalon::lang::pick(
                "--prescreen 只在 --profile deep 有效（quick 不跑 AI 審查）",
                "--prescreen only applies to --profile deep (quick runs no AI audit)"
            )
        );
        return 2;
    }
    if want_prescreen && prescreen_model.is_none() {
        eprintln!(
            "[vettalon] {}",
            vettalon::lang::pick(
                "--prescreen cheap-model 需要 --prescreen-model <id>（模型清單中的便宜模型）",
                "--prescreen cheap-model needs --prescreen-model <id> (a cheap model from your roster)"
            )
        );
        return 2;
    }
    if !want_prescreen && prescreen_model.is_some() {
        eprintln!(
            "[vettalon] {}",
            vettalon::lang::pick(
                "--prescreen-model 只在 --prescreen cheap-model 時使用",
                "--prescreen-model only applies with --prescreen cheap-model"
            )
        );
        return 2;
    }
    if budget.is_set() {
        if !deep {
            eprintln!(
                "[vettalon] {}",
                vettalon::lang::pick(
                    "提示：時間預算旗標只對 --profile deep 有作用（quick 不跑模型）",
                    "note: time budget flags only apply to --profile deep (quick runs no model)"
                )
            );
        }
        eprint!("[vettalon] {}", budget.render_table(poc));
    }
    let fix_test_command = match fix_test_command
        .as_deref()
        .map(audit::fix_check::validate_test_command)
    {
        Some(Err(e)) => {
            eprintln!("[vettalon] --fix-test-command: {e}");
            return 2;
        }
        _ => fix_test_command,
    };
    if fix_test_command.is_some() && !poc {
        eprintln!(
            "[vettalon] {}",
            vettalon::lang::pick(
                "--fix-test-command 需要搭配 --poc（修補檢查在 PoC 沙箱裡執行）",
                "--fix-test-command needs --poc (fix checks run in the PoC sandbox)"
            )
        );
        return 2;
    }
    let (finders, verifiers, poc_models, roster, rank_strategy, prescreen, fix_test_command) =
        if deep {
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
            let prescreen = match prescreen_model.as_deref() {
                None => None,
                Some(id) => match all.iter().find(|(m, _)| m.id == id) {
                    Some((m, _)) => Some(audit::prescreen::PrescreenOptions {
                        model: m.clone(),
                        pool: prescreen_pool as usize,
                        top_percent: prescreen_top,
                    }),
                    None => {
                        eprintln!(
                            "[vettalon] {}",
                            vettalon::tr!(
                                "--prescreen-model {id:?} 不在模型清單（{source}）",
                                "--prescreen-model {id:?} is not in the model roster ({source})"
                            )
                        );
                        return 2;
                    }
                },
            };
            // The CLI flag wins over the config key; neither is ever inferred.
            let fix_test_command = match fix_test_command {
                Some(cmd) => Some(cmd),
                None => match cfg.fix_check.as_ref().and_then(|f| f.test_command.clone()) {
                    Some(cmd) => match audit::fix_check::validate_test_command(&cmd) {
                        Ok(()) => Some(cmd),
                        Err(e) => {
                            eprintln!("[vettalon] [fix_check] test_command: {e}");
                            return 2;
                        }
                    },
                    None => None,
                },
            };
            (f, v, p, roster, rank_strategy, prescreen, fix_test_command)
        } else {
            (
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                audit::RankStrategy::Heuristic,
                None,
                fix_test_command,
            )
        };
    audit::set_poc_image(&poc_image);
    let opts = ScanOptions {
        repo_path: path,
        profile,
        report,
        sarif,
        cyclonedx,
        fail_on,
        gates,
        max_modules,
        poc,
        save,
        cross_check_top,
        dual_finder_top,
        fail_on_needs_human,
        no_prior,
        rank: rank_strategy,
        trace,
        source_receipts,
        time_budget: budget.total,
        refuter_runs,
        finder_parse_retries: finder_parse_retries as usize,
        verifier_parse_retries: verifier_parse_retries as usize,
        prescreen,
        role_caps: budget.caps,
        fix_test_command,
        finders,
        verifiers,
        poc_models,
        roster,
    };
    audit::cmd_scan(&home_dir(), opts).await
}

struct DiscloseCmd {
    input: PathBuf,
    finding: Option<String>,
    channel: Option<String>,
    out: Option<PathBuf>,
    config: Option<PathBuf>,
    draft: DraftArgs,
}

fn print_eligible(report: &vettalon::audit::schema::AuditReport) -> i32 {
    use vettalon::disclose;
    let rows: Vec<_> = report
        .findings
        .iter()
        .filter_map(|f| disclose::draft_eligibility(f, true).ok().map(|e| (f, e)))
        .collect();
    if rows.is_empty() {
        println!(
            "{}",
            vettalon::lang::pick(
                "沒有可提交的項目（掃描器或模型分析而已的項目一律不產生草稿）。",
                "Nothing to report (findings with scanner or model analysis only are never drafted)."
            )
        );
        return 0;
    }
    println!(
        "{}",
        vettalon::lang::pick(
            "可產生提交草稿的項目（--finding <id>；標「未證實」者須加 --allow-unproven）：",
            "Findings you can draft a report for (--finding <id>; UNPROVEN ones need --allow-unproven):"
        )
    );
    for (f, e) in rows {
        let loc = f
            .line
            .map(|l| format!("{}:{l}", f.file))
            .unwrap_or_else(|| f.file.clone());
        let mark = if e.unproven {
            vettalon::lang::pick("  [未證實]", "  [UNPROVEN]")
        } else {
            ""
        };
        println!(
            "  {}  [{}] {}  ({loc})  {}{mark}",
            f.id,
            f.severity.as_str(),
            f.title,
            e.level.key()
        );
    }
    0
}

fn print_package_notes(pkg: &vettalon::disclose::DisclosurePackage) {
    if pkg.unproven {
        eprintln!(
            "{}",
            vettalon::tr!(
                "!!! 未證實：證據等級 {}，只因 --allow-unproven 才產生草稿 !!!",
                "!!! UNPROVEN: evidence level {}, drafted only because of --allow-unproven !!!",
                pkg.evidence_level.key()
            )
        );
    }
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
    for w in &pkg.warnings {
        eprintln!("  ! {w}");
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
}

async fn cmd_disclose(cmd: DiscloseCmd) -> i32 {
    use vettalon::disclose;
    let report = match audit::load_report_for_delivery(&cmd.input) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[vettalon] {e}");
            return 2;
        }
    };
    let Some(wanted) = cmd.finding else {
        return print_eligible(&report);
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
    let channel = match cmd
        .channel
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
    let config_reviewer = match load_config(cmd.config.as_deref(), Some(Path::new(&report.repo))) {
        Ok((cfg, _)) => cfg.disclosure.and_then(|d| d.reviewer),
        Err(e) => {
            eprintln!("[vettalon] {e}");
            return 2;
        }
    };
    let opts = match draft_options(&cmd.draft, config_reviewer.as_deref()) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("[vettalon] {e}");
            return 2;
        }
    };
    let src = disclose::dedupe::HttpDedupeSource::new();
    let dedupe: Option<&dyn disclose::DedupeSource> =
        cmd.draft.check_duplicates.then_some(&src as _);
    let pkg = match disclose::prepare(&report, &id, channel, &opts, dedupe).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[vettalon] {e}");
            return 2;
        }
    };
    print_package_notes(&pkg);
    // Record first: a draft that exists but is missing from the ledger would
    // slip past the throttle.
    if let Err(e) = disclose::record_draft(&opts, &pkg, chrono::Local::now().date_naive()) {
        eprintln!("[vettalon] {e}");
        return 2;
    }
    let text = format!("{}\n\n{}\n", pkg.draft.subject, pkg.draft.body);
    if let Some(path) = &cmd.out {
        if let Err(e) = vettalon::util::write_private(path, text.as_bytes()) {
            eprintln!(
                "[vettalon] {}",
                vettalon::tr!(
                    "無法寫入 {}：{e}。節流紀錄已記下這份草稿，若不再產生請執行 `vettalon disclose-ledger close {} --outcome withdrawn`。",
                    "cannot write {}: {e}. The throttle ledger already holds this draft; if you will not redo it, run `vettalon disclose-ledger close {} --outcome withdrawn`.",
                    path.display(),
                    pkg.throttle.project
                )
            );
            return 2;
        }
        eprintln!(
            "{}",
            vettalon::tr!("草稿已寫入：{}", "Draft written: {}", path.display())
        );
    } else {
        println!("{text}");
    }
    eprintln!(
        "{}",
        vettalon::tr!(
            "已記入節流紀錄（{}）。維護者回覆後請執行 `vettalon disclose-ledger close {}`。",
            "recorded in the throttle ledger ({}). After the maintainer answers, run `vettalon disclose-ledger close {}`.",
            pkg.throttle.project,
            pkg.throttle.project
        )
    );
    0
}

fn cmd_disclose_ledger(action: LedgerAction) -> i32 {
    use vettalon::disclose::ledger;
    let path = ledger::default_path(&home_dir());
    match action {
        LedgerAction::List => match ledger::load(&path) {
            Ok(l) => {
                if l.entries.is_empty() {
                    println!("{}", vettalon::lang::pick("（沒有紀錄）", "(no entries)"));
                }
                for e in &l.entries {
                    println!(
                        "{:<10} {}  {}  drafted {}{}{}",
                        format!("{:?}", e.state).to_ascii_lowercase(),
                        e.project,
                        e.finding_id,
                        e.drafted_on,
                        e.closed_on
                            .as_deref()
                            .map(|d| format!("  closed {d}"))
                            .unwrap_or_default(),
                        e.forced_reason
                            .as_deref()
                            .map(|r| format!("  forced: {r}"))
                            .unwrap_or_default()
                    );
                }
                0
            }
            Err(e) => {
                eprintln!("[vettalon] {e}");
                2
            }
        },
        LedgerAction::Close {
            project,
            finding,
            outcome,
            note,
        } => {
            let state = match outcome.as_str() {
                "answered" => ledger::LedgerState::Answered,
                "withdrawn" => ledger::LedgerState::Withdrawn,
                other => {
                    eprintln!("[vettalon] --outcome must be answered or withdrawn (got {other:?})");
                    return 2;
                }
            };
            match ledger::close(
                &path,
                &project,
                finding.as_deref(),
                state,
                note.as_deref(),
                chrono::Local::now().date_naive(),
            ) {
                Ok(0) => {
                    eprintln!(
                        "[vettalon] {}",
                        vettalon::tr!("{project} 沒有未結案的草稿", "{project} has no open drafts")
                    );
                    2
                }
                Ok(n) => {
                    println!("{}", vettalon::tr!("已結案 {n} 筆", "closed {n} entr(ies)"));
                    0
                }
                Err(e) => {
                    eprintln!("[vettalon] {e}");
                    2
                }
            }
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
        run_hunt_seeded,
    };

    let budget = match vettalon::budget::validate_hunt(args.hunt_budget, args.dep_timeout) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[vettalon] {e}");
            return vettalon::budget::BUDGET_ERROR_EXIT;
        }
    };
    let reach_evidence = match &args.reach_evidence {
        None => Vec::new(),
        Some(path) => match std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))
            .and_then(|t| vettalon::hunt::priority::parse_reach_evidence(&t))
        {
            Ok(records) => records,
            Err(e) => {
                eprintln!("[vettalon] {e}");
                return 2;
            }
        },
    };
    let opts = HuntOptions {
        max_deps: args.max_deps,
        include_transitive: args.include_transitive,
        reaudit_known: args.reaudit_known,
        per_dep_timeout: match budget {
            vettalon::budget::HuntBudget::Fixed { per_dep } => per_dep,
            vettalon::budget::HuntBudget::Rollover(_) => {
                std::time::Duration::from_secs(vettalon::budget::DEFAULT_DEP_TIMEOUT_SECS)
            }
        },
        dep_concurrency: args.dep_concurrency as usize,
        dep_priority: if args.dep_priority == "risk" {
            vettalon::hunt::priority::DepPriority::Risk
        } else {
            vettalon::hunt::priority::DepPriority::Default
        },
        reach_evidence,
        variant_seeds: args
            .variant_seeds
            .then(|| vettalon::hunt::seeds::SeedOptions {
                days: args.seed_days,
                ..Default::default()
            }),
        rollover: match budget {
            vettalon::budget::HuntBudget::Fixed { .. } => None,
            vettalon::budget::HuntBudget::Rollover(r) => Some(r),
        },
    };
    let osv = HttpOsvClient::new();

    if args.dry_run {
        return match plan_hunt(&args.path, &opts, &osv).await {
            Ok(plan) => {
                eprint!("[vettalon] {}", budget.render_table(plan.selected.len()));
                print!("{}", render_plan(&plan));
                if args.malicious_signals {
                    // --dry-run fetches nothing: offline rules only, registry rules unknown.
                    let m = malicious_report(&args, &plan, false).await;
                    print!("{}", vettalon::hunt::malicious::render(&m));
                }
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
    // Drafting rules (reviewer, format) are checked before hours of auditing.
    let draft_opts = match &args.disclose_dir {
        Some(_) => match draft_options(&args.draft, cfg.disclosure_reviewer()) {
            Ok(o) => Some(o),
            Err(e) => {
                eprintln!("[vettalon] {e}");
                return 2;
            }
        },
        None => None,
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

    let draft_opts = draft_opts.map(|mut o| {
        o.roster = roster.clone();
        o
    });
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
        fn budget(&self, table: &str) {
            eprint!("[vettalon] {table}");
        }
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
    let seed_source = vettalon::hunt::seeds::HttpSeedSource::new();
    let seeds: Option<&dyn vettalon::hunt::seeds::SeedSource> =
        args.variant_seeds.then_some(&seed_source as _);
    match run_hunt_seeded(
        &args.path,
        &opts,
        &osv,
        &fetcher,
        &auditor,
        &CliHuntProgress {
            finished: std::sync::atomic::AtomicUsize::new(0),
        },
        seeds,
    )
    .await
    {
        Ok(mut report) => {
            if args.malicious_signals {
                // Re-plan offline-cheaply from the report's own rows (no new OSV call).
                let plan = vettalon::hunt::run::HuntPlan {
                    intake: None,
                    project: report.project.clone(),
                    total_targets: report.total_targets,
                    selected: report
                        .audited
                        .iter()
                        .map(|d| vettalon::hunt::osv::DependencyAdvisories {
                            target: d.target.clone(),
                            known: d.known.clone(),
                            osv: d.osv.clone(),
                        })
                        .collect(),
                    skipped: report.skipped.clone(),
                    dep_priority: report.dep_priority,
                    priorities: Vec::new(),
                };
                report.malicious = Some(malicious_report(&args, &plan, true).await);
            }
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
            if let (Some(dir), Some(opts)) = (&args.disclose_dir, &draft_opts) {
                let today = chrono::Local::now().date_naive();
                let src = vettalon::disclose::dedupe::HttpDedupeSource::new();
                let dedupe: Option<&dyn vettalon::disclose::DedupeSource> =
                    args.draft.check_duplicates.then_some(&src as _);
                let (drafts, skipped) = disclosure_drafts(&report, today, opts, dedupe).await;
                for s in &skipped {
                    eprintln!(
                        "[vettalon] {}",
                        vettalon::tr!(
                            "略過 {} {}：{}",
                            "skipped {} {}: {}",
                            s.dependency,
                            s.finding_id,
                            s.reason
                        )
                    );
                }
                if let Err(error) = write_disclosure_drafts(dir, &drafts, |d| {
                    vettalon::disclose::record_draft(opts, &d.package, today)
                }) {
                    eprintln!("[vettalon] {error}");
                    return 2;
                }
            }
            0
        }
        Err(e) => {
            eprintln!("[vettalon] {e}");
            2
        }
    }
}

/// Rule-based malicious-package signals over every planned target (O18).
async fn malicious_report(
    args: &HuntArgs,
    plan: &vettalon::hunt::run::HuntPlan,
    query_registries: bool,
) -> vettalon::hunt::malicious::MaliciousReport {
    use vettalon::hunt::{fetch::HttpSourceFetcher, mal_index, malicious, registry};
    let dir = args
        .mal_index_dir
        .clone()
        .unwrap_or_else(|| home_dir().join("mal-index"));
    let (indexes, errors) = mal_index::load_dir(&dir);
    for e in &errors {
        eprintln!("[vettalon] mal-index: {e}");
    }
    let probe = registry::LiveRegistryProbe {
        http: registry::HttpRegistryGet::new(),
        fetcher: HttpSourceFetcher::new(),
    };
    let opts = malicious::MaliciousOptions {
        cooldown_hours: args.cooldown_hours,
        cooldown_exclude: args.cooldown_exclude.clone(),
        max_registry_checks: args.malicious_max_registry,
    };
    let mut report = malicious::check_all(
        &plan.all_targets(),
        &plan.osv_rows(),
        query_registries.then_some(&probe as &dyn registry::RegistryProbe),
        &indexes,
        &opts,
        chrono::Utc::now(),
    )
    .await;
    if !errors.is_empty() {
        report.incomplete_reasons.push("mal_index_unusable".into());
        report.complete = false;
    }
    report
}

/// `vettalon rule-draft`: Semgrep rule draft from a confirmed finding.
fn cmd_rule_draft(report: &Path, finding: &str, out: Option<PathBuf>) -> i32 {
    let (found, origin) = match vettalon::hunt::run::load_hunt_report(report) {
        Ok(h) => match h
            .audited
            .iter()
            .flat_map(|d| d.findings.iter().map(move |f| (d, f)))
            .find(|(_, f)| f.id == finding)
        {
            Some((d, f)) => (
                Some(f.clone()),
                format!("{}@{}", d.target.name, d.target.version),
            ),
            None => (None, String::new()),
        },
        Err(_) => match audit::load_report_for_delivery(report) {
            Ok(r) => (
                r.findings.iter().find(|f| f.id == finding).cloned(),
                // Basename only: the draft may be shared, the absolute path need not be.
                std::path::Path::new(&r.repo)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            ),
            Err(e) => {
                eprintln!("[vettalon] {e}");
                return 2;
            }
        },
    };
    let Some(f) = found else {
        eprintln!(
            "[vettalon] {}",
            vettalon::tr!(
                "報告中沒有 finding {finding}",
                "no finding {finding} in the report"
            )
        );
        return 2;
    };
    let yaml = match vettalon::hunt::rule_draft::draft(&f, &origin, chrono::Utc::now().date_naive())
    {
        Ok(y) => y,
        Err(e) => {
            eprintln!("[vettalon] {e}");
            return 2;
        }
    };
    let path = out.unwrap_or_else(|| {
        let safe: String =
            f.id.chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                .collect();
        home_dir()
            .join("semgrep-drafts")
            .join(format!("{safe}.yaml"))
    });
    match vettalon::hunt::rule_draft::write_new(&path, &yaml) {
        Ok(()) => {
            eprintln!(
                "[vettalon] {}",
                vettalon::tr!(
                    "已寫入規則草稿 {}（使用前必須人工審閱，vettalon 不會自動載入）",
                    "rule draft written: {} (human review required before use; vettalon never loads it)",
                    path.display()
                )
            );
            0
        }
        Err(e) => {
            eprintln!("[vettalon] {e}");
            2
        }
    }
}

/// `vettalon mal-index update|status`.
async fn cmd_mal_index(action: MalIndexAction) -> i32 {
    use vettalon::hunt::mal_index;
    let default_dir = || home_dir().join("mal-index");
    match action {
        MalIndexAction::Status { dir } => {
            let dir = dir.unwrap_or_else(default_dir);
            let (indexes, errors) = mal_index::load_dir(&dir);
            for i in &indexes {
                println!(
                    "{}: {} entries, archive sha256 {}{}, fetched {} from {}",
                    i.ecosystem,
                    i.entries.len(),
                    i.archive_sha256,
                    if i.sha256_pinned {
                        " (pinned)"
                    } else {
                        " (not pinned)"
                    },
                    i.fetched_at,
                    i.source_url
                );
            }
            for e in &errors {
                println!("unusable: {e}");
            }
            if indexes.is_empty() && errors.is_empty() {
                println!("no index in {}", dir.display());
            }
            if errors.is_empty() { 0 } else { 2 }
        }
        MalIndexAction::Update {
            ecosystem,
            expect_sha256,
            from_file,
            dir,
        } => {
            let dir = dir.unwrap_or_else(default_dir);
            let url = match mal_index::archive_url(&ecosystem) {
                Ok(u) => u,
                Err(e) => {
                    eprintln!("[vettalon] {e}");
                    return 2;
                }
            };
            if let Err(e) = std::fs::create_dir_all(&dir) {
                eprintln!("[vettalon] cannot create {}: {e}", dir.display());
                return 2;
            }
            let staging = match tempfile::NamedTempFile::new_in(&dir) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("[vettalon] staging file: {e}");
                    return 2;
                }
            };
            let (archive, source, hashed) = match &from_file {
                Some(path) => (
                    path.clone(),
                    // Basename only: the index info is copied into shareable reports.
                    format!(
                        "file:{}",
                        path.file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default()
                    ),
                    mal_index::hash_file(path),
                ),
                None => {
                    eprintln!("[vettalon] downloading {url}");
                    (
                        staging.path().to_path_buf(),
                        url.clone(),
                        mal_index::download(&url, staging.path()).await,
                    )
                }
            };
            let hashed = match hashed {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("[vettalon] {e}");
                    return 2;
                }
            };
            eprintln!(
                "[vettalon] archive sha256 {} ({} bytes)",
                hashed.0, hashed.1
            );
            match mal_index::install(
                &archive,
                &ecosystem,
                &source,
                hashed,
                expect_sha256.as_deref(),
                &dir,
                chrono::Utc::now(),
            ) {
                Ok((path, index)) => {
                    println!(
                        "{}: {} MAL entries -> {}{}",
                        index.ecosystem,
                        index.entries.len(),
                        path.display(),
                        if index.sha256_pinned {
                            ""
                        } else {
                            " (archive hash not pinned; pass --expect-sha256 to pin)"
                        }
                    );
                    0
                }
                Err(e) => {
                    eprintln!("[vettalon] {e}");
                    2
                }
            }
        }
    }
}

/// Write each upstream disclosure draft to `<dir>/<dep>-<finding>.md` with the
/// pre-send checklist, calling `record` after each successful write (the
/// throttle ledger). Drafts only — nothing is sent.
fn write_disclosure_drafts(
    dir: &std::path::Path,
    drafts: &[vettalon::hunt::run::HuntDisclosure],
    mut record: impl FnMut(&vettalon::hunt::run::HuntDisclosure) -> Result<(), String>,
) -> Result<usize, String> {
    if drafts.is_empty() {
        eprintln!(
            "[vettalon] {}",
            vettalon::lang::pick(
                "沒有產生揭露草稿（候選須 OSV 查無已知、達證據門檻或加 --allow-unproven，並通過節流）。",
                "no disclosure drafts produced (candidates must be unknown to OSV, meet the evidence threshold or be allowed with --allow-unproven, and pass the throttle)."
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
        let pkg = &d.package;
        let checklist = pkg
            .checklist
            .iter()
            .map(|c| format!("- [ ] {c}"))
            .collect::<Vec<_>>()
            .join("\n");
        let content = format!(
            "# {}\n\n> 上游負責任揭露草稿（{}）。只是草稿，送出前請逐項確認下方清單。\n> 證據等級：{}{}；格式：{}；審閱者：{}（{}）\n> 建議協調檢查日期：{}；公開另須核准{}\n\n{}\n\n---\n\n## 送出前檢查清單\n\n{checklist}\n",
            pkg.draft.subject,
            d.dependency,
            pkg.evidence_level.key(),
            if pkg.unproven {
                "（未證實，僅因 --allow-unproven 產生）"
            } else {
                ""
            },
            pkg.format,
            pkg.ai_use.reviewer.pseudonym,
            pkg.ai_use.reviewer.review_date,
            pkg.draft.disclose_by,
            pkg.draft
                .submit
                .as_deref()
                .map(|s| format!("\n> 送交位置：{s}"))
                .unwrap_or_default(),
            pkg.draft.body,
        );
        let path = dir.join(&name);
        match vettalon::util::write_private(&path, content.as_bytes()) {
            Ok(()) => {
                written += 1;
                record(d)?;
            }
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
        Command::Verify(args) => cmd_verify(args).await,
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
            config,
            draft,
        } => {
            cmd_disclose(DiscloseCmd {
                input: report,
                finding,
                channel,
                out,
                config,
                draft,
            })
            .await
        }
        Command::DiscloseLedger { action } => cmd_disclose_ledger(action),
        Command::Hunt(args) => cmd_hunt(args).await,
        Command::RuleDraft {
            report,
            finding,
            out,
        } => cmd_rule_draft(&report, &finding, out),
        Command::MalIndex { action } => cmd_mal_index(action).await,
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
    fn no_record(_: &vettalon::hunt::run::HuntDisclosure) -> Result<(), String> {
        Ok(())
    }

    fn draft_fixture(id: &str) -> vettalon::hunt::run::HuntDisclosure {
        use vettalon::audit::schema::{
            EvidenceItem, EvidenceKind, Finding, FindingKind, FindingStatus, Severity,
        };
        let today = chrono::NaiveDate::from_ymd_opt(2026, 10, 13).unwrap();
        let mut f = Finding::candidate(
            "ai_audit",
            FindingKind::Other,
            Severity::High,
            "Synthetic draft",
            "src/a.rs",
            Some(1),
            "s",
            "ai-audit/x",
            vec![EvidenceItem {
                kind: EvidenceKind::OperatorReview,
                source: "dashboard".into(),
                detail: "operator_decision: confirmed; reason: self-authored test".into(),
                recorded_at: "2026-10-13T00:00:00Z".into(),
            }],
        );
        f.status = FindingStatus::Confirmed;
        let home = tempfile::tempdir().unwrap();
        let reviewer =
            vettalon::disclose::Reviewer::resolve(Some("night-owl"), None, None, today).unwrap();
        let opts = vettalon::disclose::DraftOptions::new(reviewer, home.path());
        let meta = vettalon::disclose::ProjectMeta {
            name: Some("fixture".into()),
            github: Some("acme/fixture".into()),
            ..Default::default()
        };
        let package = vettalon::disclose::package_for(
            &f,
            meta,
            None,
            today,
            &opts,
            vettalon::disclose::FindingExtras::default(),
        )
        .unwrap();
        vettalon::hunt::run::HuntDisclosure {
            dependency: "fixture@1.0.0".into(),
            finding_id: id.into(),
            finding_title: "synthetic".into(),
            package,
        }
    }

    #[test]
    fn disclose_and_hunt_parse_the_draft_flags() {
        let cli = Cli::try_parse_from([
            "vettalon",
            "disclose",
            "r.json",
            "--finding",
            "x",
            "--reviewer",
            "night-owl",
            "--format",
            "kernel",
            "--no-patch",
            "--allow-unproven",
            "--check-duplicates",
            "--force-throttle",
            "urgent",
        ])
        .unwrap();
        let Command::Disclose { draft, .. } = cli.command else {
            panic!("disclose parser");
        };
        let o = draft_options(&draft, None).unwrap();
        assert_eq!(o.reviewer.pseudonym, "night-owl");
        assert_eq!(o.format, Some(vettalon::disclose::DraftFormat::Kernel));
        assert!(!o.include_patch && o.allow_unproven);
        assert_eq!(o.force_throttle.as_deref(), Some("urgent"));
        assert!(draft.check_duplicates);
        // No reviewer anywhere: refused.
        assert!(draft_options(&DraftArgs::default(), None).is_err());
        assert!(
            draft_options(
                &DraftArgs {
                    format: Some("pdf".into()),
                    ..Default::default()
                },
                Some("cfg")
            )
            .is_err()
        );
        let cli = Cli::try_parse_from([
            "vettalon",
            "hunt",
            ".",
            "--disclose-dir",
            "d",
            "--reviewer",
            "r",
        ])
        .unwrap();
        assert!(matches!(cli.command, Command::Hunt(_)));
        let cli = Cli::try_parse_from([
            "vettalon",
            "disclose-ledger",
            "close",
            "github:a/b",
            "--outcome",
            "withdrawn",
        ])
        .unwrap();
        assert!(matches!(cli.command, Command::DiscloseLedger { .. }));
    }

    #[tokio::test]
    async fn hunt_with_disclose_dir_and_no_reviewer_fails_before_auditing() {
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
        let cli = Cli::try_parse_from([
            "vettalon",
            "hunt",
            project.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
            "--disclose-dir",
            dir.path().join("drafts").to_str().unwrap(),
        ])
        .unwrap();
        let Command::Hunt(args) = cli.command else {
            panic!("hunt parser");
        };
        assert_eq!(cmd_hunt(args).await, 2);
        assert!(!dir.path().join("drafts").exists());
    }

    #[test]
    fn written_disclosure_date_is_a_coordination_checkpoint_only() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            write_disclosure_drafts(dir.path(), &[draft_fixture("one")], no_record).unwrap(),
            1
        );
        let text = std::fs::read_to_string(dir.path().join("fixture_1_0_0-one.md")).unwrap();
        assert!(text.contains("建議協調檢查日期：2027-01-11"));
        assert!(text.contains("證據等級：maintainer_confirmed"));
        assert!(text.contains("night-owl"));
        assert!(text.contains("公開另須核准"));
        assert!(!text.contains("建議公開時程"));
    }

    #[test]
    fn requested_disclosure_mkdir_failure_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let blocked = dir.path().join("file-not-directory");
        std::fs::write(&blocked, "preserve").unwrap();
        assert!(write_disclosure_drafts(&blocked, &[draft_fixture("one")], no_record).is_err());
        assert_eq!(std::fs::read_to_string(&blocked).unwrap(), "preserve");
    }

    #[test]
    fn requested_disclosure_write_failure_preserves_already_written_drafts() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("fixture_1_0_0-two.md")).unwrap();
        assert!(
            write_disclosure_drafts(
                dir.path(),
                &[draft_fixture("one"), draft_fixture("two")],
                no_record
            )
            .is_err()
        );
        assert!(dir.path().join("fixture_1_0_0-one.md").is_file());
    }

    #[test]
    fn no_disclosure_candidates_is_success_without_creating_directory() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("not-needed");
        assert_eq!(write_disclosure_drafts(&output, &[], no_record).unwrap(), 0);
        assert!(!output.exists());
    }
}

#[cfg(test)]
mod o7_o8_o18_cli_tests {
    use super::*;
    use vettalon::audit::schema::{Finding, FindingKind, FindingStatus, Severity};

    fn hunt_report_with(status: FindingStatus) -> (tempfile::TempDir, PathBuf, String) {
        let mut f = Finding::candidate(
            "ai_audit",
            FindingKind::Other,
            Severity::High,
            "Unescaped attribute",
            "src/lib.rs",
            Some(3),
            "let out = attr(\"href\", v);",
            "ai-audit/xss",
            vec![],
        );
        f.status = status;
        let id = f.id.clone();
        let report = serde_json::json!({
            "project": "p",
            "total_targets": 1,
            "audited": [{
                "target": {"ecosystem":"cargo","name":"ammonia","version":"4.0.0","direct":true},
                "known": [], "audited": true, "error": null,
                "upstream": {"github": null, "security_emails": []},
                "findings": [f]
            }],
            "skipped": []
        });
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hunt.json");
        std::fs::write(&path, serde_json::to_vec(&report).unwrap()).unwrap();
        (dir, path, id)
    }

    #[test]
    fn rule_draft_cli_writes_once_and_refuses_unconfirmed() {
        let (dir, report, id) = hunt_report_with(FindingStatus::Confirmed);
        let out = dir.path().join("rule.yaml");
        assert_eq!(cmd_rule_draft(&report, &id, Some(out.clone())), 0);
        let yaml = std::fs::read_to_string(&out).unwrap();
        assert!(yaml.contains("ammonia@4.0.0") && yaml.contains("review_required: true"));
        assert_eq!(
            cmd_rule_draft(&report, &id, Some(out.clone())),
            2,
            "never overwrites"
        );
        let (dir2, report2, id2) = hunt_report_with(FindingStatus::NeedsHuman);
        assert_eq!(
            cmd_rule_draft(&report2, &id2, Some(dir2.path().join("r.yaml"))),
            2
        );
        assert_eq!(cmd_rule_draft(&report2, "missing", None), 2);
    }

    #[test]
    fn new_hunt_flags_parse_with_safe_defaults() {
        let cli = Cli::try_parse_from(["vettalon", "hunt", "."]).unwrap();
        let Command::Hunt(a) = cli.command else {
            panic!("hunt parser")
        };
        assert_eq!(a.dep_priority, "default");
        assert!(!a.variant_seeds && !a.malicious_signals);
        assert_eq!((a.seed_days, a.cooldown_hours), (90, 72));
        let cli = Cli::try_parse_from([
            "vettalon",
            "hunt",
            ".",
            "--dep-priority",
            "risk",
            "--variant-seeds",
            "--seed-days",
            "30",
            "--malicious-signals",
            "--cooldown-exclude",
            "a,b",
        ])
        .unwrap();
        let Command::Hunt(a) = cli.command else {
            panic!("hunt parser")
        };
        assert_eq!(a.dep_priority, "risk");
        assert_eq!(a.cooldown_exclude, vec!["a", "b"]);
        assert!(Cli::try_parse_from(["vettalon", "hunt", ".", "--dep-priority", "fast"]).is_err());
    }

    #[tokio::test]
    async fn mal_index_update_from_file_is_offline_and_status_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("all.zip");
        {
            use std::io::Write;
            let mut w = zip::ZipWriter::new(std::fs::File::create(&zip_path).unwrap());
            w.start_file("MAL-1.json", zip::write::SimpleFileOptions::default())
                .unwrap();
            w.write_all(
                br#"{"id":"MAL-1","affected":[{"package":{"ecosystem":"npm","name":"evil"},"versions":["1.0.0"]}]}"#,
            )
            .unwrap();
            w.finish().unwrap();
        }
        let idx = dir.path().join("idx");
        let update = |sha: Option<String>| MalIndexAction::Update {
            ecosystem: "npm".into(),
            expect_sha256: sha,
            from_file: Some(zip_path.clone()),
            dir: Some(idx.clone()),
        };
        assert_eq!(cmd_mal_index(update(Some("00".into()))).await, 2);
        assert_eq!(cmd_mal_index(update(None)).await, 0);
        assert_eq!(
            cmd_mal_index(MalIndexAction::Status {
                dir: Some(idx.clone())
            })
            .await,
            0
        );
        assert_eq!(
            cmd_mal_index(MalIndexAction::Update {
                ecosystem: "Maven".into(),
                expect_sha256: None,
                from_file: None,
                dir: Some(idx),
            })
            .await,
            2
        );
    }
}
