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
    /// Finder attack-class methodologies: auto selects up to three; all uses all eight (more tokens).
    /// Overrides config attack_classes; defaults to off when neither is set.
    #[arg(long, value_enum)]
    attack_classes: Option<audit::attack_classes::AttackClassMode>,
    /// Repository root.
    path: PathBuf,
    /// Deep PR scope relative to a Git ref. Quick accepts but ignores this flag.
    #[arg(long, value_name = "REF", value_parser = vettalon::audit::diff_scope::validate_ref)]
    diff_base: Option<String>,
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
    /// Deep only: exit on the --fail-on/--gate result (0 or 1) even when no
    /// AI engine could run. Without it such a scan exits 4, so CI cannot
    /// mistake it for a clean deep scan. The report is the same either way.
    #[arg(long)]
    allow_incomplete: bool,
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
    /// Refuter policy: `current` (default: refute unless provable) or
    /// `evidence+retrieval`, an opt-in conservative mode (closing needs
    /// cited, checked evidence; undecided claims stay candidate as
    /// unresolved; definitions the refuter could not see are grepped and it
    /// judges once more). In one benchmark it closed fewer real
    /// vulnerabilities and also fewer false alerts, so expect more alerts to
    /// review. Experimental: `evidence`, `evidence-ext` (evidence only for
    /// external scanner claims) and `+prosecutor` (a blind bypass attempt on
    /// guard / trust closures).
    #[arg(long, default_value = "current", value_parser = parse_refuter_policy)]
    refuter_policy: audit::RefuterPolicy,
    /// Experimental: ask every refuter run for a probability (0-100) that the
    /// claim is real and an evidence level, and record them. No decision
    /// reads the scores; the prompt gains a section, so replies may differ.
    #[arg(long)]
    refuter_score: bool,
    /// Experimental, opt-in: a refutation closes a finding only when the
    /// same reply's probability is below this value (0-100); a higher,
    /// missing or invalid score keeps the finding open as `candidate`.
    /// Turns on --refuter-score.
    #[arg(long, value_name = "P", value_parser = clap::value_parser!(u8).range(0..=100))]
    refuter_score_threshold: Option<u8>,
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
    /// Refuter policy, as `scan --refuter-policy` (default `current`;
    /// `evidence+retrieval` is the opt-in conservative mode).
    #[arg(long, default_value = "current", value_parser = parse_refuter_policy)]
    refuter_policy: audit::RefuterPolicy,
    /// Experimental, as `scan --refuter-score`: record each refuter run's
    /// probability (0-100) and evidence level. No decision reads them.
    #[arg(long)]
    refuter_score: bool,
    /// Experimental, as `scan --refuter-score-threshold`: close only when
    /// the reply's probability is below this value (0-100).
    #[arg(long, value_name = "P", value_parser = clap::value_parser!(u8).range(0..=100))]
    refuter_score_threshold: Option<u8>,
    /// Experimental, opt-in: after review, a Joern source-to-sink data-flow
    /// path to the claimed line keeps a finding the refuter closed open
    /// (`candidate`). Never closes anything; no path, an unsupported language
    /// or any Joern error leaves the verdict as it was. Runs only in the local
    /// `vettalon joern build` image, without network.
    #[arg(long)]
    joern_keep: bool,
    /// Timeout per Joern container run in seconds (30-7200).
    #[arg(long, value_name = "SECS", requires = "joern_keep",
          default_value_t = vettalon::joern::DEFAULT_TIMEOUT_SECS,
          value_parser = clap::value_parser!(u64).range(vettalon::joern::MIN_TIMEOUT_SECS..=vettalon::joern::MAX_TIMEOUT_SECS))]
    joern_timeout: u64,
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

#[derive(Args)]
struct ReproduceArgs {
    /// Repository root whose bytes must match the validated report.
    path: PathBuf,
    /// Validator-clean scan report containing the pinned finding.
    #[arg(long)]
    report: PathBuf,
    /// Exact finding id, or a unique prefix.
    #[arg(long)]
    finding: String,
    /// Closed TargetCall JSON: file, top-level function and data-only args.
    #[arg(long, value_name = "JSON")]
    target: PathBuf,
    /// Local sandbox image; never pulled automatically.
    #[arg(long, default_value = vettalon::sandbox::DEFAULT_POC_IMAGE)]
    poc_image: String,
    /// Write the versioned target-PoC receipt here (0600).
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args)]
struct FixCheckArgs {
    /// Repository root whose bytes must match the validated report.
    path: PathBuf,
    /// Validator-clean scan report containing the pinned finding and,
    /// unless --diff is used, its suggested fix.
    #[arg(long)]
    report: PathBuf,
    /// Exact finding id, or a unique prefix.
    #[arg(long)]
    finding: String,
    /// The same closed TargetCall JSON used by `reproduce`.
    #[arg(long, value_name = "JSON")]
    target: PathBuf,
    /// Operator-supplied unified diff. Omit to check the report's suggested fix.
    /// The live tree is never modified.
    #[arg(long, value_name = "PATCH")]
    diff: Option<PathBuf>,
    /// Project test command run inside the same isolated sandbox, first on
    /// the original prepared copy and then on the fixed copy.
    #[arg(long, value_name = "CMD")]
    test_command: Option<String>,
    /// Local sandbox image; never pulled automatically.
    #[arg(long, default_value = vettalon::sandbox::DEFAULT_POC_IMAGE)]
    poc_image: String,
    /// Write the versioned bound fix-check receipt here (0600).
    #[arg(long)]
    out: PathBuf,
    /// Write the validator-clean report with this exact diff and its bound
    /// fix-check evidence here (0600). The input report is never overwritten.
    #[arg(long)]
    report_out: PathBuf,
}

#[derive(Subcommand)]
enum FixAction {
    /// Check a suggested/operator diff on private before/after copies. Never applies it.
    Check(FixCheckArgs),
}

#[derive(Subcommand)]
enum VerificationRegistryAction {
    /// Add one immutable case descriptor. Existing identical content is idempotent.
    Add {
        #[arg(long)]
        registry: PathBuf,
        #[arg(long = "case")]
        case_path: PathBuf,
    },
    /// Add one stable, content-addressed counterexample descriptor.
    AddCell {
        #[arg(long)]
        registry: PathBuf,
        #[arg(long = "cell")]
        cell_path: PathBuf,
    },
    /// Record that an actor read a case for development, evaluation or audit.
    Access {
        #[arg(long)]
        registry: PathBuf,
        #[arg(long = "case")]
        case_id: String,
        #[arg(long, value_parser = ["development", "evaluation", "audit"])]
        purpose: String,
        #[arg(long)]
        actor: String,
    },
    /// Recompute the effective split; development access permanently contaminates hidden cases.
    Audit {
        #[arg(long)]
        registry: PathBuf,
        #[arg(long = "case")]
        case_id: String,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum VerificationAction {
    /// Re-derive and validate a verification event; stored verdicts are never trusted.
    Validate {
        #[arg(long)]
        event: PathBuf,
    },
    /// Compare two execution envelopes bound to the same Verification IR.
    Compare {
        #[arg(long)]
        ir: PathBuf,
        #[arg(long)]
        first: PathBuf,
        #[arg(long)]
        second: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Recompute the seven engineering-moat denominator families from preregistered rows.
    Scorecard {
        #[arg(long)]
        measurements: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Maintain a local, content-addressed evaluation registry.
    Registry {
        #[command(subcommand)]
        action: VerificationRegistryAction,
    },
}

// Parsed once at startup; boxing the big variant buys nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum Command {
    /// Explain a Vettalon code offline (reference pages are in English).
    Explain {
        #[arg(
            value_name = "CODE",
            required_unless_present = "list",
            conflicts_with = "list"
        )]
        code: Option<String>,
        /// List all codes with English summaries.
        #[arg(long)]
        list: bool,
    },
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
    /// Reproduce one finding against the exact selected Python source in
    /// three fresh, network-disabled containers. Never changes its status.
    Reproduce(ReproduceArgs),
    /// Inspect a fix candidate without applying it to the live repository.
    Fix {
        #[command(subcommand)]
        action: FixAction,
    },
    /// Validate proof-carrying events, compare replays and track holdout lineage.
    Verification {
        #[command(subcommand)]
        action: VerificationAction,
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
    /// Experimental: the local Joern image behind `verify --joern-keep`.
    Joern {
        #[command(subcommand)]
        action: JoernAction,
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
enum JoernAction {
    /// Build the Joern image from the definition in this binary (downloads
    /// the pinned Joern release, about 1.8 GB, and checks its hashes).
    Build,
    /// Print the expected Joern image tag (no Docker call).
    Image,
    /// Ask the fixed source-to-sink template about each claim's file:line in
    /// one source tree. No model call, no verdict; writes
    /// vettalon.joern-check/1 JSON.
    Check {
        /// Source tree the claims point into.
        path: PathBuf,
        /// Claims file (vettalon.claims/1).
        #[arg(long)]
        claims: PathBuf,
        #[arg(long)]
        out: PathBuf,
        /// Timeout per container run in seconds (30-7200).
        #[arg(long, value_name = "SECS",
              default_value_t = vettalon::joern::DEFAULT_TIMEOUT_SECS,
              value_parser = clap::value_parser!(u64).range(vettalon::joern::MIN_TIMEOUT_SECS..=vettalon::joern::MAX_TIMEOUT_SECS))]
        timeout: u64,
    },
}

#[derive(Subcommand)]
enum AgentsAction {
    /// Build every image locally from the definitions in this binary (needs
    /// network access; nothing is pulled from GHCR).
    Build,
    /// Pull the egress proxy and the grok-free base from GHCR, verify their
    /// cosign signatures, pin them by digest, then add grok locally.
    Pull {
        /// Skip the signature check (insecure: trusts whatever the registry
        /// serves). Without cosign installed, pull refuses unless this is set.
        #[arg(long)]
        no_verify: bool,
    },
    /// Remove the egress proxy and the internal network.
    Stop,
    /// Print the expected image tags, one per line (no Docker call): the
    /// agents image, the egress proxy, then the published agents base.
    /// Tags follow the image definitions, not the vettalon version.
    Images,
}

#[derive(clap::Args)]
struct HuntArgs {
    /// Finder attack-class methodologies: auto selects up to three; all uses all eight (more tokens).
    /// Overrides config attack_classes; defaults to off when neither is set.
    #[arg(long, value_enum)]
    attack_classes: Option<audit::attack_classes::AttackClassMode>,
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
可改用工具能完全關閉的 CLI、HTTP/Ollama backend；若設 allow_agent_tools = true，代表明確接受它直接讀取本機檔案與認證的風險。",
                "note: found {}, but their tools cannot be fully disabled (they may read local files), so they are not used without a config file. \
Use a tool-disabled CLI or HTTP/Ollama backend instead; setting allow_agent_tools = true explicitly accepts direct access to local files and credentials.",
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

/// `--refuter-policy`: `current` or `+`-joined evidence / evidence-ext /
/// prosecutor / retrieval.
fn parse_refuter_policy(s: &str) -> Result<audit::RefuterPolicy, String> {
    audit::RefuterPolicy::parse(s)
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

async fn cmd_joern(action: JoernAction) -> i32 {
    let fail = |msg: String| {
        eprintln!("[vettalon] {msg}");
        2
    };
    match action {
        JoernAction::Image => {
            println!("{}", vettalon::llm::container::joern_image());
            0
        }
        JoernAction::Build => match vettalon::llm::container::build_joern_image().await {
            Ok(()) => {
                println!("{}", vettalon::lang::pick("完成", "Done"));
                0
            }
            Err(e) => fail(e),
        },
        JoernAction::Check {
            path,
            claims,
            out,
            timeout,
        } => {
            use vettalon::audit::verify_only::VerifyInput;
            let src = match path.canonicalize() {
                Ok(p) if p.is_dir() => p,
                _ => return fail(format!("{} is not a directory", path.display())),
            };
            let input = match std::fs::read_to_string(&claims)
                .map_err(|e| format!("cannot read {}: {e}", claims.display()))
                .and_then(|t| VerifyInput::parse(&t))
            {
                Ok(VerifyInput::Claims(c)) => c,
                Ok(_) => {
                    return fail("`joern check` takes a claims file (vettalon.claims/1)".into());
                }
                Err(e) => return fail(e),
            };
            let refs: Vec<vettalon::joern::ClaimRef> = input
                .iter()
                .map(|c| (c.id.clone(), c.file.clone(), c.line))
                .collect();
            let settings = vettalon::joern::JoernSettings::new(timeout);
            let report = match vettalon::joern::check_claims(&src, &refs, &settings).await {
                Ok(r) => r,
                Err(e) => return fail(e),
            };
            let json = match serde_json::to_string_pretty(&report) {
                Ok(j) => j,
                Err(e) => return fail(format!("cannot serialize the result: {e}")),
            };
            if let Err(e) = vettalon::util::write_private(&out, json.as_bytes()) {
                return fail(format!("cannot write {}: {e}", out.display()));
            }
            // Exit 0 even when runs failed: every failure is in the JSON.
            0
        }
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
            policy: a.refuter_policy,
            score: a.refuter_score,
            score_threshold: a.refuter_score_threshold,
            joern: a
                .joern_keep
                .then(|| vettalon::joern::JoernSettings::new(a.joern_timeout)),
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
        diff_base,
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
        allow_incomplete,
        poc,
        poc_image,
        fix_test_command,
        save,
        no_prior,
        trace,
        source_receipts,
        attack_classes,
        time_budget,
        refuter_runs,
        finder_parse_retries,
        verifier_parse_retries,
        refuter_policy,
        refuter_score,
        refuter_score_threshold,
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
    let mut attack_classes = attack_classes;
    let (finders, verifiers, poc_models, roster, rank_strategy, prescreen, fix_test_command) =
        if deep {
            let (cfg, source) = match load_config(config.as_deref(), Some(&path)) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("[vettalon] {e}");
                    return 2;
                }
            };
            attack_classes = attack_classes.or(cfg.attack_classes);
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
    let opts = ScanOptions {
        repo_path: path,
        diff_base,
        profile,
        report,
        sarif,
        cyclonedx,
        fail_on,
        gates,
        max_modules,
        poc,
        poc_image,
        save,
        cross_check_top,
        dual_finder_top,
        fail_on_needs_human,
        no_prior,
        rank: rank_strategy,
        trace,
        source_receipts,
        attack_classes: attack_classes.unwrap_or_default(),
        time_budget: budget.total,
        refuter_runs,
        finder_parse_retries: finder_parse_retries as usize,
        verifier_parse_retries: verifier_parse_retries as usize,
        refuter_policy,
        refuter_score,
        refuter_score_threshold,
        prescreen,
        role_caps: budget.caps,
        fix_test_command,
        finders,
        verifiers,
        poc_models,
        roster,
    };
    audit::cmd_scan_with(&home_dir(), opts, allow_incomplete).await
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

    let draft_opts = draft_opts.map(|mut o| {
        o.roster = roster.clone();
        o
    });
    let auditor = EngineAuditor {
        home: home_dir(),
        attack_classes: args
            .attack_classes
            .or(cfg.attack_classes)
            .unwrap_or_default(),
        finders,
        verifiers,
        poc_models,
        roster,
        max_modules: args.max_modules,
        poc: args.poc,
        poc_image: args.poc_image.clone(),
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
            let outcome = if !h.facade_of.is_empty() {
                vettalon::tr!(
                    "{outcome}；這是外殼套件，程式碼在 {}（見後續列）",
                    "{outcome}; facade crate, its code is in {} (see below)",
                    h.facade_of.join(", ")
                )
            } else if let Some(from) = &h.promoted_from {
                vettalon::tr!(
                    "{outcome}；{from} 的實作套件",
                    "{outcome}; implementation crate of {from}"
                )
            } else {
                outcome
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

const REMEDIATION_INPUT_MAX_BYTES: u64 = 64 * 1024;

fn remediation_fail(error: impl std::fmt::Display) -> i32 {
    eprintln!("[vettalon] {error}");
    2
}

fn read_regular_capped(path: &Path, cap: u64, label: &str) -> Result<String, String> {
    use std::io::Read;
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|e| format!("cannot inspect {label} {}: {e}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > cap {
        return Err(format!(
            "{label} must be a regular non-symlink file no larger than {cap} bytes"
        ));
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|e| format!("cannot open {label} {}: {e}", path.display()))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    (&mut file)
        .take(cap + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read {label} {}: {e}", path.display()))?;
    if bytes.len() as u64 > cap || file.metadata().map(|m| m.len()).ok() != Some(metadata.len()) {
        return Err(format!("{label} changed while it was read"));
    }
    String::from_utf8(bytes).map_err(|_| format!("{label} must be UTF-8"))
}

fn remediation_context(
    repo: &Path,
    report_path: &Path,
    finding_id: &str,
    target_path: &Path,
) -> Result<
    (
        PathBuf,
        vettalon::audit::schema::AuditReport,
        vettalon::audit::schema::Finding,
        vettalon::audit::target_poc::TargetCall,
    ),
    String,
> {
    let repo = std::fs::canonicalize(repo)
        .map_err(|e| format!("cannot resolve repository {}: {e}", repo.display()))?;
    if !repo.is_dir() {
        return Err("repository path is not a directory".into());
    }
    let report = audit::load_report_for_delivery(report_path)?;
    let reported_repo = std::fs::canonicalize(&report.repo).map_err(|e| {
        format!(
            "cannot resolve the report repository {:?}: {e}; reproduce/fix-check refuses a moved or unavailable tree",
            report.repo
        )
    })?;
    if repo != reported_repo {
        return Err(format!(
            "repository identity mismatch: report names {}, command names {}",
            reported_repo.display(),
            repo.display()
        ));
    }
    let exact: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.id == finding_id)
        .collect();
    let matches = if exact.is_empty() {
        report
            .findings
            .iter()
            .filter(|finding| finding.id.starts_with(finding_id))
            .collect::<Vec<_>>()
    } else {
        exact
    };
    let finding = match matches.as_slice() {
        [finding] => (*finding).clone(),
        [] => return Err(format!("finding {finding_id:?} is not in the report")),
        _ => return Err(format!("finding prefix {finding_id:?} is ambiguous")),
    };
    let target_raw = read_regular_capped(target_path, 8 * 1024, "target call")?;
    let target = vettalon::audit::target_poc::parse_target_call(&target_raw)
        .map_err(|reason| format!("target call refused: {reason}"))?;
    if target.file != finding.file {
        return Err(format!(
            "target file {:?} does not match finding file {:?}",
            target.file, finding.file
        ));
    }
    Ok((repo, report, finding, target))
}

fn encode_remediation_output<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    serde_json::to_vec_pretty(value)
        .map_err(|e| format!("cannot serialize remediation output: {e}"))
}

/// Resolve a brand-new output without following a symlink in its parent
/// chain. Remediation outputs contain source evidence and must never replace
/// an operator-owned file, symlink target or hardlink.
fn preflight_new_output(path: &Path) -> Result<PathBuf, String> {
    use std::path::Component;

    if path.file_name().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(format!(
            "unsafe output path {}; '..' is refused",
            path.display()
        ));
    }
    let raw_absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("cannot resolve current directory: {e}"))?
            .join(path)
    };
    let mut absolute = PathBuf::new();
    for component in raw_absolute.components() {
        if !matches!(component, Component::CurDir) {
            absolute.push(component.as_os_str());
        }
    }
    let parent = absolute
        .parent()
        .ok_or_else(|| format!("output has no parent: {}", path.display()))?;
    let mut cursor = PathBuf::new();
    for component in parent.components() {
        cursor.push(component.as_os_str());
        if matches!(component, Component::CurDir) {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&cursor)
            .map_err(|e| format!("cannot inspect output parent {}: {e}", cursor.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(format!(
                "output parent must be a real directory, not a symlink: {}",
                cursor.display()
            ));
        }
    }
    match std::fs::symlink_metadata(&absolute) {
        Ok(_) => Err(format!(
            "output already exists and will not be replaced: {}",
            absolute.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(absolute),
        Err(error) => Err(format!(
            "cannot inspect output {}: {error}",
            absolute.display()
        )),
    }
}

fn create_new_private_output(path: &Path) -> Result<std::fs::File, String> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options
        .open(path)
        .map_err(|e| format!("cannot create new output {}: {e}", path.display()))
}

fn write_new_remediation_output<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), String> {
    use std::io::Write;

    let encoded = encode_remediation_output(value)?;
    let path = preflight_new_output(path)?;
    let mut file = create_new_private_output(&path)?;
    if let Err(error) = file.write_all(&encoded).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(&path);
        return Err(format!("cannot write output {}: {error}", path.display()));
    }
    Ok(())
}

fn write_new_remediation_pair<A: serde::Serialize, B: serde::Serialize>(
    first_path: &Path,
    first: &A,
    second_path: &Path,
    second: &B,
) -> Result<(), String> {
    use std::io::Write;

    let first_bytes = encode_remediation_output(first)?;
    let second_bytes = encode_remediation_output(second)?;
    let first_path = preflight_new_output(first_path)?;
    let second_path = preflight_new_output(second_path)?;
    if first_path == second_path {
        return Err("--out and --report-out must be different paths".into());
    }
    let mut first_file = create_new_private_output(&first_path)?;
    let mut second_file = match create_new_private_output(&second_path) {
        Ok(file) => file,
        Err(error) => {
            drop(first_file);
            let _ = std::fs::remove_file(&first_path);
            return Err(error);
        }
    };
    let write_result = first_file
        .write_all(&first_bytes)
        .and_then(|()| first_file.sync_all())
        .and_then(|()| second_file.write_all(&second_bytes))
        .and_then(|()| second_file.sync_all());
    if let Err(error) = write_result {
        drop(first_file);
        drop(second_file);
        let _ = std::fs::remove_file(&first_path);
        let _ = std::fs::remove_file(&second_path);
        return Err(format!("cannot write remediation outputs: {error}"));
    }
    Ok(())
}

#[cfg(test)]
mod remediation_output_tests {
    use super::*;

    fn real_tempdir(prefix: &str) -> tempfile::TempDir {
        let root = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        tempfile::Builder::new()
            .prefix(prefix)
            .tempdir_in(root)
            .unwrap()
    }

    #[test]
    fn remediation_output_is_new_private_and_never_follows_existing_links() {
        let dir = real_tempdir("vettalon-remediation-output-");
        let fresh = dir.path().join("fresh.json");
        write_new_remediation_output(&fresh, &serde_json::json!({"ok": true})).unwrap();
        assert!(std::fs::read_to_string(&fresh).unwrap().contains("true"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let victim = dir.path().join("victim.txt");
        std::fs::write(&victim, "preserve").unwrap();
        assert!(write_new_remediation_output(&victim, &0).is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "preserve");

        #[cfg(unix)]
        {
            let symlink = dir.path().join("receipt-symlink.json");
            std::os::unix::fs::symlink(&victim, &symlink).unwrap();
            assert!(write_new_remediation_output(&symlink, &1).is_err());
            assert_eq!(std::fs::read_to_string(&victim).unwrap(), "preserve");

            let hardlink = dir.path().join("receipt-hardlink.json");
            std::fs::hard_link(&victim, &hardlink).unwrap();
            assert!(write_new_remediation_output(&hardlink, &2).is_err());
            assert_eq!(std::fs::read_to_string(&victim).unwrap(), "preserve");

            let real_parent = dir.path().join("real-parent");
            std::fs::create_dir(&real_parent).unwrap();
            let linked_parent = dir.path().join("linked-parent");
            std::os::unix::fs::symlink(&real_parent, &linked_parent).unwrap();
            assert!(write_new_remediation_output(&linked_parent.join("receipt.json"), &3).is_err());
            assert!(!real_parent.join("receipt.json").exists());
        }
    }

    #[test]
    fn paired_outputs_preflight_both_and_leave_no_partial_first_file() {
        let dir = real_tempdir("vettalon-remediation-pair-");
        let first = dir.path().join("receipt.json");
        let existing_second = dir.path().join("report.json");
        std::fs::write(&existing_second, "preserve").unwrap();
        assert!(write_new_remediation_pair(&first, &1, &existing_second, &2).is_err());
        assert!(!first.exists());
        assert_eq!(
            std::fs::read_to_string(&existing_second).unwrap(),
            "preserve"
        );

        let same = dir.path().join("same.json");
        assert!(
            write_new_remediation_pair(&same, &1, &dir.path().join("./same.json"), &2).is_err()
        );
        assert!(!same.exists());
    }

    #[tokio::test]
    #[ignore = "requires a Docker daemon + python:3.12-slim present locally"]
    async fn live_fix_cli_writes_a_bound_validator_clean_report_without_touching_source() {
        use vettalon::audit::schema::*;
        use vettalon::audit::target_poc::{TargetArgument, TargetCall};

        let dir = real_tempdir("vettalon-fix-cli-");
        let repo = dir.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        let source = "import os\n\ndef run(cmd):\n    os.system('echo ' + cmd)\n";
        std::fs::write(repo.join("app.py"), source).unwrap();
        let mut finding = Finding::candidate(
            "ai_audit",
            FindingKind::Other,
            Severity::High,
            "command injection",
            "app.py",
            Some(4),
            source,
            "ai-audit/command_injection",
            vec![],
        );
        finding.cwe = Some("CWE-78".into());
        finding.file_hash = Some(sha256_hex(source.as_bytes()));
        let finding_id = finding.id.clone();
        let findings = vec![finding];
        let report = AuditReport {
            schema_version: 2,
            scope: None,
            repo: std::fs::canonicalize(&repo)
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            started_at: "2026-10-24T00:00:00Z".into(),
            profile: ScanProfile {
                mode: ProfileMode::Deep,
                intake: None,
            },
            engines_run: vec![],
            engines_missing: vec![],
            summary: Summary::from_findings(&findings, 0, 0, GatePolicy::default(), &[]),
            findings,
            run_status: vettalon_contract::coverage::RunStatus::Complete,
            incomplete_reason: None,
            coverage: vec![],
            prior_run: None,
            verifier: VerifierInfo::default(),
            ensemble: Default::default(),
        };
        let validation = audit::validation_errors(&report);
        assert!(validation.is_empty(), "{validation:?}");
        let report_path = dir.path().join("report.json");
        std::fs::write(&report_path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
        let target_path = dir.path().join("target.json");
        std::fs::write(
            &target_path,
            serde_json::to_vec(&TargetCall {
                file: "app.py".into(),
                function: "run".into(),
                args: vec![TargetArgument::Payload],
            })
            .unwrap(),
        )
        .unwrap();
        let diff_path = dir.path().join("fix.patch");
        std::fs::write(
            &diff_path,
            "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -3,2 +3,2 @@\n def run(cmd):\n-    os.system('echo ' + cmd)\n+    os.system('echo ' + __import__('shlex').quote(cmd))\n",
        )
        .unwrap();
        let receipt_path = dir.path().join("fix-receipt.json");
        let updated_path = dir.path().join("updated-report.json");
        let before = std::fs::read(repo.join("app.py")).unwrap();
        let code = cmd_fix_check(FixCheckArgs {
            path: repo.clone(),
            report: report_path,
            finding: finding_id.clone(),
            target: target_path,
            diff: Some(diff_path),
            test_command: Some("true".into()),
            poc_image: vettalon::sandbox::DEFAULT_POC_IMAGE.into(),
            out: receipt_path.clone(),
            report_out: updated_path.clone(),
        })
        .await;
        assert_eq!(code, 0);
        assert_eq!(std::fs::read(repo.join("app.py")).unwrap(), before);
        let receipt: serde_json::Value =
            serde_json::from_slice(&std::fs::read(receipt_path).unwrap()).unwrap();
        assert_eq!(receipt["outcome"], "fix_verified");
        let updated = audit::load_report_for_delivery(&updated_path).unwrap();
        let finding = updated
            .findings
            .iter()
            .find(|finding| finding.id == finding_id)
            .unwrap();
        assert_eq!(finding.status, FindingStatus::Candidate);
        assert_eq!(
            finding.fix_check().unwrap().outcome,
            audit::fix_check::FixOutcome::FixVerified
        );
        assert!(finding.fix_check().unwrap().binding.is_some());
    }
}

#[cfg(test)]
mod verification_cli_tests {
    use super::*;

    use vettalon::audit::verification::{CompileInput, HostObservations, VerificationEvent};
    use vettalon_contract::verification::{
        BackendKind, CleanupState, CounterexampleKind, DataRights, ENGINEERING_MEASUREMENT_SCHEMA,
        EVALUATION_CASE_SCHEMA, EngineeringMeasurement, EvaluationCase, EvaluationSplit, Language,
        ReplayGrade, ReplayOutcome, SupportOutcome,
    };

    fn hash(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn event_fixture() -> VerificationEvent {
        let ir = vettalon::audit::verification::compile_ir(&CompileInput {
            finding_id: "finding-1".into(),
            file: "app.py".into(),
            line: Some(7),
            symbol: "run".into(),
            cwe: "CWE-78".into(),
            source_sha256: hash('a'),
            target_file_sha256: hash('b'),
            target_plan_sha256: hash('c'),
            harness_sha256: hash('d'),
        })
        .unwrap();
        VerificationEvent::from_host_observations(
            ir,
            HostObservations {
                backend_kind: BackendKind::Docker,
                backend_identity: format!("sha256:{}", hash('e')),
                platform: "linux/arm64".into(),
                challenge_commitment: hash('f'),
                capture_complete: true,
                cleanup: CleanupState::Confirmed,
                tampering: Vec::new(),
                effect_observed: Some(true),
                benign_control: Some(true),
                fresh_challenge_control: Some(true),
                exit_code: Some(0),
                transcript_sha256: Some(hash('1')),
                replay_grade: ReplayGrade::Exact,
            },
        )
        .unwrap()
    }

    #[test]
    fn attack_classes_cli_scan_and_hunt_modes() {
        use audit::attack_classes::AttackClassMode;
        for command in ["scan", "hunt"] {
            for (value, expected) in [
                ("off", AttackClassMode::Off),
                ("auto", AttackClassMode::Auto),
                ("all", AttackClassMode::All),
            ] {
                let cli =
                    Cli::try_parse_from(["vettalon", command, ".", "--attack-classes", value])
                        .unwrap();
                let actual = match cli.command {
                    Command::Scan(a) => a.attack_classes,
                    Command::Hunt(a) => a.attack_classes,
                    _ => panic!("command"),
                };
                assert_eq!(actual, Some(expected));
            }
            let cli = Cli::try_parse_from(["vettalon", command, "."]).unwrap();
            let actual = match cli.command {
                Command::Scan(a) => a.attack_classes,
                Command::Hunt(a) => a.attack_classes,
                _ => panic!("command"),
            };
            assert_eq!(actual, None);
            assert!(
                Cli::try_parse_from(["vettalon", command, ".", "--attack-classes", "unknown"])
                    .is_err()
            );
        }
    }

    #[test]
    fn verification_commands_have_closed_explicit_inputs() {
        let cli = Cli::try_parse_from([
            "vettalon",
            "verification",
            "validate",
            "--event",
            "event.json",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Verification {
                action: VerificationAction::Validate { .. }
            }
        ));

        let cli = Cli::try_parse_from([
            "vettalon",
            "verification",
            "scorecard",
            "--measurements",
            "measurements.json",
            "--out",
            "scorecard.json",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Verification {
                action: VerificationAction::Scorecard { .. }
            }
        ));

        let cli = Cli::try_parse_from([
            "vettalon",
            "verification",
            "registry",
            "add-cell",
            "--registry",
            "registry",
            "--cell",
            "cell.json",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Verification {
                action: VerificationAction::Registry {
                    action: VerificationRegistryAction::AddCell { .. }
                }
            }
        ));

        let cli = Cli::try_parse_from([
            "vettalon",
            "verification",
            "compare",
            "--ir",
            "ir.json",
            "--first",
            "a.json",
            "--second",
            "b.json",
            "--out",
            "result.json",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Verification {
                action: VerificationAction::Compare { .. }
            }
        ));

        let cli = Cli::try_parse_from([
            "vettalon",
            "verification",
            "registry",
            "access",
            "--registry",
            "registry",
            "--case",
            "hidden-1",
            "--purpose",
            "development",
            "--actor",
            "builder",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Verification {
                action: VerificationAction::Registry {
                    action: VerificationRegistryAction::Access { .. }
                }
            }
        ));

        assert!(
            Cli::try_parse_from([
                "vettalon",
                "verification",
                "registry",
                "access",
                "--registry",
                "registry",
                "--case",
                "hidden-1",
                "--purpose",
                "train",
                "--actor",
                "builder",
            ])
            .is_err()
        );
    }

    #[test]
    fn verification_commands_validate_compare_and_track_holdout_contamination() {
        let temp_root = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let temp = tempfile::Builder::new()
            .prefix("vettalon-verification-cli-")
            .tempdir_in(temp_root)
            .unwrap();
        let event = event_fixture();
        let event_path = temp.path().join("event.json");
        std::fs::write(&event_path, serde_json::to_vec_pretty(&event).unwrap()).unwrap();
        assert_eq!(
            cmd_verification(VerificationAction::Validate { event: event_path }),
            0
        );

        let ir_path = temp.path().join("ir.json");
        let first_path = temp.path().join("first.json");
        let second_path = temp.path().join("second.json");
        std::fs::write(&ir_path, serde_json::to_vec_pretty(&event.ir).unwrap()).unwrap();
        std::fs::write(
            &first_path,
            serde_json::to_vec_pretty(&event.envelope).unwrap(),
        )
        .unwrap();
        std::fs::write(
            &second_path,
            serde_json::to_vec_pretty(&event.envelope).unwrap(),
        )
        .unwrap();
        let comparison_path = temp.path().join("comparison.json");
        assert_eq!(
            cmd_verification(VerificationAction::Compare {
                ir: ir_path,
                first: first_path,
                second: second_path,
                out: comparison_path.clone(),
            }),
            0
        );
        assert!(comparison_path.is_file());

        let mut incomplete = event.envelope.clone();
        incomplete.cleanup = CleanupState::Unknown;
        let incomplete_path = temp.path().join("incomplete.json");
        std::fs::write(
            &incomplete_path,
            serde_json::to_vec_pretty(&incomplete).unwrap(),
        )
        .unwrap();
        assert_eq!(
            cmd_verification(VerificationAction::Compare {
                ir: temp.path().join("ir.json"),
                first: incomplete_path.clone(),
                second: incomplete_path,
                out: temp.path().join("incomplete-comparison.json"),
            }),
            4
        );

        let measurements = vec![EngineeringMeasurement {
            schema: ENGINEERING_MEASUREMENT_SCHEMA.into(),
            measurement_id: "m-1".into(),
            cohort: "day-30".into(),
            project: "repo-a".into(),
            effect: "command_execution".into(),
            language: Language::Python,
            framework: "stdlib".into(),
            verifier_engineering_minutes: 60,
            manual_trusted_loc: 100,
            support: SupportOutcome::Supported,
            prospective: true,
            false_proof: false,
            replay: ReplayOutcome::Equivalent,
            tamper_attempt: true,
            positive_forgery: false,
            state_leak: false,
            cleanup_residue: false,
            build_ms: 10,
            execution_ms: 20,
            capture_ms: 30,
            cleanup_ms: 40,
            human_minutes: 5,
            direct_cost_microunits: 1_000,
            currency: "USD".into(),
        }];
        let measurements_path = temp.path().join("measurements.json");
        std::fs::write(
            &measurements_path,
            serde_json::to_vec_pretty(&measurements).unwrap(),
        )
        .unwrap();
        let scorecard_path = temp.path().join("scorecard.json");
        assert_eq!(
            cmd_verification(VerificationAction::Scorecard {
                measurements: measurements_path,
                out: scorecard_path.clone(),
            }),
            0
        );
        let scorecard: vettalon::audit::verification::EngineeringScorecard =
            serde_json::from_slice(&std::fs::read(scorecard_path).unwrap()).unwrap();
        assert_eq!(scorecard.roster_total, 1);
        assert_eq!(scorecard.conclusive_proofs, 1);

        let registry = temp.path().join("registry");
        let case_path = temp.path().join("case.json");
        let case = EvaluationCase {
            schema: EVALUATION_CASE_SCHEMA.into(),
            case_id: "holdout-1".into(),
            content_sha256: hash('9'),
            declared_split: EvaluationSplit::SealedHoldout,
            rights: DataRights::ServiceOnly,
            parents: Vec::new(),
        };
        std::fs::write(&case_path, serde_json::to_vec_pretty(&case).unwrap()).unwrap();
        assert_eq!(
            cmd_verification(VerificationAction::Registry {
                action: VerificationRegistryAction::Add {
                    registry: registry.clone(),
                    case_path,
                },
            }),
            0
        );
        let mut replay_envelope = event.envelope.clone();
        replay_envelope.challenge_commitment = hash('2');
        replay_envelope.transcript_sha256 = Some(hash('2'));
        let replay_event =
            VerificationEvent::new(event.ir.clone(), replay_envelope, None, None).unwrap();
        let cell = vettalon::audit::verification::promote_counterexample(
            &[event.clone(), replay_event],
            "false-proof-1",
            CounterexampleKind::FalseProof,
            &hash('7'),
            &hash('8'),
            EvaluationSplit::Development,
            DataRights::ServiceOnly,
            Vec::new(),
        )
        .unwrap();
        let cell_path = temp.path().join("cell.json");
        std::fs::write(&cell_path, serde_json::to_vec_pretty(&cell).unwrap()).unwrap();
        assert_eq!(
            cmd_verification(VerificationAction::Registry {
                action: VerificationRegistryAction::AddCell {
                    registry: registry.clone(),
                    cell_path,
                },
            }),
            0
        );
        assert_eq!(
            vettalon::audit::verification::RegistryStore::open(&registry)
                .unwrap()
                .load_counterexamples()
                .unwrap(),
            vec![cell]
        );
        assert_eq!(
            cmd_verification(VerificationAction::Registry {
                action: VerificationRegistryAction::Access {
                    registry: registry.clone(),
                    case_id: "holdout-1".into(),
                    purpose: "development".into(),
                    actor: "builder".into(),
                },
            }),
            0
        );
        let audit_path = temp.path().join("audit.json");
        assert_eq!(
            cmd_verification(VerificationAction::Registry {
                action: VerificationRegistryAction::Audit {
                    registry,
                    case_id: "holdout-1".into(),
                    out: audit_path.clone(),
                },
            }),
            1
        );
        let audit: vettalon::audit::verification::CaseAudit =
            serde_json::from_slice(&std::fs::read(audit_path).unwrap()).unwrap();
        assert!(audit.compromised);
        assert_eq!(audit.effective_split, EvaluationSplit::Development);
    }
}

async fn cmd_reproduce(args: ReproduceArgs) -> i32 {
    let (repo, _report, finding, target) =
        match remediation_context(&args.path, &args.report, &args.finding, &args.target) {
            Ok(value) => value,
            Err(error) => return remediation_fail(error),
        };
    let receipt =
        audit::target_poc::run_target_poc(&repo, &finding, &target, &args.poc_image).await;
    if let Err(error) = write_new_remediation_output(&args.out, &receipt) {
        return remediation_fail(error);
    }
    eprintln!(
        "[vettalon] target PoC: {:?}; status unchanged; receipt={}",
        receipt.outcome,
        args.out.display()
    );
    match receipt.outcome {
        audit::target_poc::TargetPocOutcome::EffectObserved => 0,
        audit::target_poc::TargetPocOutcome::EffectAbsent => 1,
        audit::target_poc::TargetPocOutcome::Inconclusive => 2,
    }
}

async fn cmd_fix_check(args: FixCheckArgs) -> i32 {
    let (repo, mut report, finding, target) =
        match remediation_context(&args.path, &args.report, &args.finding, &args.target) {
            Ok(value) => value,
            Err(error) => return remediation_fail(error),
        };
    if let Some(command) = args.test_command.as_deref()
        && let Err(error) = audit::fix_check::validate_test_command(command)
    {
        return remediation_fail(format!("test command refused: {error}"));
    }
    let diff = match args.diff.as_deref() {
        Some(path) => match read_regular_capped(path, REMEDIATION_INPUT_MAX_BYTES, "fix diff") {
            Ok(diff) => diff,
            Err(error) => return remediation_fail(error),
        },
        None => match finding.suggested_fix.clone() {
            Some(diff) => diff,
            None => return remediation_fail("the finding has no suggested fix; pass --diff"),
        },
    };
    if let Err(reason) = audit::validate_fix_diff(&diff) {
        return remediation_fail(format!("fix diff refused: {reason}"));
    }
    let run = audit::fix_check::run_target_fix(
        &repo,
        &finding,
        &target,
        &diff,
        args.test_command.as_deref(),
        &args.poc_image,
    )
    .await;
    let Some(updated_finding) = report
        .findings
        .iter_mut()
        .find(|candidate| candidate.id == finding.id)
    else {
        return remediation_fail("selected finding disappeared from the report");
    };
    updated_finding.suggested_fix = Some(diff);
    audit::fix_check::record_fix_run(updated_finding, &run);
    if let Some(error) = audit::validation_errors(&report).first() {
        return remediation_fail(format!("updated report is invalid: {error}"));
    }
    if let Err(error) = write_new_remediation_pair(&args.out, &run, &args.report_out, &report) {
        return remediation_fail(error);
    }
    eprintln!(
        "[vettalon] fix check: {}; live tree unchanged; receipt={}; report={}",
        run.outcome().key(),
        args.out.display(),
        args.report_out.display()
    );
    usize::from(run.outcome() != audit::fix_check::FixOutcome::FixVerified) as i32
}

const VERIFICATION_INPUT_MAX_BYTES: u64 = 128 * 1024;
const REPLAY_COMPARISON_SCHEMA: &str = "vettalon.replay-comparison/1";

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayComparisonReceipt {
    schema: String,
    verification_ir_sha256: String,
    first_envelope_sha256: String,
    second_envelope_sha256: String,
    comparison: vettalon_contract::verification::ReplayComparison,
}

fn read_verification_json<T: serde::de::DeserializeOwned>(
    path: &Path,
    label: &str,
) -> Result<T, String> {
    let raw = read_regular_capped(path, VERIFICATION_INPUT_MAX_BYTES, label)?;
    vettalon_contract::strict_json::parse_strict_with_limit(
        &raw,
        VERIFICATION_INPUT_MAX_BYTES as usize,
    )
    .map_err(|error| format!("invalid {label} {}: {error:?}", path.display()))
}

fn verification_store(path: &Path) -> Result<audit::verification::RegistryStore, String> {
    audit::verification::RegistryStore::open(path)
        .map_err(|reason| format!("cannot open registry {}: {reason}", path.display()))
}

fn cmd_verification(action: VerificationAction) -> i32 {
    use vettalon_contract::verification::{
        AccessPurpose, EvaluationCase, ExecutionEnvelope, ReplayComparison, VerificationIr,
        compare_replay,
    };

    let result: Result<i32, String> = (|| match action {
        VerificationAction::Validate { event } => {
            let event: audit::verification::VerificationEvent =
                read_verification_json(&event, "verification event")?;
            event
                .validate()
                .map_err(|reason| format!("verification event refused: {reason}"))?;
            let identity = event
                .identity_sha256()
                .map_err(|reason| format!("verification event refused: {reason}"))?;
            println!(
                "verification_event_sha256={identity} verdict={:?}",
                event.decision.verdict
            );
            Ok(0)
        }
        VerificationAction::Compare {
            ir,
            first,
            second,
            out,
        } => {
            let ir: VerificationIr = read_verification_json(&ir, "verification IR")?;
            let first: ExecutionEnvelope =
                read_verification_json(&first, "first execution envelope")?;
            let second: ExecutionEnvelope =
                read_verification_json(&second, "second execution envelope")?;
            let comparison = compare_replay(&ir, &first, &second)
                .map_err(|error| format!("replay comparison refused: {error:?}"))?;
            let receipt = ReplayComparisonReceipt {
                schema: REPLAY_COMPARISON_SCHEMA.into(),
                verification_ir_sha256: ir
                    .identity_sha256()
                    .map_err(|error| format!("invalid verification IR: {error:?}"))?,
                first_envelope_sha256: audit::schema::sha256_hex(
                    &serde_json::to_vec(&first)
                        .map_err(|error| format!("cannot encode first envelope: {error}"))?,
                ),
                second_envelope_sha256: audit::schema::sha256_hex(
                    &serde_json::to_vec(&second)
                        .map_err(|error| format!("cannot encode second envelope: {error}"))?,
                ),
                comparison,
            };
            write_new_remediation_output(&out, &receipt)?;
            println!(
                "comparison={:?} receipt={}",
                receipt.comparison,
                out.display()
            );
            Ok(match comparison {
                ReplayComparison::Equivalent => 0,
                ReplayComparison::Diverged => 1,
                ReplayComparison::Inconclusive => 4,
            })
        }
        VerificationAction::Scorecard { measurements, out } => {
            let measurements: Vec<vettalon_contract::verification::EngineeringMeasurement> =
                read_verification_json(&measurements, "engineering measurements")?;
            let scorecard = audit::verification::build_scorecard(&measurements)
                .map_err(|reason| format!("scorecard refused: {reason}"))?;
            write_new_remediation_output(&out, &scorecard)?;
            println!(
                "samples={} conclusive_proofs={} receipt={}",
                scorecard.roster_total,
                scorecard.conclusive_proofs,
                out.display()
            );
            Ok(0)
        }
        VerificationAction::Registry { action } => match action {
            VerificationRegistryAction::Add {
                registry,
                case_path,
            } => {
                let case: EvaluationCase = read_verification_json(&case_path, "evaluation case")?;
                verification_store(&registry)?
                    .add_case(&case)
                    .map_err(|reason| format!("evaluation case refused: {reason}"))?;
                println!("case={} registry={}", case.case_id, registry.display());
                Ok(0)
            }
            VerificationRegistryAction::AddCell {
                registry,
                cell_path,
            } => {
                let cell: vettalon_contract::verification::CounterexampleCell =
                    read_verification_json(&cell_path, "counterexample cell")?;
                verification_store(&registry)?
                    .add_counterexample(&cell)
                    .map_err(|reason| format!("counterexample cell refused: {reason}"))?;
                println!("cell={} registry={}", cell.cell_id, registry.display());
                Ok(0)
            }
            VerificationRegistryAction::Access {
                registry,
                case_id,
                purpose,
                actor,
            } => {
                let purpose = match purpose.as_str() {
                    "development" => AccessPurpose::Development,
                    "evaluation" => AccessPurpose::Evaluation,
                    "audit" => AccessPurpose::Audit,
                    _ => return Err("invalid registry access purpose".into()),
                };
                verification_store(&registry)?
                    .record_access(&case_id, purpose, &actor)
                    .map_err(|reason| format!("registry access refused: {reason}"))?;
                println!("case={case_id} purpose={purpose:?} actor={actor}");
                Ok(0)
            }
            VerificationRegistryAction::Audit {
                registry,
                case_id,
                out,
            } => {
                let audit = verification_store(&registry)?
                    .audit_case(&case_id)
                    .map_err(|reason| format!("registry audit refused: {reason}"))?;
                write_new_remediation_output(&out, &audit)?;
                println!(
                    "case={case_id} effective_split={:?} compromised={} receipt={}",
                    audit.effective_split,
                    audit.compromised,
                    out.display()
                );
                Ok(i32::from(audit.compromised))
            }
        },
    })();

    match result {
        Ok(code) => code,
        Err(error) => remediation_fail(error),
    }
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
        Command::Explain { code, list } => vettalon::explain::run(code.as_deref(), list),
        Command::Scan(args) => cmd_scan(args).await,
        Command::Validate { report } => audit::cmd_validate(&report).await,
        Command::Verify(args) => cmd_verify(args).await,
        Command::Reproduce(args) => cmd_reproduce(args).await,
        Command::Fix {
            action: FixAction::Check(args),
        } => cmd_fix_check(args).await,
        Command::Verification { action } => cmd_verification(action),
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
        Command::Joern { action } => cmd_joern(action).await,
        Command::Agents { action } => {
            let r = match action {
                AgentsAction::Build => vettalon::llm::container::build_images().await,
                AgentsAction::Pull { no_verify } => {
                    vettalon::llm::container::pull_images(!no_verify).await
                }
                AgentsAction::Stop => vettalon::llm::container::teardown().await,
                AgentsAction::Images => {
                    // Machine-readable: tags only, no "Done" line. The
                    // first two are what scans run; the third is the
                    // published base the agents image is built on.
                    println!("{}", vettalon::llm::container::agents_image());
                    println!("{}", vettalon::llm::container::egress_image());
                    println!("{}", vettalon::llm::container::agents_base_image());
                    return ExitCode::SUCCESS;
                }
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
