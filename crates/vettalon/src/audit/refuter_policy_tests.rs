//! Tests for `refuter_policy`: the policy flag, the I1 citation checks and
//! verdict mapping, the I2 prosecutor's blindness and veto, I3 retrieval,
//! and the I0 basis line. No model is called (scripted replies).

use super::*;
use crate::audit::adversarial::{ReviewOutcome, ReviewPlan, review_with};
use crate::audit::schema::{FindingKind, Severity, TraceKind};
use crate::llm::LlmCaller;

// ── helpers ──────────────────────────────────────────────────────────

struct Scripted {
    replies: std::sync::Mutex<std::collections::VecDeque<String>>,
    prompts: std::sync::Mutex<Vec<String>>,
}

impl Scripted {
    fn new(replies: &[&str]) -> Self {
        Scripted {
            replies: std::sync::Mutex::new(replies.iter().map(|s| s.to_string()).collect()),
            prompts: std::sync::Mutex::new(Vec::new()),
        }
    }
    fn prompts(&self) -> Vec<String> {
        self.prompts.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl LlmCaller for Scripted {
    async fn complete(&self, prompt: &str) -> crate::llm::Result<String> {
        self.prompts.lock().unwrap().push(prompt.to_string());
        self.replies
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| crate::llm::LlmError::Executor("no reply queued".into()))
    }
}

/// `app/views.py`: request value through a partial filter into a raw query.
fn repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("app")).unwrap();
    std::fs::write(
        dir.path().join("app/views.py"),
        "import db\n\
         # sanitize the name\n\
         def show(request):\n\
         \x20   name = request.GET['name']\n\
         \x20   name = clean_name(name)\n\
         \n\
         \x20   return db.raw(\"SELECT * FROM t WHERE n = '%s'\" % name)\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("app/util.py"),
        "import re\n\ndef clean_name(v):\n    return v.replace(\"'\", \"\")\n",
    )
    .unwrap();
    dir
}

fn finding(engine: &str) -> Finding {
    let mut f = Finding::candidate(
        engine,
        FindingKind::StaticAnalysis,
        Severity::Medium,
        "CWE-89 SQL injection",
        "app/views.py",
        Some(7),
        "",
        "external/CWE-89",
        vec![],
    );
    f.trace = vec![TraceStep {
        kind: TraceKind::Propagation,
        file: "app/views.py".into(),
        line: 4,
        scope: "show".into(),
        description: String::new(),
    }];
    f
}

fn plan(policy: &str) -> ReviewPlan {
    ReviewPlan {
        runs: 1,
        deadline: None,
        parse_retries: 1,
        policy: RefuterPolicy::parse(policy).unwrap(),
        score: false,
        score_threshold: None,
    }
}

fn shown_views() -> Shown {
    let mut s = Shown::default();
    s.add("app/views.py", 1, 7);
    s
}

fn refuted(basis: &str, evidence: &str, extra: &str) -> String {
    format!(
        r#"{{"verdict":"refuted","reason":"ZZ-REFUTER-REASON","blockers":[],"validation_plan":{{"local":null,"deployment":null}},"refute_basis":"{basis}","evidence":{evidence}{extra}}}"#
    )
}

const UNRESOLVED: &str = r#"{"verdict":"unresolved","reason":"ZZ-UNSEEN","blockers":["what clean_name does"],"validation_plan":{"local":null,"deployment":null},"missing_code":["clean_name"]}"#;
const PLAUSIBLE: &str = r#"{"verdict":"plausible","reason":"raw query","blockers":["is it reachable?"],"validation_plan":{"local":"run it","deployment":null}}"#;

fn details(f: &Finding) -> Vec<String> {
    f.evidence.iter().map(|e| e.detail.clone()).collect()
}

// ── policy flag ──────────────────────────────────────────────────────

#[test]
fn policy_parses_and_labels() {
    assert_eq!(
        RefuterPolicy::parse("current").unwrap(),
        RefuterPolicy::CURRENT
    );
    assert_eq!(RefuterPolicy::default(), RefuterPolicy::CURRENT);
    for s in [
        "evidence",
        "evidence-ext",
        "evidence+prosecutor",
        "evidence+retrieval",
        "evidence-ext+prosecutor+retrieval",
        "prosecutor",
    ] {
        assert_eq!(RefuterPolicy::parse(s).unwrap().label(), s, "{s}");
    }
    assert_eq!(
        RefuterPolicy::parse(" Evidence + Prosecutor ")
            .unwrap()
            .label(),
        "evidence+prosecutor"
    );
    for bad in [
        "",
        "retrieval",
        "prosecutor+retrieval",
        "evidence+evidence-ext",
        "evidence+evidence",
        "current+evidence",
        "strict",
    ] {
        assert!(
            RefuterPolicy::parse(bad).is_err(),
            "{bad:?} must be rejected"
        );
    }
}

#[test]
fn evidence_ext_applies_only_to_external_scanner_claims() {
    let ext = RefuterPolicy::parse("evidence-ext").unwrap();
    assert!(ext.evidence_applies(&finding(EXTERNAL_ENGINE)));
    assert!(!ext.evidence_applies(&finding("ai_audit")));
    let all = RefuterPolicy::parse("evidence").unwrap();
    assert!(all.evidence_applies(&finding("ai_audit")));
    assert!(!RefuterPolicy::CURRENT.evidence_applies(&finding(EXTERNAL_ENGINE)));
}

// ── I1 checks and verdict mapping ────────────────────────────────────

#[test]
fn refutation_with_checked_code_lines_is_applied() {
    let dir = repo();
    let raw = refuted(
        "not_attacker_controlled",
        r#"[{"file":"app/views.py","line":4,"shows":"value source"}]"#,
        "",
    );
    let (run, basis) = judge_evidence(dir.path(), &finding(EXTERNAL_ENGINE), &raw, &shown_views());
    assert!(matches!(run, RunVerdict::Refuted { .. }), "{run:?}");
    let b = basis.unwrap();
    assert_eq!(b.basis, "not_attacker_controlled");
    assert_eq!(b.cited, vec![("app/views.py".to_string(), 4)]);
}

fn downgraded(raw: &str) -> String {
    let dir = repo();
    let (run, basis) = judge_evidence(dir.path(), &finding(EXTERNAL_ENGINE), raw, &shown_views());
    assert!(basis.is_some(), "a refutation always leaves a basis record");
    match run {
        RunVerdict::Unresolved(u) => u.downgraded.expect("downgraded"),
        other => panic!("expected a downgrade, got {other:?}"),
    }
}

#[test]
fn failed_citation_checks_downgrade_to_unresolved() {
    // Outside the excerpts shown (line 9 does not exist; util.py not shown).
    assert!(
        downgraded(&refuted(
            "unreachable",
            r#"[{"file":"app/util.py","line":4,"shows":"x"}]"#,
            ""
        ))
        .contains("not in the excerpts shown")
    );
    // A comment line is not evidence.
    assert!(
        downgraded(&refuted(
            "not_dangerous",
            r#"[{"file":"app/views.py","line":2,"shows":"comment"}]"#,
            ""
        ))
        .contains("blank or only a comment")
    );
    // A blank line is not evidence either.
    assert!(
        downgraded(&refuted(
            "not_dangerous",
            r#"[{"file":"app/views.py","line":6,"shows":"blank"}]"#,
            ""
        ))
        .contains("blank or only a comment")
    );
    // No evidence at all.
    assert!(downgraded(&refuted("unreachable", "null", "")).contains("no evidence"));
    assert!(downgraded(&refuted("unreachable", "[]", "")).contains("no evidence"));
    // Unsafe path.
    assert!(
        downgraded(&refuted(
            "unreachable",
            r#"[{"file":"../etc/passwd","line":1,"shows":"x"}]"#,
            ""
        ))
        .contains("unsafe path")
    );
}

#[test]
fn guarded_needs_an_on_trace_guard_and_covers() {
    let ev = r#"[{"file":"app/views.py","line":5,"shows":"filter"}]"#;
    let no_guard = downgraded(&refuted("guarded", ev, ""));
    assert!(no_guard.contains("without a guard location"), "{no_guard}");
    let no_covers = downgraded(&refuted(
        "guarded",
        ev,
        r#","guard":{"file":"app/views.py","line":5}"#,
    ));
    assert!(no_covers.contains("without covers"), "{no_covers}");
    let ok = refuted(
        "guarded",
        ev,
        r#","guard":{"file":"app/views.py","line":5},"covers":"all quotes removed on the only path""#,
    );
    let dir = repo();
    let (run, _) = judge_evidence(dir.path(), &finding(EXTERNAL_ENGINE), &ok, &shown_views());
    assert!(matches!(run, RunVerdict::Refuted { .. }), "{run:?}");
}

#[test]
fn defect_absent_must_cite_the_claimed_file() {
    let mut shown = shown_views();
    shown.add("app/util.py", 1, 4);
    let dir = repo();
    let raw = refuted(
        "defect_absent",
        r#"[{"file":"app/util.py","line":4,"shows":"x"}]"#,
        "",
    );
    let (run, _) = judge_evidence(dir.path(), &finding(EXTERNAL_ENGINE), &raw, &shown);
    match run {
        RunVerdict::Unresolved(u) => assert!(u.downgraded.unwrap().contains("claimed file")),
        other => panic!("{other:?}"),
    }
}

#[test]
fn unresolved_needs_blockers_and_keeps_clean_symbols() {
    let dir = repo();
    let f = finding(EXTERNAL_ENGINE);
    let (run, basis) = judge_evidence(dir.path(), &f, UNRESOLVED, &shown_views());
    assert!(basis.is_none());
    match run {
        RunVerdict::Unresolved(u) => {
            assert!(u.downgraded.is_none());
            assert_eq!(u.missing_code, vec!["clean_name".to_string()]);
            assert_eq!(u.blockers, vec!["what clean_name does".to_string()]);
        }
        other => panic!("{other:?}"),
    }
    let empty = UNRESOLVED.replace(r#"["what clean_name does"]"#, "[]");
    assert!(matches!(
        judge_evidence(dir.path(), &f, &empty, &shown_views()).0,
        RunVerdict::Malformed(_)
    ));
    let with_basis = UNRESOLVED.replace(
        r#""missing_code""#,
        r#""refute_basis":"unreachable","missing_code""#,
    );
    assert!(matches!(
        judge_evidence(dir.path(), &f, &with_basis, &shown_views()).0,
        RunVerdict::Malformed(_)
    ));
    assert_eq!(clean_symbol("db.clean_name()"), Some("clean_name".into()));
    assert_eq!(clean_symbol("Foo::BAR"), Some("BAR".into()));
    assert_eq!(clean_symbol("x"), None);
    assert_eq!(clean_symbol("rm -rf /"), None);
}

#[test]
fn plausible_follows_the_current_contract() {
    let dir = repo();
    let f = finding(EXTERNAL_ENGINE);
    let (run, _) = judge_evidence(dir.path(), &f, PLAUSIBLE, &shown_views());
    assert!(matches!(run, RunVerdict::Plausible(_)));
    let with_evidence = PLAUSIBLE.replace(
        r#""validation_plan""#,
        r#""evidence":[{"file":"app/views.py","line":7,"shows":"x"}],"validation_plan""#,
    );
    assert!(matches!(
        judge_evidence(dir.path(), &f, &with_evidence, &shown_views()).0,
        RunVerdict::Malformed(_)
    ));
}

#[test]
fn evidence_prompt_puts_the_burden_on_closing() {
    let p = build_evidence_prompt(&finding(EXTERNAL_ENGINE), &[]);
    assert!(p.contains("\"unresolved\""));
    assert!(p.contains("The burden of proof is on closing"));
    assert!(p.contains("Do not close a claim because evidence is missing"));
    assert!(!p.contains("the default verdict is \"refuted\""));
    assert!(!p.contains("an unverifiable or vague claim must be marked"));
    assert!(p.contains(ANTI_PATTERNS) && p.contains(LINE_NUMBER_INSTRUCTIONS));
}

// ── review_with: I1 never re-asks, unresolved keeps the finding ──────

#[tokio::test]
async fn failed_check_is_never_re_asked_and_keeps_the_finding() {
    let dir = repo();
    let mut f = finding(EXTERNAL_ENGINE);
    let bad = refuted(
        "unreachable",
        r#"[{"file":"app/views.py","line":2,"shows":"comment"}]"#,
        "",
    );
    let caller = Scripted::new(&[&bad, PLAUSIBLE]);
    let out = review_with(dir.path(), &mut f, &caller, plan("evidence")).await;
    assert_eq!(
        caller.prompts().len(),
        1,
        "a failed check is never re-asked"
    );
    assert!(matches!(out, ReviewOutcome::Reviewed { .. }));
    assert_eq!(f.status, FindingStatus::Candidate);
    let d = details(&f);
    assert!(
        d.iter()
            .any(|x| x.starts_with("verify_uncertain: unresolved 1/1")),
        "{d:?}"
    );
    assert!(
        d.iter().any(|x| {
            x.starts_with(
        "refute_basis: run 1/1 unreachable; guard=none; cited=app/views.py:2; outcome=downgraded"
    )
        }),
        "{d:?}"
    );
    assert!(f.blockers[0].starts_with("closure not supported by checkable lines"));
}

#[tokio::test]
async fn unresolved_reply_is_kept_not_closed() {
    let dir = repo();
    let mut f = finding(EXTERNAL_ENGINE);
    let caller = Scripted::new(&[UNRESOLVED]);
    review_with(dir.path(), &mut f, &caller, plan("evidence")).await;
    assert_eq!(f.status, FindingStatus::Candidate);
    assert!(crate::audit::adversarial::is_uncertain(&f));
    assert_eq!(caller.prompts().len(), 1, "no retrieval without +retrieval");
}

#[tokio::test]
async fn multi_run_with_an_unresolved_run_never_closes() {
    let dir = repo();
    let mut f = finding(EXTERNAL_ENGINE);
    let ok = refuted(
        "not_attacker_controlled",
        r#"[{"file":"app/views.py","line":4,"shows":"x"}]"#,
        "",
    );
    let caller = Scripted::new(&[&ok, UNRESOLVED, &ok]);
    let mut p = plan("evidence");
    p.runs = 3;
    review_with(dir.path(), &mut f, &caller, p).await;
    assert_eq!(f.status, FindingStatus::Candidate);
    assert!(
        details(&f)
            .iter()
            .any(|x| x.starts_with("verify_uncertain: unresolved 1/3"))
    );
}

#[tokio::test]
async fn evidence_ext_leaves_ai_findings_on_the_current_prompt() {
    let dir = repo();
    let mut f = finding("ai_audit");
    let current = r#"{"verdict":"refuted","reason":"x","blockers":[],"validation_plan":{"local":null,"deployment":null},"refute_basis":"defect_absent"}"#;
    let caller = Scripted::new(&[current]);
    review_with(dir.path(), &mut f, &caller, plan("evidence-ext")).await;
    assert_eq!(f.status, FindingStatus::Refuted);
    assert!(caller.prompts()[0].contains("the default verdict is \"refuted\""));
}

// ── I0 on the current policy ─────────────────────────────────────────

#[tokio::test]
async fn current_policy_records_the_basis_line() {
    let dir = repo();
    let mut f = finding(EXTERNAL_ENGINE);
    let r = r#"{"verdict":"refuted","reason":"x","blockers":[],"validation_plan":{"local":null,"deployment":null},"refute_basis":"guarded","guard":{"file":"app/views.py","line":5}}"#;
    let caller = Scripted::new(&[r]);
    review_with(dir.path(), &mut f, &caller, plan("current")).await;
    assert_eq!(f.status, FindingStatus::Refuted);
    assert!(details(&f).iter().any(|x| x
        == "refute_basis: run 1/1 guarded; guard=app/views.py:5; cited=app/views.py:5; outcome=refuted"));
    // Same check as before I0: an off-trace guard is a verify_error, now
    // with its basis recorded.
    let mut g = finding(EXTERNAL_ENGINE);
    g.trace.clear();
    g.line = Some(1);
    let far = r#"{"verdict":"refuted","reason":"x","blockers":[],"validation_plan":{"local":null,"deployment":null},"refute_basis":"guarded","guard":{"file":"app/util.py","line":4}}"#;
    let caller = Scripted::new(&[far]);
    review_with(dir.path(), &mut g, &caller, plan("current")).await;
    assert_eq!(g.status, FindingStatus::Candidate);
    assert!(details(&g).iter().any(|x| x.ends_with("outcome=invalid")));
}

// ── I2 prosecutor ────────────────────────────────────────────────────

fn guarded_refutation() -> String {
    refuted(
        "guarded",
        r#"[{"file":"app/views.py","line":5,"shows":"ZZ-SHOWS-TEXT"}]"#,
        r#","guard":{"file":"app/views.py","line":5},"covers":"ZZ-COVERS-TEXT""#,
    )
}

const VETO: &str = r#"{"bypass":true,"input":"name=\\' OR 1=1 --","path":[{"file":"app/views.py","line":4},{"file":"app/views.py","line":7}],"explanation":"backslash survives"}"#;

#[tokio::test]
async fn prosecutor_sees_no_refuter_text_and_its_veto_keeps_the_finding() {
    let dir = repo();
    let mut f = finding(EXTERNAL_ENGINE);
    let caller = Scripted::new(&[&guarded_refutation(), VETO]);
    review_with(dir.path(), &mut f, &caller, plan("evidence+prosecutor")).await;
    let prompts = caller.prompts();
    assert_eq!(
        prompts.len(),
        2,
        "one refuter call, one prosecutor call, nothing after"
    );
    let p = &prompts[1];
    for leaked in [
        "ZZ-REFUTER-REASON",
        "ZZ-COVERS-TEXT",
        "ZZ-SHOWS-TEXT",
        "refute_basis",
        "\"refuted\"",
    ] {
        assert!(!p.contains(leaked), "prosecutor prompt leaks {leaked:?}");
    }
    assert!(p.contains("<cited_lines>\napp/views.py:5\n</cited_lines>"));
    assert_eq!(f.status, FindingStatus::Candidate);
    let d = details(&f);
    assert!(
        d.iter().any(|x| x.starts_with("prosecutor: veto;")),
        "{d:?}"
    );
    assert!(
        d.iter()
            .any(|x| x == "verify_uncertain: prosecutor veto (checked bypass)")
    );
    assert!(crate::audit::adversarial::is_uncertain(&f));
}

#[tokio::test]
async fn prosecutor_without_a_checked_bypass_leaves_the_closure() {
    for reply in [
        r#"{"bypass":false,"input":null,"path":[],"explanation":"blocked"}"#,
        // A path line outside the excerpts is rejected.
        r#"{"bypass":true,"input":"x","path":[{"file":"app/util.py","line":4}],"explanation":"e"}"#,
        r#"{"bypass":true,"input":"","path":[{"file":"app/views.py","line":7}],"explanation":"e"}"#,
        "not json",
    ] {
        let dir = repo();
        let mut f = finding(EXTERNAL_ENGINE);
        let caller = Scripted::new(&[&guarded_refutation(), reply]);
        review_with(dir.path(), &mut f, &caller, plan("evidence+prosecutor")).await;
        assert_eq!(caller.prompts().len(), 2, "never re-asked: {reply}");
        assert_eq!(f.status, FindingStatus::Refuted, "{reply}");
        assert!(details(&f).iter().any(|x| x.starts_with("prosecutor:")));
    }
}

#[tokio::test]
async fn prosecutor_only_runs_on_guard_and_trust_closures() {
    let dir = repo();
    let mut f = finding(EXTERNAL_ENGINE);
    let r = refuted(
        "not_dangerous",
        r#"[{"file":"app/views.py","line":7,"shows":"x"}]"#,
        "",
    );
    let caller = Scripted::new(&[&r]);
    review_with(dir.path(), &mut f, &caller, plan("evidence+prosecutor")).await;
    assert_eq!(caller.prompts().len(), 1);
    assert_eq!(f.status, FindingStatus::Refuted);
}

// ── I3 retrieval ─────────────────────────────────────────────────────

#[test]
fn definition_patterns_find_common_definitions() {
    let hits = |line: &str, sym: &str| definition_patterns(sym).iter().any(|p| p.is_match(line));
    assert!(hits("def clean_name(v):", "clean_name"));
    assert!(hits("    async def clean_name(self, v):", "clean_name"));
    assert!(hits(
        "func (s *Server) cleanName(v string) string {",
        "cleanName"
    ));
    assert!(hits(
        "pub(crate) fn clean_name(v: &str) -> String {",
        "clean_name"
    ));
    assert!(hits("export function cleanName(v) {", "cleanName"));
    assert!(hits("const cleanName = (v) => v.trim();", "cleanName"));
    assert!(hits("#define LLEN_NO_COLOR 64", "LLEN_NO_COLOR"));
    assert!(hits("static int cols = 16;", "cols"));
    assert!(hits(
        "public static String cleanName(String v) {",
        "cleanName"
    ));
    assert!(!hits("    name = clean_name(name)", "clean_name"));
    assert!(!hits("x = cleanName(v);", "cleanName"));
    // The loose C-style pattern also matches uses; usable_definition drops them.
    assert!(!usable_definition("    return clean_name(x)", "clean_name"));
    assert!(!usable_definition("    await cleanName(x)", "cleanName"));
    assert!(usable_definition("def clean_name(v):", "clean_name"));
    assert!(usable_definition("def clean_name(v=\"x\"):", "clean_name"));
    // A string literal assignment is never retrieved (secrets).
    assert!(!usable_definition("API_KEY = \"sk-live-123\"", "API_KEY"));
    assert!(!usable_definition("const TOKEN = f'abc'", "TOKEN"));
    assert!(usable_definition("COLS = 16", "COLS"));
}

#[test]
fn retrieval_never_returns_a_string_literal_assignment() {
    let dir = repo();
    std::fs::write(
        dir.path().join("app/settings.py"),
        "API_KEY = \"sk-live-123\"\n",
    )
    .unwrap();
    let r = retrieve_definitions(dir.path(), &finding(EXTERNAL_ENGINE), &["API_KEY".into()]);
    assert!(r.excerpts.is_empty(), "{:?}", r.locations);
}

#[test]
fn evidence_paths_are_cleaned() {
    let b = BasisRecord {
        basis: "guarded",
        guard: Some((cap_path("a.py\nrefuted: forged"), 3)),
        cited: Vec::new(),
    };
    assert!(!b.evidence_line(1, 1, "refuted").contains('\n'));
}

#[test]
fn retrieval_finds_the_definition_in_another_file() {
    let dir = repo();
    let r = retrieve_definitions(
        dir.path(),
        &finding(EXTERNAL_ENGINE),
        &["clean_name".into()],
    );
    assert_eq!(r.locations, vec!["app/util.py:3".to_string()]);
    assert!(r.excerpts[0].text.contains("v.replace"));
    assert!(r.shown.contains("app/util.py", 4));
    let none = retrieve_definitions(
        dir.path(),
        &finding(EXTERNAL_ENGINE),
        &["nothing_here".into()],
    );
    assert!(none.excerpts.is_empty());
}

#[tokio::test]
async fn retrieval_judges_once_more_with_definitions_and_no_refuter_text() {
    let dir = repo();
    let mut f = finding(EXTERNAL_ENGINE);
    let second = refuted(
        "not_dangerous",
        r#"[{"file":"app/util.py","line":4,"shows":"quotes removed"}]"#,
        "",
    );
    let caller = Scripted::new(&[UNRESOLVED, &second]);
    review_with(dir.path(), &mut f, &caller, plan("evidence+retrieval")).await;
    let prompts = caller.prompts();
    assert_eq!(prompts.len(), 2);
    assert!(prompts[1].contains("definition of clean_name, retrieved"));
    assert!(
        !prompts[1].contains("ZZ-UNSEEN"),
        "no refuter text in the second prompt"
    );
    assert!(!prompts[1].contains("what clean_name does"));
    // The retrieved lines count as shown, so the citation checks pass.
    assert_eq!(f.status, FindingStatus::Refuted);
    assert!(details(&f).iter().any(|x| x.starts_with(
        "retrieval: run 1/1 symbols=[clean_name] found=[app/util.py:3]; second reply: refuted"
    )));
}

#[tokio::test]
async fn prosecutor_sees_the_definitions_the_closing_run_saw() {
    let dir = repo();
    let mut f = finding(EXTERNAL_ENGINE);
    let second = refuted(
        "not_attacker_controlled",
        r#"[{"file":"app/util.py","line":4,"shows":"ZZ-SHOWS-TEXT"}]"#,
        "",
    );
    let veto = r#"{"bypass":true,"input":"a backslash","path":[{"file":"app/util.py","line":4},{"file":"app/views.py","line":7}],"explanation":"e"}"#;
    let caller = Scripted::new(&[UNRESOLVED, &second, veto]);
    review_with(
        dir.path(),
        &mut f,
        &caller,
        plan("evidence+prosecutor+retrieval"),
    )
    .await;
    let prompts = caller.prompts();
    assert_eq!(prompts.len(), 3);
    assert!(prompts[2].contains("definition of clean_name, retrieved"));
    assert!(!prompts[2].contains("ZZ-SHOWS-TEXT") && !prompts[2].contains("ZZ-UNSEEN"));
    // The bypass path runs through a retrieved line, which counts as shown.
    assert_eq!(f.status, FindingStatus::Candidate);
    assert!(
        details(&f)
            .iter()
            .any(|x| x.starts_with("prosecutor: veto;"))
    );
}

#[tokio::test]
async fn retrieval_never_runs_on_a_downgraded_refutation() {
    let dir = repo();
    let mut f = finding(EXTERNAL_ENGINE);
    let bad = refuted("unreachable", "[]", "");
    let caller = Scripted::new(&[&bad]);
    review_with(dir.path(), &mut f, &caller, plan("evidence+retrieval")).await;
    assert_eq!(caller.prompts().len(), 1);
    assert_eq!(f.status, FindingStatus::Candidate);
}

// ── --refuter-score (recorded only) ─────────────────────────────────────

fn scored(base: ReviewPlan) -> ReviewPlan {
    ReviewPlan {
        score: true,
        ..base
    }
}

fn with_score(reply: &str, p: u8, level: &str) -> String {
    let mut v: serde_json::Value = serde_json::from_str(reply).unwrap();
    v["p_real"] = serde_json::json!(p);
    v["evidence_level"] = serde_json::json!(level);
    v.to_string()
}

#[tokio::test]
async fn without_the_flag_score_keys_still_break_the_contract() {
    let dir = repo();
    let mut f = finding(EXTERNAL_ENGINE);
    let reply = with_score(PLAUSIBLE, 80, "flow_shown");
    // Keys the default contract does not know: re-asked, and the plain
    // second reply decides, exactly as before the flag existed.
    let caller = Scripted::new(&[&reply, PLAUSIBLE]);
    review_with(dir.path(), &mut f, &caller, plan("current")).await;
    assert_eq!(caller.prompts().len(), 2);
    assert!(!caller.prompts()[0].contains("## Score"));
    assert_eq!(f.status, FindingStatus::NeedsHuman);
    assert!(!details(&f).iter().any(|d| d.starts_with("refuter_score:")));
}

#[tokio::test]
async fn score_of_the_re_asked_reply_is_the_one_recorded() {
    let dir = repo();
    let mut f = finding(EXTERNAL_ENGINE);
    let broken = r#"{"verdict":"plausible","p_real":90,"evidence_level":"flow_shown"}"#;
    let fixed = with_score(PLAUSIBLE, 61, "flow_likely");
    let caller = Scripted::new(&[broken, &fixed]);
    review_with(dir.path(), &mut f, &caller, scored(plan("current"))).await;
    assert_eq!(caller.prompts().len(), 2);
    assert!(caller.prompts()[1].contains("## Score"));
    assert_eq!(f.status, FindingStatus::NeedsHuman);
    let lines: Vec<String> = details(&f)
        .into_iter()
        .filter(|d| d.starts_with("refuter_score:"))
        .collect();
    assert_eq!(
        lines,
        vec!["refuter_score: run 1/1 p_real=61 evidence=flow_likely; verdict=plausible"]
    );
}

#[tokio::test]
async fn score_with_evidence_retrieval_keeps_the_adopted_reply_and_its_verdict() {
    let dir = repo();
    let second = refuted(
        "not_dangerous",
        r#"[{"file":"app/util.py","line":4,"shows":"quotes removed"}]"#,
        "",
    );
    let mut plain = finding(EXTERNAL_ENGINE);
    let plain_caller = Scripted::new(&[UNRESOLVED, &second]);
    review_with(
        dir.path(),
        &mut plain,
        &plain_caller,
        plan("evidence+retrieval"),
    )
    .await;
    let mut f = finding(EXTERNAL_ENGINE);
    let first = with_score(UNRESOLVED, 50, "undetermined");
    let second_scored = with_score(&second, 9, "safe_shown");
    let caller = Scripted::new(&[&first, &second_scored]);
    review_with(
        dir.path(),
        &mut f,
        &caller,
        scored(plan("evidence+retrieval")),
    )
    .await;
    assert_eq!(f.status, FindingStatus::Refuted);
    assert_eq!(f.status, plain.status);
    assert!(caller.prompts()[1].contains("## Score"));
    assert!(
        details(&f)
            .iter()
            .any(|d| d == "refuter_score: run 1/1 p_real=9 evidence=safe_shown; verdict=refuted")
    );
    // Apart from the score lines, the evidence matches the plain run's.
    let strip = |x: &Finding| -> Vec<String> {
        details(x)
            .into_iter()
            .filter(|d| !d.starts_with("refuter_score:"))
            .collect()
    };
    assert_eq!(strip(&f), strip(&plain));
}

// ── --refuter-score-threshold (opt-in closing rule) ──────────────────────

const CURRENT_REFUTED: &str = r#"{"verdict":"refuted","reason":"ZZ-NO-FLOW","blockers":[],"validation_plan":{"local":null,"deployment":null},"refute_basis":"defect_absent"}"#;

fn gated(t: u8, runs: usize) -> ReviewPlan {
    ReviewPlan {
        runs,
        score_threshold: Some(t),
        ..plan("current")
    }
}

#[tokio::test]
async fn a_refutation_below_the_threshold_closes() {
    let dir = repo();
    let mut f = finding(EXTERNAL_ENGINE);
    let caller = Scripted::new(&[&with_score(CURRENT_REFUTED, 6, "safe_shown")]);
    review_with(dir.path(), &mut f, &caller, gated(7, 1)).await;
    assert_eq!(f.status, FindingStatus::Refuted);
    assert!(
        caller.prompts()[0].contains("## Score"),
        "threshold turns the score on"
    );
    assert!(
        details(&f)
            .iter()
            .any(|d| d == "refuter_score: run 1/1 p_real=6 evidence=safe_shown; verdict=refuted")
    );
}

#[tokio::test]
async fn a_refutation_at_or_above_the_threshold_stays_open() {
    let dir = repo();
    let mut f = finding(EXTERNAL_ENGINE);
    let caller = Scripted::new(&[&with_score(CURRENT_REFUTED, 7, "safe_likely")]);
    review_with(dir.path(), &mut f, &caller, gated(7, 1)).await;
    assert_eq!(f.status, FindingStatus::Candidate);
    assert!(crate::audit::adversarial::is_uncertain(&f));
    let d = details(&f);
    assert!(
        d.iter()
            .any(|x| x.contains("p_real 7 is not below the closing threshold 7"))
    );
    assert!(
        d.iter()
            .any(|x| x.starts_with("refute_basis: run 1/1 defect_absent")
                && x.ends_with("outcome=downgraded"))
    );
    assert!(d.iter().any(|x| x.ends_with("; verdict=downgraded")));
    assert_eq!(caller.prompts().len(), 1, "never re-asked");
}

#[tokio::test]
async fn a_refutation_without_a_usable_score_never_closes() {
    let dir = repo();
    for reply in [
        CURRENT_REFUTED.to_string(),
        CURRENT_REFUTED.replace("\"refute_basis\"", "\"p_real\":2,\"refute_basis\""),
        with_score(CURRENT_REFUTED, 2, "safe_shown").replace("\"p_real\":2", "\"p_real\":2.5"),
    ] {
        let mut f = finding(EXTERNAL_ENGINE);
        let caller = Scripted::new(&[&reply]);
        review_with(dir.path(), &mut f, &caller, gated(7, 1)).await;
        assert_eq!(f.status, FindingStatus::Candidate, "{reply}");
        assert!(
            details(&f)
                .iter()
                .any(|x| x.contains("closing needs p_real below 7")),
            "{reply}"
        );
    }
}

#[tokio::test]
async fn the_threshold_never_closes_a_plausible_finding() {
    let dir = repo();
    let mut f = finding(EXTERNAL_ENGINE);
    let caller = Scripted::new(&[&with_score(PLAUSIBLE, 1, "safe_shown")]);
    review_with(dir.path(), &mut f, &caller, gated(7, 1)).await;
    assert_eq!(f.status, FindingStatus::NeedsHuman);
}

#[tokio::test]
async fn one_open_run_among_closing_runs_keeps_the_finding_open() {
    let dir = repo();
    let mut f = finding(EXTERNAL_ENGINE);
    let first = with_score(CURRENT_REFUTED, 2, "safe_shown");
    let second = with_score(CURRENT_REFUTED, 40, "undetermined");
    let caller = Scripted::new(&[&first, &second]);
    review_with(dir.path(), &mut f, &caller, gated(7, 2)).await;
    assert_eq!(caller.prompts().len(), 2);
    assert_eq!(f.status, FindingStatus::Candidate);
}

#[tokio::test]
async fn without_a_threshold_a_high_score_does_not_block_a_refutation() {
    let dir = repo();
    let mut f = finding(EXTERNAL_ENGINE);
    let caller = Scripted::new(&[&with_score(CURRENT_REFUTED, 90, "flow_shown")]);
    review_with(dir.path(), &mut f, &caller, scored(plan("current"))).await;
    assert_eq!(f.status, FindingStatus::Refuted);
}
