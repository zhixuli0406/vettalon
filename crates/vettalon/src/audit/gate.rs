//! Policy gate: SonarQube-style conditions that decide whether a scan fails
//! CI, finer than the single `--fail-on` severity threshold.
//!
//! A condition counts findings at or above a severity, restricted to a set of
//! statuses and optionally to those a cross-family verifier (or a human)
//! upheld, and fails when that count passes a threshold:
//!
//! ```text
//! severity>=critical status=confirmed,needs_human cross_family count>0
//! ```
//!
//! Tokens (whitespace-separated, any order):
//! - `severity>=LEVEL` — `critical|high|medium|low|info` (default `info`).
//! - `status=a,b` — any of `candidate,confirmed,needs_human` (default
//!   `candidate,confirmed`, the statuses `--fail-on` reads). Refuted and
//!   suppressed findings are closed and can never gate.
//! - `cross_family` — only findings with at least one cross-family verifier
//!   vote of `plausible`, or confirmed by an operator.
//! - `count>N` or `count>=N` — required; the condition fails when the
//!   count meets it.
//!
//! Results live in `summary.policy`, recomputed on every operator decision
//! and checked by the report validator like the rest of the summary.

use serde::{Deserialize, Serialize};

use super::schema::{Finding, FindingStatus, Severity, SeverityBasis, VoteVerdict};

/// Comparison of a condition's threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CountOp {
    /// Fails when count > threshold.
    Gt,
    /// Fails when count >= threshold.
    Gte,
}

/// One gate condition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateCondition {
    pub min_severity: Severity,
    pub statuses: Vec<FindingStatus>,
    #[serde(default)]
    pub cross_family: bool,
    pub op: CountOp,
    pub threshold: usize,
}

/// One evaluated condition, as stored in the report summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateResult {
    pub condition: GateCondition,
    /// Canonical expression, for display and for re-parsing.
    pub expr: String,
    /// Findings the condition counted.
    pub count: usize,
    pub failed: bool,
}

const DEFAULT_STATUSES: [FindingStatus; 2] = [FindingStatus::Candidate, FindingStatus::Confirmed];

fn status_name(s: FindingStatus) -> &'static str {
    match s {
        FindingStatus::Candidate => "candidate",
        FindingStatus::Confirmed => "confirmed",
        FindingStatus::NeedsHuman => "needs_human",
        FindingStatus::Refuted => "refuted",
        FindingStatus::Suppressed => "suppressed",
    }
}

fn parse_status(s: &str) -> Result<FindingStatus, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "candidate" => Ok(FindingStatus::Candidate),
        "confirmed" => Ok(FindingStatus::Confirmed),
        "needs_human" | "needs-human" => Ok(FindingStatus::NeedsHuman),
        "refuted" | "suppressed" => Err(format!(
            "狀態 {s} 是已結案的發現，不能作為門檻條件（只接受 candidate、confirmed、needs_human）"
        )),
        other => Err(format!(
            "未知的狀態 {other:?}（只接受 candidate、confirmed、needs_human）"
        )),
    }
}

impl std::str::FromStr for GateCondition {
    type Err = String;

    fn from_str(expr: &str) -> Result<Self, Self::Err> {
        let mut min_severity = Severity::Info;
        let mut statuses: Option<Vec<FindingStatus>> = None;
        let mut cross_family = false;
        let mut count: Option<(CountOp, usize)> = None;
        for tok in expr.split_whitespace() {
            let lower = tok.to_ascii_lowercase();
            if let Some(v) = lower
                .strip_prefix("severity>=")
                .or_else(|| lower.strip_prefix("sev>="))
            {
                min_severity = v.parse()?;
            } else if let Some(v) = lower.strip_prefix("status=") {
                let mut list = Vec::new();
                for s in v.split(',').filter(|s| !s.is_empty()) {
                    let st = parse_status(s)?;
                    if !list.contains(&st) {
                        list.push(st);
                    }
                }
                if list.is_empty() {
                    return Err("status= 後面至少要有一個狀態".into());
                }
                statuses = Some(list);
            } else if lower == "cross_family" || lower == "cross-family" {
                cross_family = true;
            } else if let Some(v) = lower.strip_prefix("count>=") {
                count = Some((CountOp::Gte, parse_threshold(v)?));
            } else if let Some(v) = lower.strip_prefix("count>") {
                count = Some((CountOp::Gt, parse_threshold(v)?));
            } else {
                return Err(format!(
                    "看不懂門檻條件中的 {tok:?}（可用：severity>=LEVEL、status=a,b、cross_family、count>N / count>=N）"
                ));
            }
        }
        let (op, threshold) =
            count.ok_or_else(|| format!("門檻條件 {expr:?} 缺少 count>N 或 count>=N"))?;
        if op == CountOp::Gte && threshold == 0 {
            return Err("count>=0 永遠成立，請改用 count>0 或更大的門檻".into());
        }
        let mut statuses = statuses.unwrap_or_else(|| DEFAULT_STATUSES.to_vec());
        statuses.sort_by_key(|s| status_name(*s));
        Ok(GateCondition {
            min_severity,
            statuses,
            cross_family,
            op,
            threshold,
        })
    }
}

fn parse_threshold(v: &str) -> Result<usize, String> {
    v.parse()
        .map_err(|_| format!("門檻數量 {v:?} 不是非負整數"))
}

impl std::fmt::Display for GateCondition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let statuses: Vec<&str> = self.statuses.iter().map(|s| status_name(*s)).collect();
        write!(
            f,
            "severity>={} status={}",
            self.min_severity.as_str(),
            statuses.join(",")
        )?;
        if self.cross_family {
            f.write_str(" cross_family")?;
        }
        match self.op {
            CountOp::Gt => write!(f, " count>{}", self.threshold),
            CountOp::Gte => write!(f, " count>={}", self.threshold),
        }
    }
}

/// A cross-family verifier upheld the finding, or a human confirmed it.
pub fn upheld_cross_family(f: &Finding) -> bool {
    (f.status == FindingStatus::Confirmed && f.severity_basis == SeverityBasis::Operator)
        || f.verification
            .iter()
            .any(|v| v.cross_family && v.verdict == VoteVerdict::Plausible)
}

impl GateCondition {
    fn counts(&self, f: &Finding) -> bool {
        f.severity >= self.min_severity
            && self.statuses.contains(&f.status)
            && (!self.cross_family || upheld_cross_family(f))
    }

    pub fn evaluate(&self, findings: &[Finding]) -> GateResult {
        let count = findings.iter().filter(|f| self.counts(f)).count();
        let failed = match self.op {
            CountOp::Gt => count > self.threshold,
            CountOp::Gte => count >= self.threshold,
        };
        GateResult {
            condition: self.clone(),
            expr: self.to_string(),
            count,
            failed,
        }
    }
}

/// Parse every `--gate` expression; the first bad one is the error.
pub fn parse_all(exprs: &[String]) -> Result<Vec<GateCondition>, String> {
    exprs
        .iter()
        .filter(|e| !e.trim().is_empty())
        .map(|e| e.parse().map_err(|err| format!("--gate {e:?}：{err}")))
        .collect()
}

/// Evaluate `conditions` in order.
pub fn evaluate_all(conditions: &[GateCondition], findings: &[Finding]) -> Vec<GateResult> {
    conditions.iter().map(|c| c.evaluate(findings)).collect()
}

/// Re-evaluate the conditions an existing result list was built from.
pub fn reevaluate(previous: &[GateResult], findings: &[Finding]) -> Vec<GateResult> {
    previous
        .iter()
        .map(|r| r.condition.evaluate(findings))
        .collect()
}

/// Whether any condition failed.
pub fn any_failed(results: &[GateResult]) -> bool {
    results.iter().any(|r| r.failed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::schema::{FindingKind, VerifierVote};

    fn finding(sev: Severity, status: FindingStatus) -> Finding {
        let mut f = Finding::candidate(
            "ai_audit",
            FindingKind::Other,
            sev,
            "t",
            "a.py",
            Some(1),
            "x",
            "r",
            vec![],
        );
        f.status = status;
        f
    }

    fn vote(cross: bool, verdict: VoteVerdict) -> VerifierVote {
        VerifierVote {
            model: "codex".into(),
            family: "openai".into(),
            verdict,
            cross_family: cross,
            same_model: false,
        }
    }

    #[test]
    fn parses_defaults_and_roundtrips() {
        let c: GateCondition = "count>0".parse().unwrap();
        assert_eq!(c.min_severity, Severity::Info);
        assert_eq!(
            c.statuses,
            vec![FindingStatus::Candidate, FindingStatus::Confirmed]
        );
        assert!(!c.cross_family);
        let expr = "severity>=critical status=needs_human,confirmed cross_family count>=2";
        let c: GateCondition = expr.parse().unwrap();
        assert_eq!(c.op, CountOp::Gte);
        assert_eq!(c.threshold, 2);
        let again: GateCondition = c.to_string().parse().unwrap();
        assert_eq!(c, again, "Display is a canonical, re-parseable form");
        assert_eq!(
            c.to_string(),
            "severity>=critical status=confirmed,needs_human cross_family count>=2"
        );
    }

    #[test]
    fn rejects_bad_expressions() {
        for bad in [
            "severity>=high",               // no count
            "status=refuted count>0",       // closed status
            "status= count>0",              // empty list
            "severity>=urgent count>0",     // bad level
            "count>-1",                     // negative
            "count>=0",                     // always true
            "severity>=high count>0 bogus", // unknown token
        ] {
            assert!(bad.parse::<GateCondition>().is_err(), "{bad}");
        }
    }

    #[test]
    fn cross_family_counts_only_upheld_findings() {
        let mut upheld = finding(Severity::Critical, FindingStatus::NeedsHuman);
        upheld.verification = vec![vote(true, VoteVerdict::Plausible)];
        let mut same_family = finding(Severity::Critical, FindingStatus::NeedsHuman);
        same_family.verification = vec![vote(false, VoteVerdict::Plausible)];
        let mut by_human = finding(Severity::Critical, FindingStatus::Confirmed);
        by_human.severity_basis = SeverityBasis::Operator;
        let refuted = finding(Severity::Critical, FindingStatus::Refuted);
        let low = {
            let mut f = finding(Severity::Low, FindingStatus::NeedsHuman);
            f.verification = vec![vote(true, VoteVerdict::Plausible)];
            f
        };
        let all = [upheld, same_family, by_human, refuted, low];

        let c: GateCondition =
            "severity>=critical status=confirmed,needs_human cross_family count>0"
                .parse()
                .unwrap();
        let r = c.evaluate(&all);
        assert_eq!(r.count, 2);
        assert!(r.failed);

        let c: GateCondition =
            "severity>=critical status=confirmed,needs_human cross_family count>2"
                .parse()
                .unwrap();
        assert!(!c.evaluate(&all).failed);
    }

    #[test]
    fn reevaluate_tracks_status_changes() {
        let mut fs = vec![finding(Severity::High, FindingStatus::Candidate)];
        let conds = parse_all(&["severity>=high count>0".to_string()]).unwrap();
        let first = evaluate_all(&conds, &fs);
        assert!(any_failed(&first));
        fs[0].status = FindingStatus::Refuted;
        assert!(!any_failed(&reevaluate(&first, &fs)));
    }
}
