//! Budget settings: validation at startup, the effective budget table, and
//! the hunt's per-dependency allocator with rollover.
//!
//! Subscription CLIs report no token counts, so every budget here is wall
//! clock seconds. Two lessons from the DARPA AIxCC finalists' published
//! write-ups shape this module:
//!
//! - Team Atlanta funded each target with "remaining budget ÷ remaining
//!   targets" and rolled what a target did not use forward to later ones.
//!   [`DepBudget`] does the same for `hunt` dependencies.
//! - Shellphish lost a core feature for the whole final because one budget
//!   key was silently capped at $10. So a value that cannot fund even one
//!   model call is rejected before any work starts, with a clear message and
//!   exit code 2, instead of quietly deferring everything.

use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// The least time one model call needs. A budget or cap below this cannot
/// fund a single finder, refuter or PoC call, so it is a configuration
/// error, not a budget. A floor, not an estimate: real calls often take
/// minutes.
pub const MIN_CALL_SECS: u64 = 60;

/// The least time one hunt dependency needs: a source fetch (30 s request
/// timeout) plus one model call.
pub const MIN_DEP_SECS: u64 = 90;

/// Per-dependency time limit when no total hunt budget is set (unchanged
/// from earlier releases).
pub const DEFAULT_DEP_TIMEOUT_SECS: u64 = 300;

/// Why a budget setting was rejected at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetError {
    /// The value is zero.
    Zero { flag: &'static str },
    /// The value is below the minimum one call (or one dependency) needs.
    BelowMinimum {
        flag: &'static str,
        secs: u64,
        min: u64,
    },
    /// A role cap is larger than the total budget it lives inside.
    CapExceedsTotal {
        flag: &'static str,
        secs: u64,
        total: u64,
    },
}

impl std::fmt::Display for BudgetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            BudgetError::Zero { flag } => crate::tr!(
                "{flag} 不能是 0（0 秒連一次模型呼叫都做不了；不設此旗標即不限）",
                "{flag} cannot be 0 (zero seconds cannot fund a single model call; omit the flag for no limit)"
            ),
            BudgetError::BelowMinimum { flag, secs, min } => {
                let need = if *min >= MIN_DEP_SECS {
                    crate::lang::pick(
                        "不夠完成一次原始碼下載加一次模型呼叫",
                        "not enough for a source fetch plus one model call",
                    )
                } else {
                    crate::lang::pick("不夠完成一次模型呼叫", "not enough for one model call")
                };
                crate::tr!(
                    "{flag} {secs} 秒低於下限 {min} 秒（{need}），請調高或不設",
                    "{flag} {secs}s is below the {min}s minimum ({need}); raise it or omit the flag"
                )
            }
            BudgetError::CapExceedsTotal { flag, secs, total } => crate::tr!(
                "{flag} {secs} 秒大於 --time-budget {total} 秒；角色上限不能超過總預算",
                "{flag} {secs}s exceeds --time-budget {total}s; a role cap cannot be larger than the total budget"
            ),
        };
        f.write_str(&text)
    }
}

impl std::error::Error for BudgetError {}

/// Exit code for a rejected budget setting (same as other bad flags).
pub const BUDGET_ERROR_EXIT: i32 = 2;

fn check_secs(flag: &'static str, secs: u64, min: u64) -> Result<Duration, BudgetError> {
    if secs == 0 {
        return Err(BudgetError::Zero { flag });
    }
    if secs < min {
        return Err(BudgetError::BelowMinimum { flag, secs, min });
    }
    Ok(Duration::from_secs(secs))
}

// ── scan: total budget + per-role caps ──────────────────────────────────

/// Wall-clock caps for each model role of a deep scan, measured from the
/// moment that role's step starts. `None` = no cap of its own (the scan's
/// `--time-budget`, if any, still applies).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RoleCaps {
    pub finder: Option<Duration>,
    pub refuter: Option<Duration>,
    pub poc: Option<Duration>,
}

/// Raw scan budget flags, in seconds, as given on the command line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScanBudgetFlags {
    pub total: Option<u64>,
    pub finder: Option<u64>,
    pub refuter: Option<u64>,
    pub poc: Option<u64>,
}

/// Validated scan budget.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScanBudget {
    pub total: Option<Duration>,
    pub caps: RoleCaps,
}

/// Validate the scan budget flags: every value must be non-zero and at least
/// [`MIN_CALL_SECS`], and no role cap may exceed the total budget.
pub fn validate_scan(flags: ScanBudgetFlags) -> Result<ScanBudget, BudgetError> {
    let total = flags
        .total
        .map(|s| check_secs("--time-budget", s, MIN_CALL_SECS))
        .transpose()?;
    let cap = |flag: &'static str, v: Option<u64>| -> Result<Option<Duration>, BudgetError> {
        let Some(secs) = v else { return Ok(None) };
        let d = check_secs(flag, secs, MIN_CALL_SECS)?;
        if let Some(t) = flags.total
            && secs > t
        {
            return Err(BudgetError::CapExceedsTotal {
                flag,
                secs,
                total: t,
            });
        }
        Ok(Some(d))
    };
    Ok(ScanBudget {
        total,
        caps: RoleCaps {
            finder: cap("--finder-budget", flags.finder)?,
            refuter: cap("--refuter-budget", flags.refuter)?,
            poc: cap("--poc-budget", flags.poc)?,
        },
    })
}

fn secs_cell(d: Option<Duration>) -> String {
    match d {
        Some(d) => format!("{}s", d.as_secs()),
        None => crate::lang::pick("不限", "no limit").to_string(),
    }
}

impl ScanBudget {
    /// The effective budget table printed at startup. Finder and PoC: the
    /// role's own cap (from the start of its step) bounded by the total.
    /// Refuter: its own cap only; the total stops extra refuter runs (2..n)
    /// but never a finding's first review.
    pub fn render_table(&self, poc_enabled: bool) -> String {
        let mut out = String::new();
        out.push_str(&crate::tr!(
            "預算（牆鐘秒數）：總計 {}\n",
            "budget (wall-clock seconds): total {}\n",
            secs_cell(self.total)
        ));
        let rows: [(&str, Option<Duration>, bool, bool); 3] = [
            ("finder", self.caps.finder, true, true),
            ("refuter", self.caps.refuter, true, false),
            ("poc", self.caps.poc, poc_enabled, true),
        ];
        for (role, cap, active, total_applies) in rows {
            let total = if total_applies { self.total } else { None };
            let effective = match (cap, total) {
                (Some(c), Some(t)) => Some(c.min(t)),
                (c, t) => c.or(t),
            };
            let line = if active {
                crate::tr!(
                    "  {role:<8} 上限 {:<9} 實際 {}\n",
                    "  {role:<8} cap {:<9} effective {}\n",
                    secs_cell(cap),
                    secs_cell(effective)
                )
            } else {
                crate::tr!("  {role:<8} 未啟用\n", "  {role:<8} not enabled\n")
            };
            out.push_str(&line);
        }
        if self.total.is_some() {
            out.push_str(crate::lang::pick(
                "  （--time-budget 到期後不再開始額外的 refuter 覆核，但每筆發現的第一次覆核照跑）\n",
                "  (after --time-budget, extra refuter runs do not start; each finding's first review still runs)\n",
            ));
        }
        out
    }

    /// True when any budget flag was set (the table is only worth printing
    /// then).
    pub fn is_set(&self) -> bool {
        self.total.is_some()
            || self.caps.finder.is_some()
            || self.caps.refuter.is_some()
            || self.caps.poc.is_some()
    }
}

/// The scan's budget as recorded in the report (`ensemble.budget`): the
/// limits that applied and whether each role's own cap cut work short.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanBudgetRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finder_cap_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refuter_cap_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poc_cap_secs: Option<u64>,
    /// The finder cap deferred at least one module.
    #[serde(default)]
    pub finder_cap_hit: bool,
    /// The refuter cap left at least one finding without a review.
    #[serde(default)]
    pub refuter_cap_hit: bool,
    /// The PoC cap skipped at least one eligible finding.
    #[serde(default)]
    pub poc_cap_hit: bool,
}

/// The earlier of a step's own cap (from `step_start`) and the scan-wide
/// deadline.
pub fn step_deadline(
    scan_deadline: Option<std::time::Instant>,
    cap: Option<Duration>,
    step_start: std::time::Instant,
) -> Option<std::time::Instant> {
    let own = cap.map(|c| step_start + c);
    match (scan_deadline, own) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

// ── hunt: per-dependency allocator with rollover ────────────────────────

/// `--hunt-budget`: each dependency gets remaining ÷ remaining dependencies
/// when it starts; `cap` (an explicit `--dep-timeout`) bounds one share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RolloverBudget {
    pub total: Duration,
    pub cap: Option<Duration>,
}

/// Validated hunt budget: either a fixed per-dependency timeout (the
/// default), or a total budget split across dependencies with rollover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HuntBudget {
    /// Every dependency gets the same `--dep-timeout`.
    Fixed {
        per_dep: Duration,
    },
    Rollover(RolloverBudget),
}

/// Validate the hunt budget flags.
pub fn validate_hunt(
    total: Option<u64>,
    dep_timeout: Option<u64>,
) -> Result<HuntBudget, BudgetError> {
    let cap = dep_timeout
        .map(|s| check_secs("--dep-timeout", s, MIN_DEP_SECS))
        .transpose()?;
    match total {
        None => Ok(HuntBudget::Fixed {
            per_dep: cap.unwrap_or(Duration::from_secs(DEFAULT_DEP_TIMEOUT_SECS)),
        }),
        Some(s) => Ok(HuntBudget::Rollover(RolloverBudget {
            total: check_secs("--hunt-budget", s, MIN_DEP_SECS)?,
            cap,
        })),
    }
}

impl HuntBudget {
    /// The effective budget table printed at hunt start.
    pub fn render_table(&self, deps: usize) -> String {
        match self {
            HuntBudget::Fixed { per_dep } => crate::tr!(
                "預算：每個相依固定 {}s（--dep-timeout），共 {deps} 個相依\n",
                "budget: a fixed {}s per dependency (--dep-timeout), {deps} dependencies\n",
                per_dep.as_secs()
            ),
            HuntBudget::Rollover(RolloverBudget { total, cap }) => {
                let first = share(*total, Duration::ZERO, Duration::ZERO, deps, *cap)
                    .max(Duration::from_secs(MIN_DEP_SECS))
                    .min(*total);
                crate::tr!(
                    "預算：總計 {}s（--hunt-budget，相依秒數加總），共 {deps} 個相依；第一個約 {}s，每個相依開始時重算「剩餘 ÷ 剩餘相依數」，提早結束的額度往後滾；單一相依上限 {}\n",
                    "budget: {}s total (--hunt-budget, summed over dependencies), {deps} dependencies; the first gets about {}s, each share is recomputed as remaining ÷ remaining dependencies when it starts, unused time rolls forward; per-dependency cap {}\n",
                    total.as_secs(),
                    first.as_secs(),
                    secs_cell(*cap)
                )
            }
        }
    }
}

/// One dependency's share: what is neither spent nor reserved by in-flight
/// dependencies, divided by the dependencies that have not started yet
/// (including this one), bounded by `cap`. Pure.
pub fn share(
    total: Duration,
    spent: Duration,
    reserved: Duration,
    remaining: usize,
    cap: Option<Duration>,
) -> Duration {
    let available = total.saturating_sub(spent).saturating_sub(reserved);
    let even = available / remaining.max(1) as u32;
    match cap {
        Some(c) => even.min(c),
        None => even,
    }
}

#[derive(Debug, Default)]
struct DepBudgetState {
    spent: Duration,
    reserved: Duration,
    remaining: usize,
}

/// Allocator for `--hunt-budget`. Each dependency calls [`allocate`] when it
/// starts and [`settle`] when it ends; time a dependency did not use returns
/// to the pool for the ones after it. Safe to share across the concurrent
/// dependency audits.
///
/// With `--dep-concurrency` above 1, an in-flight dependency's whole share
/// stays reserved until it ends. A dependency that starts while the free
/// pool is below the minimum but others are still in flight waits for one of
/// them to settle (their unused time may fund it) instead of being deferred;
/// it is deferred only when nothing is in flight and the pool is short.
///
/// [`allocate`]: DepBudget::allocate
/// [`settle`]: DepBudget::settle
#[derive(Debug)]
pub struct DepBudget {
    total: Duration,
    cap: Option<Duration>,
    min: Duration,
    state: Mutex<DepBudgetState>,
    settled: tokio::sync::Notify,
}

impl DepBudget {
    pub fn new(total: Duration, cap: Option<Duration>, deps: usize) -> Self {
        Self::with_min(total, cap, deps, Duration::from_secs(MIN_DEP_SECS))
    }

    /// [`DepBudget::new`] with a custom minimum share (tests).
    pub fn with_min(total: Duration, cap: Option<Duration>, deps: usize, min: Duration) -> Self {
        DepBudget {
            total,
            cap,
            min,
            state: Mutex::new(DepBudgetState {
                remaining: deps,
                ..Default::default()
            }),
            settled: tokio::sync::Notify::new(),
        }
    }

    /// Reserve this dependency's share. `None` when what is left cannot fund
    /// the minimum for one dependency and no other dependency is in flight
    /// to return unused time: the dependency is deferred, not started with a
    /// hopeless share. While others are in flight it waits for a settle and
    /// checks again. When the even share is below the minimum but the pool
    /// still holds it, this dependency (earlier in priority order) gets the
    /// minimum instead.
    pub async fn allocate(&self) -> Option<Duration> {
        if self.cap.is_some_and(|c| c < self.min) {
            self.take_slot();
            return None;
        }
        loop {
            // Registered before the check, so a settle in between is not missed.
            let settled = self.settled.notified();
            {
                let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
                let available = self
                    .total
                    .saturating_sub(s.spent)
                    .saturating_sub(s.reserved);
                if available >= self.min {
                    let remaining = s.remaining.max(1);
                    s.remaining = s.remaining.saturating_sub(1);
                    let even = share(self.total, s.spent, s.reserved, remaining, self.cap);
                    let granted = even.max(self.min);
                    s.reserved += granted;
                    return Some(granted);
                }
                if s.reserved.is_zero() {
                    s.remaining = s.remaining.saturating_sub(1);
                    return None;
                }
            }
            settled.await;
        }
    }

    fn take_slot(&self) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.remaining = s.remaining.saturating_sub(1);
    }

    /// Release a share: the time actually used (at most the share) is spent,
    /// the rest rolls forward.
    pub fn settle(&self, granted: Duration, used: Duration) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.reserved = s.reserved.saturating_sub(granted);
        s.spent += used.min(granted);
        drop(s);
        self.settled.notify_waiters();
    }

    /// Time spent so far by settled dependencies.
    pub fn spent(&self) -> Duration {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).spent
    }
}

/// One dependency's line in the hunt budget record.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepAllocation {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    /// Seconds granted when it started; `None` when it was deferred.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted_secs: Option<u64>,
    pub used_ms: u64,
    /// Not started: the budget could not fund the minimum share.
    #[serde(default)]
    pub deferred: bool,
}

/// The hunt's budget as recorded in the report.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HuntBudgetRecord {
    /// `"fixed"` (per-dependency `--dep-timeout`) or `"rollover"`
    /// (`--hunt-budget`).
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_secs: Option<u64>,
    /// Per-dependency limit: the fixed timeout, or the rollover cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dep_cap_secs: Option<u64>,
    /// Sum of the dependencies' own durations (not wall clock: concurrent
    /// dependencies overlap).
    pub spent_ms: u64,
    pub deferred: usize,
    #[serde(default)]
    pub allocations: Vec<DepAllocation>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: fn(u64) -> Duration = Duration::from_secs;

    #[test]
    fn share_is_remaining_over_remaining_deps() {
        assert_eq!(share(S(600), S(0), S(0), 4, None), S(150));
        assert_eq!(share(S(600), S(100), S(200), 3, None), S(100));
        assert_eq!(share(S(600), S(0), S(0), 4, Some(S(120))), S(120));
        // Overspent pool never underflows.
        assert_eq!(share(S(100), S(80), S(50), 2, None), S(0));
        // Zero remaining is treated as one.
        assert_eq!(share(S(100), S(0), S(0), 0, None), S(100));
    }

    #[tokio::test]
    async fn early_finish_rolls_forward_to_later_dependencies() {
        let b = DepBudget::with_min(S(600), None, 4, S(10));
        let first = b.allocate().await.unwrap();
        assert_eq!(first, S(150));
        b.settle(first, S(30)); // finished early: 120 s unused
        let second = b.allocate().await.unwrap();
        assert_eq!(second, S(190), "(600 - 30) / 3");
        b.settle(second, S(190));
        let third = b.allocate().await.unwrap();
        assert_eq!(third, S(190), "(600 - 220) / 2");
        b.settle(third, S(10));
        let fourth = b.allocate().await.unwrap();
        assert_eq!(fourth, S(370), "everything left goes to the last one");
        b.settle(fourth, S(400)); // overrun is clamped to the share
        assert_eq!(b.spent(), S(600));
    }

    #[tokio::test]
    async fn concurrent_shares_reserve_until_settled() {
        let b = DepBudget::with_min(S(600), None, 4, S(10));
        let a = b.allocate().await.unwrap();
        let c = b.allocate().await.unwrap();
        assert_eq!((a, c), (S(150), S(150)), "(600 - 150) / 3");
        b.settle(a, S(50));
        let d = b.allocate().await.unwrap();
        assert_eq!(
            d,
            S(200),
            "(600 - 50 - 150) / 2: a's unused 100 s rolled forward"
        );
    }

    #[tokio::test]
    async fn exhaustion_defers_instead_of_starting_a_hopeless_share() {
        let b = DepBudget::with_min(S(200), None, 3, S(90));
        // Even share 66 s < 90 s minimum: the first (highest priority) gets
        // the minimum instead.
        let first = b.allocate().await.unwrap();
        assert_eq!(first, S(90));
        b.settle(first, S(90));
        let second = b.allocate().await.unwrap();
        assert_eq!(second, S(90), "110 / 2 = 55 → raised to the 90 s minimum");
        b.settle(second, S(90));
        assert_eq!(
            b.allocate().await,
            None,
            "20 s left cannot fund one dependency"
        );
        assert_eq!(b.spent(), S(180));
    }

    #[tokio::test]
    async fn cap_bounds_each_share_and_a_cap_below_minimum_defers() {
        let b = DepBudget::with_min(S(1000), Some(S(100)), 2, S(10));
        assert_eq!(b.allocate().await, Some(S(100)));
        let tiny = DepBudget::with_min(S(1000), Some(S(5)), 2, S(10));
        assert_eq!(tiny.allocate().await, None);
    }

    #[tokio::test]
    async fn a_short_pool_waits_for_in_flight_time_instead_of_deferring() {
        let b = std::sync::Arc::new(DepBudget::with_min(S(150), None, 2, S(90)));
        let first = b.allocate().await.unwrap();
        assert_eq!(first, S(90), "75 s even share raised to the minimum");
        // 60 s free, first still in flight: the second waits, not defers.
        let waiter = {
            let b = b.clone();
            tokio::spawn(async move { b.allocate().await })
        };
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        b.settle(first, S(10));
        assert_eq!(
            waiter.await.unwrap(),
            Some(S(140)),
            "first's unused 80 s rolled forward"
        );
    }

    #[test]
    fn scan_validation_rejects_zero_tiny_and_oversized_caps() {
        let ok = validate_scan(ScanBudgetFlags {
            total: Some(1200),
            finder: Some(900),
            refuter: Some(300),
            poc: None,
        })
        .unwrap();
        assert_eq!(ok.total, Some(S(1200)));
        assert_eq!(ok.caps.finder, Some(S(900)));
        assert_eq!(ok.caps.poc, None);

        assert_eq!(
            validate_scan(ScanBudgetFlags {
                total: Some(0),
                ..Default::default()
            }),
            Err(BudgetError::Zero {
                flag: "--time-budget"
            })
        );
        assert_eq!(
            validate_scan(ScanBudgetFlags {
                refuter: Some(10),
                ..Default::default()
            }),
            Err(BudgetError::BelowMinimum {
                flag: "--refuter-budget",
                secs: 10,
                min: MIN_CALL_SECS
            })
        );
        assert_eq!(
            validate_scan(ScanBudgetFlags {
                total: Some(600),
                poc: Some(601),
                ..Default::default()
            }),
            Err(BudgetError::CapExceedsTotal {
                flag: "--poc-budget",
                secs: 601,
                total: 600
            })
        );
        // Caps without a total are fine.
        assert!(
            validate_scan(ScanBudgetFlags {
                finder: Some(MIN_CALL_SECS),
                ..Default::default()
            })
            .is_ok()
        );
    }

    #[test]
    fn hunt_validation() {
        assert_eq!(
            validate_hunt(None, None),
            Ok(HuntBudget::Fixed {
                per_dep: S(DEFAULT_DEP_TIMEOUT_SECS)
            })
        );
        assert_eq!(
            validate_hunt(Some(3600), Some(600)),
            Ok(HuntBudget::Rollover(RolloverBudget {
                total: S(3600),
                cap: Some(S(600))
            }))
        );
        assert_eq!(
            validate_hunt(Some(0), None),
            Err(BudgetError::Zero {
                flag: "--hunt-budget"
            })
        );
        assert_eq!(
            validate_hunt(None, Some(30)),
            Err(BudgetError::BelowMinimum {
                flag: "--dep-timeout",
                secs: 30,
                min: MIN_DEP_SECS
            })
        );
    }

    #[test]
    fn step_deadline_takes_the_earlier_limit() {
        let now = std::time::Instant::now();
        assert_eq!(step_deadline(None, None, now), None);
        assert_eq!(step_deadline(None, Some(S(5)), now), Some(now + S(5)));
        assert_eq!(
            step_deadline(Some(now + S(3)), Some(S(5)), now),
            Some(now + S(3))
        );
        assert_eq!(
            step_deadline(Some(now + S(9)), Some(S(5)), now),
            Some(now + S(5))
        );
    }

    #[test]
    fn tables_name_every_role_and_mode() {
        let b = validate_scan(ScanBudgetFlags {
            total: Some(600),
            finder: Some(400),
            ..Default::default()
        })
        .unwrap();
        let t = b.render_table(false);
        assert!(t.contains("finder") && t.contains("refuter") && t.contains("poc"));
        assert!(t.contains("400s"));
        let h = validate_hunt(Some(600), None).unwrap().render_table(4);
        assert!(h.contains("600s") && h.contains("150s"));
    }
}
