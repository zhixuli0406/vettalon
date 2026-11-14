//! Spend guard for metered HTTP backends. Money accounting fails closed:
//! a call is reserved at its worst-case cost before it is made, a missing or
//! unreadable usage report keeps that worst case, and only a provider usage
//! report or a rejection status that implies no inference (400, 401, 403,
//! 404, 413, 422, 429 without usage) lowers it. A call billed above its
//! reservation trips the guard: the run makes no further calls.
//!
//! Arithmetic: a price of `X` USD per million tokens is `X` micro-USD per
//! token. Prices are converted once to integer pico-USD per token (rounded
//! up), charges are summed in `u128` and rounded up to whole micro-USD, and
//! every step saturates. There is no float on the charging path and no NaN.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use serde::Deserialize;

use super::Usage;

/// Schema tag a price table must carry.
pub const PRICE_SCHEMA: &str = "vettalon.prices/1";
/// Largest price table accepted.
pub const MAX_PRICE_TABLE_BYTES: u64 = 64 * 1024;
/// Highest accepted price, USD per million tokens.
pub const MAX_PRICE_USD_PER_MILLION: f64 = 1000.0;
/// Highest accepted spend cap, USD.
pub const MAX_CAP_USD: f64 = 10_000.0;
/// Token allowance added to the prompt byte length for the worst case
/// (chat framing, role tokens).
pub const PROMPT_OVERHEAD_TOKENS: u64 = 256;

const PICO_PER_MICRO: u128 = 1_000_000;
const MICRO_PER_USD: f64 = 1_000_000.0;

/// One model's prices, USD per million tokens.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Price {
    pub input: f64,
    pub cached_input: f64,
    pub output: f64,
    /// Optional: the most output tokens the provider may bill for one call
    /// (e.g. reasoning tokens not bounded by `max_tokens`). When present the
    /// worst case uses `max(max_output_tokens, this)`.
    #[serde(default)]
    pub max_billed_output_tokens: Option<u32>,
}

/// A validated `vettalon.prices/1` table. Only constructible through
/// [`PriceTable::parse`] / [`PriceTable::load`], so every instance passed
/// validation.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriceTable {
    schema: String,
    retrieved: String,
    source: Vec<String>,
    #[serde(deserialize_with = "unique_models")]
    models: BTreeMap<String, Price>,
}

/// Refuse duplicate model keys: with last-wins semantics a later, cheaper
/// entry could silently replace the reviewed one.
fn unique_models<'de, D>(d: D) -> Result<BTreeMap<String, Price>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct V;
    impl<'de> serde::de::Visitor<'de> for V {
        type Value = BTreeMap<String, Price>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a map of API model id to prices")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> Result<Self::Value, A::Error> {
            use serde::de::Error as _;
            let mut out = BTreeMap::new();
            while let Some((k, v)) = map.next_entry::<String, Price>()? {
                if out.contains_key(&k) {
                    return Err(A::Error::custom(format!(
                        "duplicate model {:?}",
                        crate::util::truncate_bytes(&k, 100)
                    )));
                }
                out.insert(k, v);
            }
            Ok(out)
        }
    }
    d.deserialize_map(V)
}

/// Integer price: pico-USD per token, rounded up. `None` when the price is
/// not finite or outside `0..=MAX_PRICE_USD_PER_MILLION`.
fn pico_per_token(usd_per_million: f64) -> Option<u64> {
    if !usd_per_million.is_finite() || !(0.0..=MAX_PRICE_USD_PER_MILLION).contains(&usd_per_million)
    {
        return None;
    }
    let p = (usd_per_million * 1e6).ceil();
    // <= 1e9, exactly representable; the range check rules out NaN too.
    if !(0.0..=MAX_PRICE_USD_PER_MILLION * 1e6).contains(&p) {
        return None;
    }
    Some(p as u64)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rates {
    input: u64,
    cached_input: u64,
    output: u64,
    max_billed_output_tokens: Option<u32>,
}

impl Rates {
    fn of(p: &Price) -> Option<Rates> {
        Some(Rates {
            input: pico_per_token(p.input)?,
            cached_input: pico_per_token(p.cached_input)?,
            output: pico_per_token(p.output)?,
            max_billed_output_tokens: p.max_billed_output_tokens,
        })
    }
}

/// `sum(tokens * pico)` rounded up to whole micro-USD, saturating.
fn charge_micro(terms: &[(u64, u64)]) -> u64 {
    let pico = terms.iter().fold(0u128, |acc, &(tokens, rate)| {
        acc.saturating_add(u128::from(tokens).saturating_mul(u128::from(rate)))
    });
    u64::try_from(pico.div_ceil(PICO_PER_MICRO)).unwrap_or(u64::MAX)
}

impl PriceTable {
    /// Parse and validate a table from bytes (≤ 64 KiB).
    pub fn parse(bytes: &[u8]) -> Result<PriceTable, String> {
        if bytes.len() as u64 > MAX_PRICE_TABLE_BYTES {
            return Err(format!(
                "price table is larger than {MAX_PRICE_TABLE_BYTES} bytes"
            ));
        }
        let t: PriceTable =
            serde_json::from_slice(bytes).map_err(|e| format!("invalid price table: {e}"))?;
        t.validate()?;
        Ok(t)
    }

    /// Read a regular (non-symlink) file of at most 64 KiB and parse it.
    pub fn load(path: &Path) -> Result<PriceTable, String> {
        use crate::util::RegularFileError;
        let bytes =
            crate::util::read_regular_file(path, MAX_PRICE_TABLE_BYTES).map_err(|e| match e {
                RegularFileError::NotRegular => {
                    format!("price table {} is not a regular file", path.display())
                }
                RegularFileError::TooLarge => format!(
                    "price table {} is larger than {MAX_PRICE_TABLE_BYTES} bytes",
                    path.display()
                ),
                RegularFileError::Io(e) => {
                    format!("cannot read price table {}: {e}", path.display())
                }
            })?;
        PriceTable::parse(&bytes)
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema != PRICE_SCHEMA {
            return Err(format!(
                "price table schema must be {PRICE_SCHEMA:?}, got {:?}",
                crate::util::truncate_bytes(&self.schema, 100)
            ));
        }
        if self.models.is_empty() {
            return Err("price table has no models".into());
        }
        for (id, p) in &self.models {
            if id.is_empty() {
                return Err("price table has an empty model id".into());
            }
            if Rates::of(p).is_none() {
                return Err(format!(
                    "price for model {:?} must be finite, >= 0 and <= {MAX_PRICE_USD_PER_MILLION} USD per million tokens",
                    crate::util::truncate_bytes(id, 100)
                ));
            }
            // A cached token costing more than an uncached one is a typo
            // (swapped columns) and would let the worst case undercount.
            if p.cached_input > p.input {
                return Err(format!(
                    "price for model {:?}: cached_input must not be above input",
                    crate::util::truncate_bytes(id, 100)
                ));
            }
        }
        Ok(())
    }

    pub fn retrieved(&self) -> &str {
        &self.retrieved
    }

    pub fn source(&self) -> &[String] {
        &self.source
    }

    pub fn models(&self) -> &BTreeMap<String, Price> {
        &self.models
    }

    pub fn price(&self, api_model: &str) -> Option<&Price> {
        self.models.get(api_model)
    }
}

/// Why a call was not allowed to go out.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpendRefusal {
    #[error("no price for model {0}")]
    NoPrice(String),
    #[error("spend cap reached")]
    CapReached,
    /// An earlier call was billed above its reservation (or spend went past
    /// the cap); the worst case is no longer trusted, so nothing more goes
    /// out in this run.
    #[error("spend cap reached (an earlier call was billed above its reservation)")]
    Tripped,
}

/// What happened to a reserved call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettleOutcome {
    /// The provider reported usage: charge exactly that.
    Usage(Usage),
    /// The call may have run but usage is unknown (ok/refusal without usage,
    /// timeout, read failure, 408/409/499/5xx, cancelled): keep the worst case.
    MissingAfterResponse,
    /// HTTP 400/401/403/404/413/422/429 without usage: rejected before
    /// inference, charge nothing.
    RejectedBeforeInference,
}

/// HTTP statuses that, without a usage report, mean the request was
/// rejected before any inference ran. Anything else without usage (408,
/// 409, 499, 5xx, no status) may have run and keeps the worst case.
pub const REJECTED_BEFORE_INFERENCE_STATUSES: [u16; 7] = [400, 401, 403, 404, 413, 422, 429];

impl SettleOutcome {
    /// Map one call's metering to a settle outcome: reported usage is
    /// charged whatever the status; otherwise only the statuses in
    /// [`REJECTED_BEFORE_INFERENCE_STATUSES`] are refunded.
    pub fn from_response(usage: Option<Usage>, http_status: Option<u16>) -> SettleOutcome {
        match (usage, http_status) {
            (Some(u), _) => SettleOutcome::Usage(u),
            (None, Some(s)) if REJECTED_BEFORE_INFERENCE_STATUSES.contains(&s) => {
                SettleOutcome::RejectedBeforeInference
            }
            _ => SettleOutcome::MissingAfterResponse,
        }
    }
}

pub const TAG_PROVIDER: &str = "provider";
/// Ceiling shared by reservation and over-cap checks, including billed reasoning.
pub fn effective_output_ceiling(max_tokens: u32, max_output_tokens_worst: Option<u32>) -> u32 {
    max_tokens.max(max_output_tokens_worst.unwrap_or(max_tokens))
}

pub const TAG_WORST_CASE: &str = "charged_worst_case";

#[derive(Debug, Default)]
struct Ledger {
    /// Charged plus currently reserved, micro-USD.
    spent: u64,
    /// Outstanding reservations, micro-USD. `settle` never releases more
    /// than this, so a wrong `reserved_worst` cannot refund past what was
    /// actually reserved.
    held: u64,
}

/// Run-wide spend cap shared by every guarded [`super::StepCaller`].
#[derive(Debug)]
pub struct SpendGuard {
    cap_micro: u64,
    spent_micro: Mutex<Ledger>,
    worst_case_calls: AtomicU64,
    /// Settles that charged more than their reservation.
    over_reservation_calls: AtomicU64,
    /// Set once a settle charged above its reservation or spend went past
    /// the cap; every later `reserve` is refused.
    tripped: AtomicBool,
    entries: HashMap<String, Rates>,
}

impl SpendGuard {
    /// `cap_usd` must be finite, > 0 and <= 10 000. The cap is rounded DOWN
    /// to whole micro-USD.
    pub fn new(cap_usd: f64, table: PriceTable) -> Result<Self, String> {
        if !cap_usd.is_finite() || cap_usd <= 0.0 || cap_usd > MAX_CAP_USD {
            return Err(format!(
                "spend cap must be a finite amount > 0 and <= {MAX_CAP_USD} USD"
            ));
        }
        let cap = (cap_usd * MICRO_PER_USD).floor();
        if !(1.0..=MAX_CAP_USD * MICRO_PER_USD).contains(&cap) {
            return Err("spend cap must be at least 0.000001 USD".into());
        }
        // Re-validate even though PriceTable is only built validated.
        table.validate()?;
        let mut entries = HashMap::with_capacity(table.models.len());
        for (id, p) in &table.models {
            let rates = Rates::of(p).ok_or_else(|| format!("invalid price for model {id}"))?;
            entries.insert(id.clone(), rates);
        }
        Ok(SpendGuard {
            cap_micro: cap as u64,
            spent_micro: Mutex::new(Ledger::default()),
            worst_case_calls: AtomicU64::new(0),
            over_reservation_calls: AtomicU64::new(0),
            tripped: AtomicBool::new(false),
            entries,
        })
    }

    fn ledger(&self) -> std::sync::MutexGuard<'_, Ledger> {
        // The ledger is two integers written together under the lock and no
        // code under the lock panics; a poisoned value is still consistent.
        self.spent_micro.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Worst-case cost of one call, micro-USD.
    pub fn worst_case(
        &self,
        api_model: &str,
        prompt_len_bytes: usize,
        max_output_tokens: u32,
    ) -> Result<u64, SpendRefusal> {
        let r = self
            .entries
            .get(api_model)
            .ok_or_else(|| SpendRefusal::NoPrice(api_model.to_string()))?;
        let input = u64::try_from(prompt_len_bytes)
            .unwrap_or(u64::MAX)
            .saturating_add(PROMPT_OVERHEAD_TOKENS);
        // Validation already refuses cached_input > input; take the max
        // anyway so the worst case never depends on that check.
        let input_rate = r.input.max(r.cached_input);
        let output = max_output_tokens.max(r.max_billed_output_tokens.unwrap_or(0));
        Ok(charge_micro(&[
            (input, input_rate),
            (u64::from(output), r.output),
        ]))
    }

    /// Reserve the worst-case cost of one call. On success the amount is
    /// already counted as spent (so concurrent callers cannot both pass) and
    /// must be passed back to [`settle`](Self::settle).
    pub fn reserve(
        &self,
        api_model: &str,
        prompt_len_bytes: usize,
        max_output_tokens: u32,
    ) -> Result<u64, SpendRefusal> {
        let worst = self.worst_case(api_model, prompt_len_bytes, max_output_tokens)?;
        let mut l = self.ledger();
        // Checked under the ledger lock: `settle` sets it under the same
        // lock, so no reserve can slip in between an overshoot and the trip.
        if self.tripped.load(Ordering::SeqCst) {
            return Err(SpendRefusal::Tripped);
        }
        match l.spent.checked_add(worst) {
            Some(total) if total <= self.cap_micro => {
                l.spent = total;
                l.held = l.held.saturating_add(worst);
                Ok(worst)
            }
            _ => Err(SpendRefusal::CapReached),
        }
    }

    /// Replace a reservation with the real charge. Returns the charge in
    /// micro-USD and the trace `usage` tag.
    pub fn settle(
        &self,
        api_model: &str,
        reserved_worst: u64,
        outcome: SettleOutcome,
    ) -> (u64, &'static str) {
        let (charged, tag) = match outcome {
            SettleOutcome::Usage(u) => match self.entries.get(api_model) {
                Some(r) => {
                    let cached = u.cached_input.min(u.input);
                    (
                        charge_micro(&[
                            (u.input - cached, r.input),
                            (cached, r.cached_input),
                            (u.output, r.output),
                        ]),
                        TAG_PROVIDER,
                    )
                }
                // Cannot happen after a successful reserve; fail closed.
                None => (reserved_worst, TAG_WORST_CASE),
            },
            SettleOutcome::MissingAfterResponse => (reserved_worst, TAG_WORST_CASE),
            SettleOutcome::RejectedBeforeInference => (0, TAG_PROVIDER),
        };
        if tag == TAG_WORST_CASE {
            self.worst_case_calls.fetch_add(1, Ordering::SeqCst);
        }
        let mut l = self.ledger();
        let release = reserved_worst.min(l.held);
        l.held -= release;
        l.spent = l.spent.saturating_sub(release).saturating_add(charged);
        let over_reservation = charged > reserved_worst;
        if over_reservation {
            self.over_reservation_calls.fetch_add(1, Ordering::SeqCst);
        }
        // The worst case did not bound this call (or the cap is already
        // past): stop the run rather than trust the next estimate.
        if over_reservation || l.spent > self.cap_micro {
            self.tripped.store(true, Ordering::SeqCst);
        }
        (charged, tag)
    }

    /// True when the provider reported more output than was requested; the
    /// worst case did not bound this call.
    pub fn over_cap(usage: &Usage, max_output_tokens: u32) -> bool {
        usage.output > u64::from(max_output_tokens)
    }

    /// True when charged spend went past the cap (one call billed above
    /// its expected maximum).
    pub fn exceeded_cap(&self) -> bool {
        self.spent_micro() > self.cap_micro
    }

    /// True once the guard stopped allowing calls because a settle charged
    /// above its reservation or spend went past the cap.
    pub fn is_tripped(&self) -> bool {
        self.tripped.load(Ordering::SeqCst)
    }

    /// Settles that charged more than their reservation.
    pub fn over_reservation_calls(&self) -> u64 {
        self.over_reservation_calls.load(Ordering::SeqCst)
    }

    pub fn spent_micro(&self) -> u64 {
        self.ledger().spent
    }

    pub fn cap_micro(&self) -> u64 {
        self.cap_micro
    }

    pub fn spent_usd(&self) -> f64 {
        self.spent_micro() as f64 / MICRO_PER_USD
    }

    pub fn cap_usd(&self) -> f64 {
        self.cap_micro as f64 / MICRO_PER_USD
    }

    pub fn calls_charged_worst_case(&self) -> u64 {
        self.worst_case_calls.load(Ordering::SeqCst)
    }
}

/// A reservation that settles itself as [`SettleOutcome::MissingAfterResponse`]
/// if dropped unsettled (e.g. the call future was cancelled mid-flight).
pub(crate) struct Reservation<'a> {
    guard: &'a SpendGuard,
    api_model: String,
    worst: u64,
    settled: bool,
}

impl<'a> Reservation<'a> {
    pub(crate) fn new(guard: &'a SpendGuard, api_model: String, worst: u64) -> Self {
        Reservation {
            guard,
            api_model,
            worst,
            settled: false,
        }
    }

    pub(crate) fn settle(mut self, outcome: SettleOutcome) -> (u64, &'static str) {
        self.settled = true;
        self.guard.settle(&self.api_model, self.worst, outcome)
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if !self.settled {
            self.guard.settle(
                &self.api_model,
                self.worst,
                SettleOutcome::MissingAfterResponse,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_ceiling_bounds_reasoning_cost_and_output() {
        let g = guard(1.0);
        let default = effective_output_ceiling(1024, None);
        let reasoning = effective_output_ceiling(1024, Some(8192));
        assert_eq!(g.worst_case("m", 744, default), Ok(11240));
        assert_eq!(g.worst_case("m", 744, reasoning), Ok(82920));
        assert!(SpendGuard::over_cap(&usage(0, 0, 7326), default));
        assert!(!SpendGuard::over_cap(&usage(0, 0, 7326), reasoning));
        assert!(!SpendGuard::over_cap(&usage(0, 0, 8192), reasoning));
        assert!(SpendGuard::over_cap(&usage(0, 0, 8193), reasoning));
    }

    #[test]
    fn committed_c2_price_table_loads() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../benchmarks/c2/prices-2026-11-12.json");
        let t = PriceTable::load(&path).unwrap();
        for m in ["claude-sonnet-5-5", "gpt-6.1-sol", "grok-4.7"] {
            assert!(t.models.contains_key(m), "missing {m}");
        }
    }

    fn table_json(models: &str) -> String {
        format!(
            r#"{{"schema":"vettalon.prices/1","retrieved":"2026-11-12","source":["https://example.com/p"],"models":{models}}}"#
        )
    }

    fn table(models: &str) -> PriceTable {
        PriceTable::parse(table_json(models).as_bytes()).unwrap()
    }

    /// in 1, cached 0.1, out 10 USD/M = 1, 0.1, 10 micro-USD per token.
    fn guard(cap_usd: f64) -> SpendGuard {
        SpendGuard::new(
            cap_usd,
            table(r#"{"m":{"input":1,"cached_input":0.1,"output":10}}"#),
        )
        .unwrap()
    }

    fn usage(input: u64, cached_input: u64, output: u64) -> Usage {
        Usage {
            input,
            cached_input,
            output,
            reasoning: None,
        }
    }

    #[test]
    fn table_parses() {
        let t = table(
            r#"{"a":{"input":2,"cached_input":0.1,"output":10},"b":{"input":0,"cached_input":0,"output":1000}}"#,
        );
        assert_eq!(t.models().len(), 2);
        assert_eq!(t.retrieved(), "2026-11-12");
        assert_eq!(t.source(), ["https://example.com/p".to_string()]);
        assert_eq!(
            t.price("a"),
            Some(&Price {
                input: 2.0,
                cached_input: 0.1,
                output: 10.0,
                max_billed_output_tokens: None,
            })
        );
    }

    #[test]
    fn table_refuses_cached_input_above_input() {
        let e = PriceTable::parse(
            table_json(r#"{"ok":{"input":1,"cached_input":1,"output":1},"bad":{"input":0.1,"cached_input":1,"output":1}}"#)
                .as_bytes(),
        )
        .unwrap_err();
        assert!(e.contains("cached_input must not be above input"), "{e}");
        assert!(e.contains("bad"), "{e}");
    }

    #[test]
    fn max_billed_output_tokens_parses_and_raises_the_worst_case() {
        let t = table(
            r#"{"m":{"input":1,"cached_input":0.1,"output":10,"max_billed_output_tokens":500}}"#,
        );
        assert_eq!(t.price("m").unwrap().max_billed_output_tokens, Some(500));
        let g = SpendGuard::new(1.0, t).unwrap();
        // 744 + 256 = 1000 input; max(100, 500) * 10 = 5000 output.
        assert_eq!(g.worst_case("m", 744, 100), Ok(6000));
        // A larger max_output_tokens still wins.
        assert_eq!(g.worst_case("m", 744, 1000), Ok(11_000));
        // Without the field: max_output_tokens only.
        assert_eq!(guard(1.0).worst_case("m", 744, 100), Ok(2000));
        // Bad values are refused (negative, out of u32, wrong type).
        for bad in [
            r#"{"m":{"input":1,"cached_input":1,"output":1,"max_billed_output_tokens":-1}}"#,
            r#"{"m":{"input":1,"cached_input":1,"output":1,"max_billed_output_tokens":4294967296}}"#,
            r#"{"m":{"input":1,"cached_input":1,"output":1,"max_billed_output_tokens":"5"}}"#,
        ] {
            assert!(
                PriceTable::parse(table_json(bad).as_bytes()).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn worst_case_uses_the_higher_input_rate() {
        // Unreachable through a validated table; exercise the formula directly.
        let mut g = guard(1.0);
        g.entries.insert(
            "swapped".into(),
            Rates {
                input: 1_000_000,
                cached_input: 5_000_000,
                output: 0,
                max_billed_output_tokens: None,
            },
        );
        // (744 + 256) tokens at 5 micro-USD.
        assert_eq!(g.worst_case("swapped", 744, 0), Ok(5000));
    }

    #[test]
    fn settle_above_reservation_trips_the_guard() {
        let g = guard(1.0);
        let w = g.reserve("m", 744, 10).unwrap(); // 1000 + 100
        assert!(!g.is_tripped());
        // 1000 input + 20 output * 10 = 1200 > 1100 reserved.
        let (c, _) = g.settle("m", w, SettleOutcome::Usage(usage(1000, 0, 20)));
        assert_eq!(c, 1200);
        assert!(g.is_tripped());
        assert_eq!(g.over_reservation_calls(), 1);
        assert!(
            !g.exceeded_cap(),
            "under the cap, but the worst case failed"
        );
        // Plenty of headroom left, still refused.
        assert_eq!(g.reserve("m", 0, 0), Err(SpendRefusal::Tripped));
        assert_eq!(g.spent_micro(), 1200, "a refusal reserves nothing");
        assert!(
            SpendRefusal::Tripped
                .to_string()
                .starts_with("spend cap reached")
        );
    }

    #[test]
    fn settle_past_the_cap_trips_and_reports_exceeded_cap() {
        let g = guard(0.002); // 2000 micro
        let w = g.reserve("m", 744, 100).unwrap(); // 2000, exactly the cap
        let (c, _) = g.settle("m", w, SettleOutcome::Usage(usage(1000, 0, 150)));
        assert_eq!(c, 2500);
        assert!(g.exceeded_cap());
        assert!(g.is_tripped());
        assert_eq!(g.over_reservation_calls(), 1);
        assert_eq!(g.reserve("m", 0, 0), Err(SpendRefusal::Tripped));
    }

    #[test]
    fn settle_within_reservation_does_not_trip() {
        let g = guard(1.0);
        let w = g.reserve("m", 744, 100).unwrap();
        g.settle("m", w, SettleOutcome::Usage(usage(1000, 0, 100)));
        let w = g.reserve("m", 744, 100).unwrap();
        g.settle("m", w, SettleOutcome::MissingAfterResponse);
        assert!(!g.is_tripped() && !g.exceeded_cap());
        assert_eq!(g.over_reservation_calls(), 0);
        assert!(g.reserve("m", 744, 100).is_ok());
    }

    #[test]
    fn settle_outcome_from_response_maps_statuses() {
        let u = usage(1, 0, 1);
        // Usage present: charged whatever the status.
        for s in [Some(200), Some(400), Some(429), Some(408), Some(500), None] {
            assert_eq!(
                SettleOutcome::from_response(Some(u), s),
                SettleOutcome::Usage(u)
            );
        }
        for s in [400, 401, 403, 404, 413, 422, 429] {
            assert_eq!(
                SettleOutcome::from_response(None, Some(s)),
                SettleOutcome::RejectedBeforeInference,
                "{s}"
            );
        }
        for s in [
            Some(200),
            Some(402),
            Some(408),
            Some(409),
            Some(499),
            Some(500),
            Some(503),
            None,
        ] {
            assert_eq!(
                SettleOutcome::from_response(None, s),
                SettleOutcome::MissingAfterResponse,
                "{s:?}"
            );
        }
    }

    #[test]
    fn table_refuses_bad_shapes() {
        let ok_model = r#"{"a":{"input":1,"cached_input":1,"output":1}}"#;
        for bad in [
            // Unknown field at top level and inside a price.
            format!(
                r#"{{"schema":"vettalon.prices/1","retrieved":"x","source":[],"models":{ok_model},"extra":1}}"#
            ),
            table_json(r#"{"a":{"input":1,"cached_input":1,"output":1,"batch":1}}"#),
            // Wrong / missing schema.
            format!(
                r#"{{"schema":"vettalon.prices/2","retrieved":"x","source":[],"models":{ok_model}}}"#
            ),
            format!(r#"{{"retrieved":"x","source":[],"models":{ok_model}}}"#),
            // Missing price field.
            table_json(r#"{"a":{"input":1,"output":1}}"#),
            // Negative, > 1000, huge (out of f64 range), string.
            table_json(r#"{"a":{"input":-0.5,"cached_input":1,"output":1}}"#),
            table_json(r#"{"a":{"input":1,"cached_input":1,"output":1000.01}}"#),
            table_json(r#"{"a":{"input":1,"cached_input":1e309,"output":1}}"#),
            table_json(r#"{"a":{"input":1,"cached_input":1,"output":1e300}}"#),
            table_json(r#"{"a":{"input":"1","cached_input":1,"output":1}}"#),
            table_json(r#"{"a":{"input":null,"cached_input":1,"output":1}}"#),
            // No models, empty id, duplicate id.
            table_json("{}"),
            table_json(r#"{"":{"input":1,"cached_input":1,"output":1}}"#),
            table_json(
                r#"{"a":{"input":5,"cached_input":1,"output":5},"a":{"input":0,"cached_input":0,"output":0}}"#,
            ),
            // Duplicate top-level field.
            format!(
                r#"{{"schema":"vettalon.prices/1","schema":"vettalon.prices/1","retrieved":"x","source":[],"models":{ok_model}}}"#
            ),
            "not json".to_string(),
        ] {
            assert!(
                PriceTable::parse(bad.as_bytes()).is_err(),
                "accepted: {bad}"
            );
        }
    }

    #[test]
    fn table_size_cap_on_parse_and_load() {
        let base = table_json(r#"{"a":{"input":1,"cached_input":1,"output":1}}"#);
        let pad = |n: usize| format!("{base}{}", " ".repeat(n - base.len()));
        let at_cap = pad(MAX_PRICE_TABLE_BYTES as usize);
        let over = pad(MAX_PRICE_TABLE_BYTES as usize + 1);
        assert!(PriceTable::parse(at_cap.as_bytes()).is_ok());
        assert!(PriceTable::parse(over.as_bytes()).is_err());

        let dir = tempfile::tempdir().unwrap();
        let ok = dir.path().join("ok.json");
        std::fs::write(&ok, &at_cap).unwrap();
        assert!(PriceTable::load(&ok).is_ok());
        let big = dir.path().join("big.json");
        std::fs::write(&big, &over).unwrap();
        let e = PriceTable::load(&big).unwrap_err();
        assert!(e.contains("larger than"), "{e}");
        assert!(PriceTable::load(dir.path()).is_err(), "directory refused");
        assert!(PriceTable::load(&dir.path().join("missing.json")).is_err());
        #[cfg(unix)]
        {
            let link = dir.path().join("link.json");
            std::os::unix::fs::symlink(&ok, &link).unwrap();
            assert!(PriceTable::load(&link).is_err(), "symlink refused");
        }
    }

    #[test]
    fn cap_is_validated() {
        let t = || table(r#"{"m":{"input":1,"cached_input":1,"output":1}}"#);
        for bad in [
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            0.0,
            -1.0,
            10_000.01,
            1e-9,
        ] {
            assert!(SpendGuard::new(bad, t()).is_err(), "accepted cap {bad}");
        }
        let g = SpendGuard::new(10_000.0, t()).unwrap();
        assert_eq!(g.cap_micro(), 10_000_000_000);
        assert_eq!(g.cap_usd(), 10_000.0);
    }

    #[test]
    fn prices_round_up_never_down() {
        assert_eq!(pico_per_token(0.1), Some(100_000));
        assert_eq!(pico_per_token(2.0), Some(2_000_000));
        assert_eq!(pico_per_token(1000.0), Some(1_000_000_000));
        assert_eq!(pico_per_token(0.0), Some(0));
        assert_eq!(pico_per_token(1e-12), Some(1));
        assert_eq!(pico_per_token(f64::NAN), None);
        assert_eq!(pico_per_token(-0.0001), None);
        // One cached token at 0.1 USD/M is 0.1 micro-USD: charged as 1.
        let g = guard(1.0);
        let w = g.reserve("m", 0, 0).unwrap();
        assert_eq!(g.settle("m", w, SettleOutcome::Usage(usage(1, 1, 0))).0, 1);
        // Saturation instead of overflow.
        assert_eq!(charge_micro(&[(u64::MAX, 1_000_000_000)]), u64::MAX);
    }

    #[test]
    fn reserve_boundary_exact_cap_passes_one_more_micro_refused() {
        // cap 1 USD = 1_000_000 micro; input 1 micro/token, output 10.
        let g = guard(1.0);
        // (999_744 + 256) * 1 = 1_000_000 exactly.
        assert_eq!(g.reserve("m", 999_744, 0), Ok(1_000_000));
        assert_eq!(g.spent_micro(), 1_000_000);
        let g = guard(1.0);
        assert_eq!(g.reserve("m", 999_745, 0), Err(SpendRefusal::CapReached));
        assert_eq!(g.spent_micro(), 0, "a refusal reserves nothing");
        // Output counts too: 744 + 256 = 1000, 99_900 * 10 = 999_000.
        assert_eq!(g.reserve("m", 744, 99_900), Ok(1_000_000));
    }

    #[test]
    fn reservation_is_held_against_later_callers() {
        let g = guard(0.003); // 3000 micro
        let w = g.reserve("m", 744, 100).unwrap(); // 1000 + 1000
        assert_eq!(w, 2000);
        assert_eq!(g.reserve("m", 744, 100), Err(SpendRefusal::CapReached));
        // Settling the first with a small actual frees room.
        let (charged, tag) = g.settle("m", w, SettleOutcome::Usage(usage(100, 0, 10)));
        assert_eq!((charged, tag), (200, "provider"));
        assert_eq!(g.spent_micro(), 200);
        assert!(g.reserve("m", 744, 100).is_ok());
    }

    #[test]
    fn concurrent_reservations_never_exceed_cap() {
        let g = guard(0.01); // 10_000 micro, each worst 2000 -> exactly 5 fit
        let ok = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..32 {
                s.spawn(|| {
                    if g.reserve("m", 744, 100).is_ok() {
                        ok.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(ok.load(Ordering::SeqCst), 5);
        assert_eq!(g.spent_micro(), 10_000);
    }

    #[test]
    fn settle_with_usage_refunds_the_difference() {
        let g = guard(1.0);
        let w = g.reserve("m", 744, 100).unwrap();
        assert_eq!(w, 2000);
        // 400 * 1 + 100 * 0.1 + 50 * 10 = 910.
        let (c, tag) = g.settle("m", w, SettleOutcome::Usage(usage(500, 100, 50)));
        assert_eq!((c, tag), (910, "provider"));
        assert_eq!(g.spent_micro(), 910);
        assert_eq!(g.calls_charged_worst_case(), 0);
        assert!((g.spent_usd() - 0.00091).abs() < 1e-12);
    }

    #[test]
    fn settle_clamps_cached_above_input() {
        let g = guard(1.0);
        let w = g.reserve("m", 0, 0).unwrap();
        // cached clamped to input = 10: 10 * 0.1 = 1, not 50 * 0.1 = 5.
        let (c, _) = g.settle("m", w, SettleOutcome::Usage(usage(10, 50, 0)));
        assert_eq!(c, 1);
        assert_eq!(g.spent_micro(), 1);
    }

    #[test]
    fn settle_usage_may_exceed_reservation_and_is_charged_in_full() {
        let g = guard(1.0);
        let w = g.reserve("m", 744, 10).unwrap(); // 1000 + 100
        let u = usage(5000, 0, 20);
        assert!(SpendGuard::over_cap(&u, 10));
        assert!(!SpendGuard::over_cap(&usage(0, 0, 10), 10));
        let (c, _) = g.settle("m", w, SettleOutcome::Usage(u));
        assert_eq!(c, 5200);
        assert_eq!(g.spent_micro(), 5200);
        assert!(g.is_tripped());
    }

    #[test]
    fn missing_usage_keeps_worst_case_and_counts() {
        let g = guard(1.0);
        let w = g.reserve("m", 744, 100).unwrap();
        let (c, tag) = g.settle("m", w, SettleOutcome::MissingAfterResponse);
        assert_eq!((c, tag), (2000, "charged_worst_case"));
        assert_eq!(g.spent_micro(), 2000);
        assert_eq!(g.calls_charged_worst_case(), 1);
    }

    #[test]
    fn rejected_before_inference_refunds() {
        let g = guard(1.0);
        let w = g.reserve("m", 744, 100).unwrap();
        let (c, tag) = g.settle("m", w, SettleOutcome::RejectedBeforeInference);
        assert_eq!((c, tag), (0, "provider"));
        assert_eq!(g.spent_micro(), 0);
        assert_eq!(g.calls_charged_worst_case(), 0);
    }

    #[test]
    fn settle_cannot_refund_more_than_was_reserved() {
        let g = guard(1.0);
        let w = g.reserve("m", 744, 100).unwrap();
        g.settle("m", w, SettleOutcome::MissingAfterResponse);
        // A bogus second settle of a huge reservation releases nothing.
        g.settle("m", 1_000_000, SettleOutcome::RejectedBeforeInference);
        assert_eq!(g.spent_micro(), 2000);
    }

    #[test]
    fn dropped_reservation_is_charged_worst_case() {
        let g = guard(1.0);
        let w = g.reserve("m", 744, 100).unwrap();
        drop(Reservation::new(&g, "m".into(), w));
        assert_eq!(g.spent_micro(), 2000);
        assert_eq!(g.calls_charged_worst_case(), 1);
        let w = g.reserve("m", 744, 100).unwrap();
        let (c, _) =
            Reservation::new(&g, "m".into(), w).settle(SettleOutcome::RejectedBeforeInference);
        assert_eq!(c, 0);
        assert_eq!(g.spent_micro(), 2000);
        assert_eq!(g.calls_charged_worst_case(), 1);
    }

    #[test]
    fn unknown_model_has_no_price() {
        let g = guard(1.0);
        assert_eq!(
            g.reserve("other", 1, 1),
            Err(SpendRefusal::NoPrice("other".into()))
        );
        assert!(
            SpendRefusal::NoPrice("other".into())
                .to_string()
                .starts_with("no price for model")
        );
        assert_eq!(SpendRefusal::CapReached.to_string(), "spend cap reached");
        assert_eq!(g.spent_micro(), 0);
    }
}
