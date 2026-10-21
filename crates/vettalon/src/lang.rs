//! Language of human-facing terminal text (summaries, hints, errors).
//!
//! Only text printed for a person follows this setting. Data written into
//! reports (exploitability labels, knowledge-base text, carried-over notes),
//! prompts sent to models and detection patterns are never translated, so a
//! report means the same thing whichever language produced it.
//!
//! The library default is Traditional Chinese, which keeps the behaviour of
//! embedders that never call [`set`]. The `vettalon` CLI calls [`set`] once
//! at startup with [`detect`]; the Pro dashboard and desktop app call it
//! whenever their UI language changes (Japanese maps to English).

use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    ZhTw,
    En,
}

impl Lang {
    fn as_u8(self) -> u8 {
        match self {
            Lang::ZhTw => 0,
            Lang::En => 1,
        }
    }

    fn from_u8(v: u8) -> Lang {
        if v == 1 { Lang::En } else { Lang::ZhTw }
    }
}

static CURRENT: AtomicU8 = AtomicU8::new(0);

#[cfg(test)]
thread_local! {
    // Tests run in parallel; an override per thread keeps them independent.
    static TEST_OVERRIDE: std::cell::Cell<Option<Lang>> = const { std::cell::Cell::new(None) };
}

/// Set the language for the rest of the process.
pub fn set(lang: Lang) {
    CURRENT.store(lang.as_u8(), Ordering::Relaxed);
}

/// The language terminal text is rendered in.
pub fn get() -> Lang {
    #[cfg(test)]
    if let Some(l) = TEST_OVERRIDE.with(|c| c.get()) {
        return l;
    }
    Lang::from_u8(CURRENT.load(Ordering::Relaxed))
}

/// Run `f` with `lang` on this thread only (tests).
#[cfg(test)]
pub fn with<T>(lang: Lang, f: impl FnOnce() -> T) -> T {
    let prev = TEST_OVERRIDE.with(|c| c.replace(Some(lang)));
    let out = f();
    TEST_OVERRIDE.with(|c| c.set(prev));
    out
}

/// Parse a `--lang` value or a locale string (`en`, `zh-TW`, `zh_TW.UTF-8`).
/// Any Chinese locale maps to Traditional Chinese, the only Chinese
/// translation; other recognised languages fall back to English.
pub fn parse(value: &str) -> Option<Lang> {
    let v = value.trim().to_ascii_lowercase();
    if v.is_empty() || v == "c" || v == "posix" || v.starts_with("c.") {
        return None;
    }
    if v.starts_with("zh") {
        Some(Lang::ZhTw)
    } else if v.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) {
        Some(Lang::En)
    } else {
        None
    }
}

/// `--lang` first, then `VETTALON_LANG`, then the POSIX locale variables in
/// their precedence order (`LC_ALL`, `LC_MESSAGES`, `LANG`). English when
/// nothing says otherwise.
pub fn detect(flag: Option<&str>) -> Lang {
    detect_from(flag, |k| std::env::var(k).ok())
}

fn detect_from(flag: Option<&str>, env: impl Fn(&str) -> Option<String>) -> Lang {
    if let Some(l) = flag.and_then(parse) {
        return l;
    }
    ["VETTALON_LANG", "LC_ALL", "LC_MESSAGES", "LANG"]
        .iter()
        .find_map(|k| env(k).as_deref().and_then(parse))
        .unwrap_or(Lang::En)
}

/// Pick a static string for the current language.
pub fn pick(zh: &'static str, en: &'static str) -> &'static str {
    match get() {
        Lang::ZhTw => zh,
        Lang::En => en,
    }
}

/// `format!` in the current language: `tr!("中文 {x}", "English {x}")`.
/// Both strings must use the same arguments.
#[macro_export]
macro_rules! tr {
    ($zh:literal, $en:literal $(,)?) => {
        match $crate::lang::get() {
            $crate::lang::Lang::ZhTw => format!($zh),
            $crate::lang::Lang::En => format!($en),
        }
    };
    ($zh:literal, $en:literal, $($arg:expr),+ $(,)?) => {
        match $crate::lang::get() {
            $crate::lang::Lang::ZhTw => format!($zh, $($arg),+),
            $crate::lang::Lang::En => format!($en, $($arg),+),
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn parse_accepts_flags_and_locales() {
        assert_eq!(parse("en"), Some(Lang::En));
        assert_eq!(parse("zh-TW"), Some(Lang::ZhTw));
        assert_eq!(parse("zh_TW.UTF-8"), Some(Lang::ZhTw));
        assert_eq!(parse("zh_CN.UTF-8"), Some(Lang::ZhTw));
        assert_eq!(parse("ja_JP.UTF-8"), Some(Lang::En));
        assert_eq!(parse("C"), None);
        assert_eq!(parse("C.UTF-8"), None);
        assert_eq!(parse("POSIX"), None);
        assert_eq!(parse(""), None);
    }

    #[test]
    fn detect_prefers_flag_then_vettalon_lang_then_locale() {
        let env = env_of(&[("VETTALON_LANG", "zh-TW"), ("LANG", "en_US.UTF-8")]);
        assert_eq!(detect_from(Some("en"), &env), Lang::En);
        assert_eq!(detect_from(None, &env), Lang::ZhTw);
        let env = env_of(&[("LC_ALL", "zh_TW.UTF-8"), ("LANG", "en_US.UTF-8")]);
        assert_eq!(detect_from(None, env), Lang::ZhTw);
    }

    #[test]
    fn detect_skips_c_locale_and_defaults_to_english() {
        assert_eq!(
            detect_from(None, env_of(&[("LC_ALL", "C"), ("LANG", "zh_TW.UTF-8")])),
            Lang::ZhTw
        );
        assert_eq!(detect_from(None, env_of(&[])), Lang::En);
        assert_eq!(
            detect_from(Some("bogus-1"), env_of(&[("LANG", "zh_TW")])),
            Lang::En
        );
    }

    #[test]
    fn with_overrides_only_this_thread() {
        assert_eq!(with(Lang::En, || pick("中", "en")), "en");
        assert_eq!(with(Lang::ZhTw, || tr!("中 {}", "en {}", 1)), "中 1");
    }
}
