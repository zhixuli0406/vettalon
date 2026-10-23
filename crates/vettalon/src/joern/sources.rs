//! Fixed source patterns for the keep-path template, per Joern frontend.
//!
//! These are the only "source" definitions the template ever sees. They are
//! constants of this binary: no model, finding or claim can add one. Each
//! pattern must match a whole name or code text (Java `matches()`), so an
//! enclosing call such as `intval($_GET['id'])` is not itself a source.
//!
//! Tuning happens on the S3 development split only (docs/EVAL-PROTOCOL.md);
//! a change bumps [`SOURCES_VERSION`], which every evidence line records.

use super::JoernLang;

/// Recorded on every `joern_path:` line and in `joern check` output.
pub const SOURCES_VERSION: &str = "sources-v1";

/// What a pattern is matched against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    /// The called method's name (`getParameter`, `recv`).
    CallName,
    /// An identifier's name (`_GET` for PHP's `$_GET`, `argv`).
    IdentName,
    /// A call's full code text, field accesses included (`request.args`).
    CallCode,
}

impl SourceKind {
    pub fn token(self) -> &'static str {
        match self {
            SourceKind::CallName => "call_name",
            SourceKind::IdentName => "ident_name",
            SourceKind::CallCode => "call_code",
        }
    }
}

/// One source pattern (a Java/Rust-compatible regex, whole-match).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourcePattern {
    pub kind: SourceKind,
    pub pattern: &'static str,
}

const fn p(kind: SourceKind, pattern: &'static str) -> SourcePattern {
    SourcePattern { kind, pattern }
}

use SourceKind::{CallCode, CallName, IdentName};

const PHP: &[SourcePattern] = &[
    // php2cpg models `$_GET["id"]` as an `<operator>.indexAccess` call; the
    // smoke test found no flow from the bare `_GET` identifier through it,
    // so the index access itself is the source.
    p(CallCode, r"\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\[.*\]"),
    p(IdentName, r"_(GET|POST|REQUEST|COOKIE|FILES|SERVER)"),
    p(
        CallCode,
        r#"file_get_contents\(\s*["']php://input["']\s*\)"#,
    ),
];

const PYTHON: &[SourcePattern] = &[
    p(
        CallCode,
        r"(flask\.)?request\.(args|form|values|files|cookies|headers|data|json|get_json\(\)|GET|POST|FILES|COOKIES|META|body|query_params|path_params)",
    ),
    p(CallCode, r"sys\.argv"),
    p(CallName, r"input"),
];

const JSSRC: &[SourcePattern] = &[
    p(
        CallCode,
        r"(req|request|ctx|ctx\.request)\.(query|body|params|headers|cookies|url|originalUrl|path|files|file|rawBody)",
    ),
    p(CallCode, r"process\.argv"),
    p(
        CallCode,
        r"((window|document)\.)?location\.(search|hash|href|pathname)",
    ),
    p(CallCode, r"document\.(URL|documentURI|cookie|referrer)"),
];

const GOLANG: &[SourcePattern] = &[
    p(
        CallName,
        r"FormValue|PostFormValue|FormFile|PathValue|GetHeader|DefaultQuery|PostForm|DefaultPostForm|QueryParam|FormParams",
    ),
    p(CallCode, r"[A-Za-z_][A-Za-z0-9_.]*\.URL\.Query\(\)"),
    p(CallCode, r"[A-Za-z_][A-Za-z0-9_.]*\.Body"),
    p(CallCode, r"os\.Args"),
];

const JAVA: &[SourcePattern] = &[p(
    CallName,
    r"getParameter|getParameterValues|getParameterMap|getParameterNames|getHeader|getHeaders|getHeaderNames|getCookies|getQueryString|getInputStream|getReader|getRequestURI|getRequestURL|getPathInfo|getPart|getParts",
)];

const C: &[SourcePattern] = &[
    p(
        CallName,
        r"getenv|recv|recvfrom|recvmsg|read|fread|fgets|gets|scanf|fscanf|sscanf|getline|getc|fgetc|getchar",
    ),
    p(IdentName, r"argv"),
];

const RUBY: &[SourcePattern] = &[
    p(CallCode, r"params(\[[^\]]*\])?"),
    p(
        CallCode,
        r"request\.(params|query_string|body|headers|cookies|env|path|url|fullpath|raw_post)",
    ),
    p(IdentName, r"ARGV"),
];

const CSHARPSRC: &[SourcePattern] = &[
    p(
        CallCode,
        r"([A-Za-z_][A-Za-z0-9_]*\.)*Request\.(Query|Form|Headers|Cookies|Body|Path|QueryString|RouteValues)",
    ),
    p(CallName, r"GetEnvironmentVariable"),
];

/// The fixed source set for one frontend.
pub fn sources_for(lang: JoernLang) -> &'static [SourcePattern] {
    match lang {
        JoernLang::Php => PHP,
        JoernLang::Python => PYTHON,
        JoernLang::JsSrc => JSSRC,
        JoernLang::Golang => GOLANG,
        JoernLang::Java => JAVA,
        JoernLang::C => C,
        JoernLang::Ruby => RUBY,
        JoernLang::CSharpSrc => CSHARPSRC,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pattern_compiles_and_is_one_params_field() {
        for lang in JoernLang::ALL {
            let set = sources_for(lang);
            assert!(!set.is_empty(), "{lang:?}");
            for s in set {
                // The template uses java.util.regex; these patterns use only
                // syntax both engines read the same way.
                regex::Regex::new(&format!("^(?:{})$", s.pattern)).unwrap();
                assert!(!s.pattern.contains(['\t', '\n', '\r']), "{}", s.pattern);
            }
        }
    }

    fn whole(set: &[SourcePattern], kind: SourceKind, text: &str) -> bool {
        set.iter().any(|s| {
            s.kind == kind
                && regex::Regex::new(&format!("^(?:{})$", s.pattern))
                    .unwrap()
                    .is_match(text)
        })
    }

    #[test]
    fn patterns_match_whole_text_only() {
        assert!(whole(PHP, IdentName, "_GET"));
        assert!(!whole(PHP, IdentName, "_GETX"));
        assert!(whole(PYTHON, CallCode, "request.args"));
        // A wrapping (possibly sanitizing) call is not itself a source.
        assert!(!whole(PYTHON, CallCode, "int(request.args)"));
        assert!(whole(JAVA, CallName, "getParameter"));
        assert!(!whole(JAVA, CallName, "getParameterX"));
        assert!(whole(GOLANG, CallCode, "r.URL.Query()"));
        assert!(!whole(GOLANG, CallCode, "db.Query(q)"));
        assert!(whole(C, IdentName, "argv"));
        assert!(whole(RUBY, CallCode, "params[:id]"));
        assert!(whole(CSHARPSRC, CallCode, "HttpContext.Request.Query"));
    }
}
