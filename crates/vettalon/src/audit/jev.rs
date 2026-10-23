//! Optional metadata-only module ranker (TypeSafe Jev).
//!
//! Jev reorders which modules a deep scan audits first, using ONLY metadata
//! (paths, byte sizes, entry-point flag, git touch counts) — never file
//! contents. It never replaces the finder/verifier models; it only changes
//! dispatch order so a high-value file lands inside the `--max-modules`
//! budget. The benchmark that justified this is summarized at
//! <https://vettalon.dudustudio.monster/#benchmarks>.
//!
//! Safety: this ranker sends metadata only when the operator passes `--rank jev`.
//! Before every ranking request, [`assert_metadata_only`] fails closed on
//! source-like payload fields. This boundary does not cover model providers:
//! deep finder/verifier/PoC prompts can send source to configured HTTP or CLI
//! providers. On ranking error the caller keeps the heuristic order
//! (see [`rerank`] returning `Err`).

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;
use serde_json::{Value, json};

use super::ai_audit::ModuleTarget;
use super::intake::RepoProfile;
use super::rank_snapshot::{FileFeatures, file_features, hotspot_index};
use crate::config::JevSettings;

/// Max characters any single string field in the payload may hold. A path is
/// far shorter; anything longer is a sign source text leaked in.
const PAYLOAD_MAX_FIELD_CHARS: usize = 300;
/// A repo source line this long (with a space) appearing verbatim in the
/// payload is treated as a content leak. Mirrors the benchmark guard.
const LEAK_MIN_LINE: usize = 40;
/// Questions per request; stays well inside Jev's 64k-token context.
const JEV_BATCH: usize = 150;
const JEV_QUESTION: &str = "Is `file` likely to contain code that processes untrusted external input in a security-sensitive way (request handling, routing or static file serving, path or file access, command execution, eval or templating, deserialization, SQL, auth)?";

/// One metadata row as Jev sees it: the file's path plus numeric features.
struct Row {
    path: String,
    features: FileFeatures,
}

/// Build the metadata rows for every file in the ranked modules, in order.
fn rows(repo_root: &Path, profile: &RepoProfile, ranked: &[ModuleTarget]) -> Vec<Row> {
    let hotspots = hotspot_index(profile);
    let mut out = Vec::new();
    for m in ranked {
        for f in &m.files {
            out.push(Row {
                path: f.clone(),
                features: file_features(repo_root, profile, &hotspots, f),
            });
        }
    }
    out
}

/// The repo-level `state` object: language census and whether git history was
/// available. Metadata only.
fn state_value(profile: &RepoProfile) -> Value {
    let languages: Vec<Value> = profile
        .language_census
        .iter()
        .take(12)
        .map(|l| json!([l.extension, l.file_count]))
        .collect();
    json!({
        "languages": languages,
        "git_history_available": matches!(
            profile.git_history,
            super::intake::GitHistoryStatus::Available { .. }
        ),
    })
}

/// One Noul question body per file. Metadata is embedded as the question's
/// `instructions.file`; there is no file content anywhere in it.
fn file_question(r: &Row) -> Value {
    json!({
        "type": "noul",
        "instructions": {
            "file": {
                "path": r.features.path,
                "ext": r.features.ext,
                "bytes": r.features.bytes,
                "is_entry_point": r.features.is_entry_point,
                "security_touches": r.features.security_touches,
                "total_touches": r.features.total_touches,
            },
            "question": JEV_QUESTION,
        },
        "criteria": {
            "true": "Application or library code on an attacker-reachable path",
            "false": "Tests, examples, docs, build tooling, or code with no untrusted input",
        },
    })
}

/// Build the request bodies (batched). Each is `{state, model, questions}`
/// where `questions` maps `f<i>` to one file's Noul question.
fn request_bodies(profile: &RepoProfile, rows: &[Row], model: &str) -> Vec<Value> {
    let state = state_value(profile);
    let mut bodies = Vec::new();
    for chunk in rows.chunks(JEV_BATCH).collect::<Vec<_>>() {
        // Keep the global index in the question id so answers map back.
        let base = bodies.len() * JEV_BATCH;
        let mut questions = serde_json::Map::new();
        for (j, r) in chunk.iter().enumerate() {
            questions.insert(format!("f{}", base + j), file_question(r));
        }
        bodies.push(json!({ "state": state, "model": model, "questions": questions }));
    }
    bodies
}

/// Fail closed if `payload` could carry source text: any string field longer
/// than a path or holding a newline, or (when `repo_root` is given) any
/// non-trivial source line from `paths` appearing verbatim in the payload.
/// The last line of defense before anything leaves the machine.
pub fn assert_metadata_only(
    payload: &Value,
    repo_root: Option<&Path>,
    paths: &[String],
) -> Result<(), String> {
    fn walk(v: &Value) -> Result<(), String> {
        match v {
            Value::String(s) => {
                if s.chars().count() > PAYLOAD_MAX_FIELD_CHARS || s.contains('\n') {
                    let head: String = s.chars().take(80).collect();
                    return Err(format!("payload string too long / multi-line: {head:?}"));
                }
                Ok(())
            }
            Value::Array(a) => a.iter().try_for_each(walk),
            Value::Object(o) => o.iter().try_for_each(|(k, x)| {
                if k.chars().count() > PAYLOAD_MAX_FIELD_CHARS {
                    return Err(format!("payload key too long: {k:?}"));
                }
                walk(x)
            }),
            _ => Ok(()),
        }
    }
    walk(payload)?;
    let Some(root) = repo_root else {
        return Ok(());
    };
    let blob = serde_json::to_string(payload).unwrap_or_default();
    for rel in paths {
        let Ok(text) = std::fs::read_to_string(root.join(rel)) else {
            continue;
        };
        for line in text.lines() {
            let s = line.trim();
            if s.chars().count() >= LEAK_MIN_LINE && s.contains(' ') && blob.contains(s) {
                let head: String = s.chars().take(80).collect();
                return Err(format!(
                    "source text from {rel} leaked into payload: {head:?}"
                ));
            }
        }
    }
    Ok(())
}

/// Reorder `ranked` by Jev's per-file scores: within each module, files with
/// a higher score come first (ties keep baseline order); modules are then
/// ordered by their highest-scoring file. Mirrors the benchmark's
/// `rerank_by_file_scores`. A file Jev did not score keeps score 0.
fn apply_scores(ranked: Vec<ModuleTarget>, scores: &HashMap<String, f64>) -> Vec<ModuleTarget> {
    let score = |f: &str| scores.get(f).copied().unwrap_or(0.0);
    let mut modules: Vec<ModuleTarget> = ranked
        .into_iter()
        .map(|mut m| {
            // Stable sort by -score keeps baseline order within equal scores.
            m.files.sort_by(|a, b| {
                score(b)
                    .partial_cmp(&score(a))
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            m
        })
        .collect();
    modules.sort_by(|a, b| {
        let ma = a.files.iter().map(|f| score(f)).fold(0.0_f64, f64::max);
        let mb = b.files.iter().map(|f| score(f)).fold(0.0_f64, f64::max);
        mb.partial_cmp(&ma).unwrap_or(std::cmp::Ordering::Equal)
    });
    modules
}

#[derive(Deserialize)]
struct JevAnswer {
    noul: Option<f64>,
}

#[derive(Deserialize)]
struct JevResponse {
    #[serde(default)]
    answers: HashMap<String, JevAnswer>,
}

/// Re-rank `ranked` with Jev. Returns the reordered modules, or `Err` (the
/// caller then keeps the heuristic order and prints a one-line notice). Only
/// metadata is sent, guarded by [`assert_metadata_only`] before each POST.
pub async fn rerank(
    repo_root: &Path,
    profile: &RepoProfile,
    ranked: Vec<ModuleTarget>,
    cfg: &JevSettings,
) -> Result<Vec<ModuleTarget>, String> {
    let http = client_builder(cfg.base_url())?
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    rerank_with_client(repo_root, profile, ranked, cfg, &http).await
}

/// Client policy is shared with local tests; production never adds test CAs.
fn client_builder(base: &str) -> Result<reqwest::ClientBuilder, String> {
    if !base.starts_with("https://") {
        return Err(format!("Jev base_url must be https://: {base}"));
    }
    // Pin the client to the configured host; refuse any redirect off it.
    let host = host_of(base).ok_or_else(|| format!("bad Jev base_url: {base}"))?;
    let host_for_policy = host.clone();
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::custom(move |a| {
            match a.url().host_str() {
                Some(h) if h == host_for_policy => a.follow(),
                _ => a.stop(),
            }
        }))
        .timeout(std::time::Duration::from_secs(30)))
}

/// Private transport seam; only in-module tests inject a CA-restricted client.
async fn rerank_with_client(
    repo_root: &Path,
    profile: &RepoProfile,
    ranked: Vec<ModuleTarget>,
    cfg: &JevSettings,
    http: &reqwest::Client,
) -> Result<Vec<ModuleTarget>, String> {
    let key = cfg.resolve_key()?;
    let base = cfg.base_url();
    if !base.starts_with("https://") {
        return Err(format!("Jev base_url must be https://: {base}"));
    }
    let endpoint = format!("{}/v1/systemone", base.trim_end_matches('/'));
    let rows = rows(repo_root, profile, &ranked);
    if rows.is_empty() {
        return Ok(ranked);
    }
    let paths: Vec<String> = rows.iter().map(|r| r.path.clone()).collect();

    let mut scores: HashMap<String, f64> = HashMap::new();
    for body in request_bodies(profile, &rows, cfg.model()) {
        // Guard every outbound body against content leakage, fail closed.
        assert_metadata_only(&body, Some(repo_root), &paths)?;
        let resp = http
            .post(&endpoint)
            .bearer_auth(&key)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("Jev request failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("Jev returned {}", resp.status()));
        }
        let parsed: JevResponse = resp
            .json()
            .await
            .map_err(|e| format!("Jev response parse failed: {e}"))?;
        for (qid, ans) in parsed.answers {
            if let (Some(idx), Some(noul)) = (qid.strip_prefix('f'), ans.noul)
                && let Ok(i) = idx.parse::<usize>()
                && let Some(p) = paths.get(i)
            {
                scores.insert(p.clone(), noul);
            }
        }
    }
    if scores.is_empty() {
        return Err("Jev scored no files".to_string());
    }
    Ok(apply_scores(ranked, &scores))
}

/// The host of an `https://host[:port]/...` URL.
fn host_of(url: &str) -> Option<String> {
    url.strip_prefix("https://")
        .map(|rest| rest.split(['/', ':']).next().unwrap_or("").to_string())
        .filter(|h| !h.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(path: &str, files: &[&str]) -> ModuleTarget {
        ModuleTarget {
            module_path: path.to_string(),
            score: 1,
            high_risk: false,
            files: files.iter().map(|f| f.to_string()).collect(),
        }
    }

    #[test]
    fn assert_metadata_only_rejects_source_lines_and_long_fields() {
        let dir = tempfile::tempdir().unwrap();
        let src = "fn transfer(amount: u64) { do_the_wire_transfer(amount, recipient) }";
        std::fs::write(dir.path().join("a.rs"), format!("{src}\n")).unwrap();
        let paths = vec!["a.rs".to_string()];

        // metadata-only payload passes
        let ok = json!({"files": [["a.rs", 42, 0, 0, 0]], "q": "short"});
        assert!(assert_metadata_only(&ok, Some(dir.path()), &paths).is_ok());

        // a real source line smuggled in fails closed
        let leak = json!({"instructions": src});
        let err = assert_metadata_only(&leak, Some(dir.path()), &paths).unwrap_err();
        assert!(err.contains("leaked"), "{err}");

        // an over-long field fails even without repo access
        let long = json!({"x": "z".repeat(PAYLOAD_MAX_FIELD_CHARS + 1)});
        assert!(assert_metadata_only(&long, None, &[]).is_err());
    }

    #[test]
    fn apply_scores_reorders_files_and_modules_by_score() {
        let ranked = vec![
            module("mod_a", &["a/low.rs", "a/high.rs"]),
            module("mod_b", &["b/mid.rs"]),
        ];
        let scores = HashMap::from([
            ("a/low.rs".to_string(), 0.1),
            ("a/high.rs".to_string(), 0.9),
            ("b/mid.rs".to_string(), 0.5),
        ]);
        let out = apply_scores(ranked, &scores);
        // mod_a has the highest-scoring file (0.9) -> first module
        assert_eq!(out[0].module_path, "mod_a");
        // within mod_a, high.rs (0.9) before low.rs (0.1)
        assert_eq!(out[0].files, vec!["a/high.rs", "a/low.rs"]);
        assert_eq!(out[1].module_path, "mod_b");
    }

    #[test]
    fn request_bodies_carry_only_metadata() {
        let profile = RepoProfile {
            language_census: vec![],
            entry_points: vec!["src/main.rs".to_string()],
            git_history: super::super::intake::GitHistoryStatus::Unavailable {
                reason: "no repo".to_string(),
            },
        };
        let rows = vec![Row {
            path: "src/main.rs".to_string(),
            features: FileFeatures {
                path: "src/main.rs".to_string(),
                ext: "rs".to_string(),
                bytes: 10,
                is_entry_point: true,
                security_touches: 0,
                total_touches: 0,
            },
        }];
        let bodies = request_bodies(&profile, &rows, "jev-latest");
        assert_eq!(bodies.len(), 1);
        // No field may hold a path longer than a path, and nothing holds code.
        assert!(assert_metadata_only(&bodies[0], None, &[]).is_ok());
        assert_eq!(bodies[0]["model"], "jev-latest");
    }

    /// Live test against the real Jev API. Ignored by default; run with
    /// `TYPESAFE_API_KEY=... cargo test -p vettalon --lib audit::jev -- --ignored`.
    /// Confirms a metadata-only payload is accepted and scores parse.
    #[tokio::test]
    #[ignore = "hits api.typesafe.ai; needs TYPESAFE_API_KEY"]
    async fn jev_live_scores_files() {
        let Ok(_) = std::env::var("TYPESAFE_API_KEY") else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(
            dir.path().join("src/main.rs"),
            "fn main() { route(req) }
",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("src/util.rs"),
            "fn add(a: u8, b: u8) -> u8 { a + b }
",
        )
        .unwrap();
        let profile = crate::audit::intake::build_profile(dir.path()).await;
        let ranked = crate::audit::rank_snapshot::ranked_modules(dir.path(), &profile);
        let cfg = JevSettings {
            api_key_env: Some("TYPESAFE_API_KEY".to_string()),
            api_key_file: None,
            base_url: None,
            model: None,
            api_key: None,
        };
        let out = rerank(dir.path(), &profile, ranked.clone(), &cfg)
            .await
            .expect("live Jev rerank");
        // Same modules, possibly reordered; nothing dropped or added.
        let before: std::collections::BTreeSet<_> =
            ranked.iter().map(|m| m.module_path.clone()).collect();
        let after: std::collections::BTreeSet<_> =
            out.iter().map(|m| m.module_path.clone()).collect();
        assert_eq!(before, after);
    }

    #[test]
    fn host_of_extracts_host() {
        assert_eq!(
            host_of("https://api.typesafe.ai").as_deref(),
            Some("api.typesafe.ai")
        );
        assert_eq!(
            host_of("https://api.typesafe.ai:443/v1").as_deref(),
            Some("api.typesafe.ai")
        );
        assert_eq!(host_of("http://api.typesafe.ai"), None);
    }
}

#[cfg(test)]
#[path = "jev_transport_tests.rs"]
mod transport_tests;
