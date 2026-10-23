//! `vettalon joern check`: ask the keep-path template about a claims file
//! against one source tree, with no model call and no verdict. The offline
//! S3 evaluation applies these answers to stored refuter replies.

use std::path::Path;

use serde::Serialize;

use super::keep::JoernVerdict;
use super::run::{ItemCheck, JoernSettings, LangRun, check_items};
use super::{JOERN_VERSION, JoernLang, SOURCES_VERSION, TEMPLATE_ID};

pub const CHECK_SCHEMA: &str = "vettalon.joern-check/1";
/// Most claims one `joern check` accepts.
pub const MAX_CHECK_CLAIMS: usize = 10_000;

#[derive(Debug, Serialize)]
pub struct CheckResult {
    pub id: String,
    pub file: String,
    pub line: Option<u32>,
    pub lang: Option<JoernLang>,
    pub verdict: JoernVerdict,
}

#[derive(Debug, Serialize)]
pub struct CheckOutput {
    pub schema: &'static str,
    pub joern: &'static str,
    pub template: &'static str,
    pub sources: &'static str,
    pub image: String,
    pub timeout_secs: u64,
    pub results: Vec<CheckResult>,
    pub runs: Vec<LangRun>,
}

/// One claim to check: `(id, file, line)`.
pub type ClaimRef = (String, String, Option<u32>);

pub async fn check_claims(
    src: &Path,
    claims: &[ClaimRef],
    s: &JoernSettings,
) -> Result<CheckOutput, String> {
    if claims.len() > MAX_CHECK_CLAIMS {
        return Err(format!(
            "{} claims; `joern check` takes at most {MAX_CHECK_CLAIMS}",
            claims.len()
        ));
    }
    let items: Vec<ItemCheck> = claims
        .iter()
        .map(|(_, file, line)| ItemCheck {
            file: file.clone(),
            line: *line,
        })
        .collect();
    let (verdicts, runs) = check_items(src, &items, s).await;
    let results = claims
        .iter()
        .zip(verdicts)
        .map(|((id, file, line), verdict)| CheckResult {
            id: id.clone(),
            file: file.clone(),
            line: *line,
            lang: JoernLang::from_path(file),
            verdict,
        })
        .collect();
    Ok(CheckOutput {
        schema: CHECK_SCHEMA,
        joern: JOERN_VERSION,
        template: TEMPLATE_ID,
        sources: SOURCES_VERSION,
        image: s.image.clone(),
        timeout_secs: s.timeout_secs,
        results,
        runs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::joern::KeepRule;

    #[tokio::test]
    async fn output_names_every_claim_in_order() {
        let s = JoernSettings {
            image: "vettalon-joern:missing-in-tests".into(),
            timeout_secs: 30,
            rule: KeepRule::Strict,
        };
        let claims = vec![
            ("a".to_string(), "README.md".to_string(), Some(1)),
            ("b".to_string(), "x/../y.php".to_string(), Some(2)),
        ];
        let out = check_claims(Path::new("/nonexistent"), &claims, &s)
            .await
            .unwrap();
        let v = serde_json::to_value(&out).unwrap();
        assert_eq!(v["schema"], CHECK_SCHEMA);
        assert_eq!(v["results"][0]["id"], "a");
        assert_eq!(v["results"][0]["verdict"]["kind"], "skipped");
        assert_eq!(v["results"][1]["lang"], "php");
        assert_eq!(v["results"][1]["verdict"]["kind"], "skipped");
        assert!(v["runs"].as_array().unwrap().is_empty());
        let too_many = vec![("x".to_string(), "a.php".to_string(), Some(1)); MAX_CHECK_CLAIMS + 1];
        assert!(check_claims(Path::new("/x"), &too_many, &s).await.is_err());
    }
}
