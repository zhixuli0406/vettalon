#![cfg(unix)]
//! `vettalon verify --spend-cap-usd` end to end against a local mock
//! OpenAI-compatible server on 127.0.0.1. No real network, no real model.

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

const REFUTED: &str = r#"{"verdict":"refuted","reason":"not reachable","blockers":[],"validation_plan":{"local":null,"deployment":null},"refute_basis":"unreachable"}"#;
const KEY_VAR: &str = "VETTALON_C2_TEST_API_KEY";
const KEY: &str = "sk-test-LEAKCHECK-7f3a9c";
const MODEL: &str = "mock-model-1";

const CLAIMS: &str = r#"{"schema": "vettalon.claims/1", "claims": [
  {"id": "c1", "file": "src/app.py", "line": 3, "title": "command injection"}]}"#;

/// One request the mock received.
#[derive(Debug, Clone)]
struct Seen {
    path: String,
    /// Lower-cased header lines, `name: value`.
    headers: Vec<String>,
}

struct Mock {
    base_url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Mock {
    /// Serves `POST /v1/chat/completions` forever (until the test process
    /// exits). `with_usage` adds a `usage` block of 1000/100/1100 tokens.
    fn start(with_usage: bool) -> Mock {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (tx, rx) = std::sync::mpsc::channel();
        let seen2 = seen.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                tx.send(listener.local_addr().unwrap()).unwrap();
                loop {
                    let Ok((mut sock, _)) = listener.accept().await else {
                        continue;
                    };
                    let seen = seen2.clone();
                    tokio::spawn(async move {
                        let mut buf: Vec<u8> = Vec::new();
                        let mut chunk = [0u8; 4096];
                        let head_end = loop {
                            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                break p + 4;
                            }
                            match sock.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                            }
                        };
                        let head = String::from_utf8_lossy(&buf[..head_end]).to_lowercase();
                        let mut lines = head.lines();
                        let request_line = lines.next().unwrap_or("").to_string();
                        let headers: Vec<String> = lines
                            .filter(|l| !l.is_empty())
                            .map(str::to_string)
                            .collect();
                        let want: usize = headers
                            .iter()
                            .find_map(|h| h.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse().ok())
                            .unwrap_or(0);
                        while buf.len() < head_end + want {
                            match sock.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                            }
                        }
                        let path = request_line.split(' ').nth(1).unwrap_or("").to_string();
                        seen.lock().unwrap().push(Seen { path, headers });
                        let mut body = serde_json::json!({
                            "choices": [{
                                "index": 0,
                                "finish_reason": "stop",
                                "message": {"role": "assistant", "content": REFUTED}
                            }]
                        });
                        if with_usage {
                            body["usage"] = serde_json::json!({
                                "prompt_tokens": 1000,
                                "completion_tokens": 100,
                                "total_tokens": 1100
                            });
                        }
                        let body = body.to_string();
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = sock.write_all(resp.as_bytes()).await;
                        let _ = sock.shutdown().await;
                    });
                }
            });
        });
        let addr = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        Mock {
            base_url: format!("http://{addr}/v1"),
            seen,
        }
    }

    fn requests(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    repo: PathBuf,
    home: PathBuf,
    empty_path: PathBuf,
}

impl Fixture {
    /// `cli` selects a CLI-backed verifier instead of the HTTP one.
    fn new(mock: &Mock, cli: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        let home = dir.path().join("home");
        let empty_path = dir.path().join("empty-path");
        for d in [&repo, &home, &empty_path] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::create_dir(repo.join("src")).unwrap();
        std::fs::write(
            repo.join("src/app.py"),
            "import os\nq = input()\nos.system(q)\n",
        )
        .unwrap();
        let roster = if cli {
            let script = dir.path().join("verifier.sh");
            std::fs::write(
                &script,
                format!("/bin/cat > /dev/null\nprintf '%s' '{REFUTED}'\n"),
            )
            .unwrap();
            format!(
                "[[model]]\nid = \"checker\"\nbackend = \"cli\"\nfamily = \"test\"\nroles = [\"verifier\"]\nprogram = \"/bin/sh\"\nargs = [{}]\nprompt_via = \"stdin\"\nallow_agent_tools = true\n",
                serde_json::to_string(&script).unwrap()
            )
        } else {
            format!(
                "[[model]]\nid = \"checker\"\nbackend = \"openai\"\nfamily = \"test\"\nroles = [\"verifier\"]\nbase_url = \"{}\"\nmodel = \"{MODEL}\"\napi_key_env = \"{KEY_VAR}\"\n",
                mock.base_url
            )
        };
        std::fs::write(home.join("config.toml"), roster).unwrap();
        std::fs::write(home.join("claims.json"), CLAIMS).unwrap();
        std::fs::write(
            home.join("prices.json"),
            serde_json::json!({
                "schema": "vettalon.prices/1",
                "retrieved": "2026-11-12",
                "source": ["test"],
                "models": {MODEL: {"input": 2, "cached_input": 0.1, "output": 10}}
            })
            .to_string(),
        )
        .unwrap();
        Self {
            _dir: dir,
            repo,
            home,
            empty_path,
        }
    }

    fn out_path(&self) -> PathBuf {
        self.home.join("verify.json")
    }

    fn trace_path(&self) -> PathBuf {
        self.home.join("t.jsonl")
    }

    /// `key = None` removes the API key variable from the environment.
    fn run_with_key(&self, key: Option<&std::ffi::OsStr>, extra: &[&str]) -> Output {
        let _ = std::fs::remove_file(self.out_path());
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_vettalon"));
        match key {
            Some(k) => cmd.env(KEY_VAR, k),
            None => cmd.env_remove(KEY_VAR),
        };
        cmd.env("VETTALON_HOME", &self.home)
            .env("PATH", &self.empty_path)
            .env("NO_PROXY", "127.0.0.1,localhost")
            .env("no_proxy", "127.0.0.1,localhost")
            .env_remove("HTTP_PROXY")
            .env_remove("http_proxy")
            .env_remove("ALL_PROXY")
            .env_remove("all_proxy")
            .args(["--lang", "en", "verify"])
            .arg(&self.repo)
            .arg("--input")
            .arg(self.home.join("claims.json"))
            .args(["--verifier", "checker", "--config"])
            .arg(self.home.join("config.toml"))
            .arg("--out")
            .arg(self.out_path())
            .arg("--trace")
            .arg(self.trace_path())
            .args(extra)
            .output()
            .unwrap()
    }

    /// Run with the spend flags and the given cap.
    fn run_capped(&self, cap: &str, extra: &[&str]) -> Output {
        self.run_capped_with_key(Some(std::ffi::OsStr::new(KEY)), cap, extra)
    }

    fn run_capped_with_key(
        &self,
        key: Option<&std::ffi::OsStr>,
        cap: &str,
        extra: &[&str],
    ) -> Output {
        let prices = self.home.join("prices.json");
        let mut args: Vec<&str> = vec!["--spend-cap-usd", cap, "--price-table"];
        let prices = prices.to_str().unwrap().to_string();
        args.push(&prices);
        args.extend_from_slice(extra);
        self.run_with_key(key, &args)
    }

    fn verify_json(&self) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(self.out_path()).expect("verify.json written"))
            .unwrap()
    }

    fn trace(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(self.trace_path())
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn a_provider_reported_call_is_charged_from_its_usage() {
    let mock = Mock::start(true);
    let fx = Fixture::new(&mock, false);
    let o = fx.run_capped(
        "1",
        &["--refuter-runs", "1", "--verifier-parse-retries", "0"],
    );
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert_eq!(mock.requests().len(), 1);
    assert_eq!(mock.requests()[0].path, "/v1/chat/completions");
    let out = fx.verify_json();
    let spend = &out["spend"];
    assert_eq!(spend["cap_usd"].as_f64(), Some(1.0));
    let spent = spend["spent_usd"].as_f64().unwrap();
    assert!((spent - 0.003).abs() < 1e-6, "spent_usd = {spent}");
    assert_eq!(spend["calls_charged_worst_case"], 0);
    assert_eq!(out["findings"][0]["verification"][0]["verdict"], "refuted");
    let trace = fx.trace();
    assert_eq!(trace.len(), 1, "{trace:?}");
    let ev = &trace[0];
    assert_eq!(ev["outcome"], "ok");
    assert_eq!(ev["input_tokens"], 1000);
    assert_eq!(ev["output_tokens"], 100);
    assert_eq!(ev["usage"], "provider");
    assert_eq!(ev["cost_micro_usd"], 3000);
}

#[test]
fn a_cap_below_one_calls_worst_case_makes_no_request() {
    let mock = Mock::start(true);
    let fx = Fixture::new(&mock, false);
    let o = fx.run_capped(
        "0.000001",
        &["--refuter-runs", "1", "--verifier-parse-retries", "0"],
    );
    assert_eq!(mock.requests().len(), 0);
    // A completed run with unverified claims is not a usage error.
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let out = fx.verify_json();
    assert!(
        out["findings"][0]["verification"]
            .as_array()
            .is_none_or(|v| v.is_empty()),
        "{}",
        out["findings"][0]
    );
    assert_eq!(out["findings"][0]["status"], "candidate");
    assert_eq!(out["spend"]["spent_usd"].as_f64(), Some(0.0));
    let trace = fx.trace();
    assert!(!trace.is_empty());
    assert!(
        trace.iter().all(|e| e["outcome"] == "budget_refused"),
        "{trace:?}"
    );
}

#[test]
fn a_reply_without_usage_is_charged_the_worst_case() {
    let mock = Mock::start(false);
    let fx = Fixture::new(&mock, false);
    let o = fx.run_capped(
        "1",
        &["--refuter-runs", "1", "--verifier-parse-retries", "0"],
    );
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert_eq!(mock.requests().len(), 1);
    let out = fx.verify_json();
    assert_eq!(out["spend"]["calls_charged_worst_case"], 1);
    // The worst case (8192 output tokens at 10 USD/M plus the prompt) is far
    // above what a 1100-token call would have cost.
    assert!(out["spend"]["spent_usd"].as_f64().unwrap() > 0.01);
    let trace = fx.trace();
    assert_eq!(trace.len(), 1, "{trace:?}");
    assert_eq!(trace[0]["usage"], "charged_worst_case");
}

#[test]
fn refuter_runs_all_severities_makes_every_run_for_a_medium_claim() {
    let mock = Mock::start(true);
    let fx = Fixture::new(&mock, false);
    let o = fx.run_capped(
        "1",
        &[
            "--refuter-runs",
            "3",
            "--refuter-runs-all-severities",
            "--verifier-parse-retries",
            "0",
        ],
    );
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert_eq!(mock.requests().len(), 3);
    let out = fx.verify_json();
    assert_eq!(out["refuter_runs_all_severities"], true);
    let spent = out["spend"]["spent_usd"].as_f64().unwrap();
    assert!((spent - 0.009).abs() < 1e-6, "spent_usd = {spent}");
    assert_eq!(fx.trace().len(), 3);
}

#[test]
fn the_api_key_goes_only_in_the_authorization_header() {
    let mock = Mock::start(true);
    let fx = Fixture::new(&mock, false);
    let o = fx.run_capped(
        "1",
        &[
            "--refuter-runs",
            "3",
            "--refuter-runs-all-severities",
            "--verifier-parse-retries",
            "0",
        ],
    );
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let reqs = mock.requests();
    assert!(!reqs.is_empty());
    let want = format!("authorization: bearer {}", KEY.to_lowercase());
    for r in &reqs {
        assert!(r.headers.contains(&want), "{:?}", r.headers);
    }
    let verify = std::fs::read_to_string(fx.out_path()).unwrap();
    let trace = std::fs::read_to_string(fx.trace_path()).unwrap();
    let stdout = String::from_utf8_lossy(&o.stdout);
    let stderr = stderr(&o);
    for (name, text) in [
        ("verify.json", verify.as_str()),
        ("trace", trace.as_str()),
        ("stdout", &stdout),
        ("stderr", &stderr),
    ] {
        assert!(!text.contains(KEY), "key leaked into {name}");
        assert!(
            !text.contains("LEAKCHECK"),
            "key fragment leaked into {name}"
        );
    }
}

#[test]
fn a_missing_or_empty_api_key_is_refused_before_any_call() {
    let mock = Mock::start(true);
    let fx = Fixture::new(&mock, false);
    for key in [None, Some("")] {
        let o =
            fx.run_capped_with_key(key.map(std::ffi::OsStr::new), "1", &["--refuter-runs", "1"]);
        assert_eq!(o.status.code(), Some(2), "key={key:?}: {}", stderr(&o));
        assert_eq!(mock.requests().len(), 0, "key={key:?}");
        assert!(!fx.out_path().exists(), "key={key:?}");
        let err = stderr(&o);
        assert!(err.contains(KEY_VAR), "{err}");
    }
}

#[cfg(unix)]
#[test]
fn a_non_utf8_api_key_is_refused_before_any_call() {
    use std::os::unix::ffi::OsStrExt;
    let mock = Mock::start(true);
    let fx = Fixture::new(&mock, false);
    let bad = std::ffi::OsStr::from_bytes(b"sk-\xff\xfe-bad");
    let o = fx.run_capped_with_key(Some(bad), "1", &["--refuter-runs", "1"]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert_eq!(mock.requests().len(), 0);
    assert!(!fx.out_path().exists());
    let err = stderr(&o);
    assert!(err.contains(KEY_VAR), "{err}");
    assert!(!err.contains("sk-"), "key value leaked: {err}");
}

#[test]
fn a_cli_verifier_cannot_be_metered_and_is_refused_before_any_call() {
    let mock = Mock::start(true);
    let fx = Fixture::new(&mock, true);
    let o = fx.run_capped("1", &["--refuter-runs", "1"]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert_eq!(mock.requests().len(), 0);
    assert!(!fx.out_path().exists());
}
