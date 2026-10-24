//! Bounded manual transport acceptance: Python/openssl are not CI prerequisites.
use super::*;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const SOURCE: &str = "def fixture(value):\n    return 'JEV_TLS_SYNTHETIC_SOURCE_MARKER_NEVER_SEND_SOURCE_0123456789' + value\n";
const SERVER: &str = r#"
import http.server, json, pathlib, socket, ssl, subprocess, sys, time
root = pathlib.Path(sys.argv[1])
def openssl(*args):
    subprocess.run(['openssl', *args], cwd=root, check=True, capture_output=True, timeout=10)
openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.pem','-days','1','-subj','/CN=Vettalon disposable test CA','-addext','basicConstraints=critical,CA:TRUE')
openssl('req','-newkey','rsa:2048','-nodes','-keyout','server.key','-out','server.csr','-subj','/CN=localhost')
(root/'ext.cnf').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n')
openssl('x509','-req','-in','server.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-out','server.pem','-days','1','-extfile','ext.cnf')
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(root/'server.pem',root/'server.key')
def record(value):
    with (root/'events.jsonl').open('a') as stream: stream.write(json.dumps(value)+'\n')
class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        size=int(self.headers.get('Content-Length','0'))
        if size>200000: self.send_error(413); return
        body=self.rfile.read(size)
        record(dict(kind='request',path=self.path,body=json.loads(body),authorization=self.headers.get('Authorization'),tls=self.connection.version()))
        mode=(root/'mode').read_text()
        status=503 if mode=='error' else 200
        response=b'not-json' if mode=='malformed' else b'{"answers":{"f0":{"noul":0.1},"f1":{"noul":0.9}}}'
        self.send_response(status); self.send_header('Content-Length',str(len(response))); self.send_header('Content-Type','application/json'); self.end_headers(); self.wfile.write(response)
    def log_message(self,*args): pass
class Server(http.server.HTTPServer):
    attempts=0
    def get_request(self):
        raw,address=self.socket.accept(); raw.settimeout(2); self.attempts+=1
        try: return context.wrap_socket(raw,server_side=True),address
        except ssl.SSLError:
            raw.close(); record(dict(kind='tls_rejected')); raise
server=Server(('127.0.0.1',0),Handler); server.timeout=0.1
(root/'ready').write_text(str(server.server_port))
deadline=time.monotonic()+60
while time.monotonic()<deadline and server.attempts<6 and not (root/'stop').exists(): server.handle_request()
server.server_close()
"#;

struct Loopback {
    root: tempfile::TempDir,
    child: Child,
    base: String,
}
impl Drop for Loopback {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Loopback {
    fn start() -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("server.py"), SERVER).unwrap();
        std::fs::write(root.path().join("mode"), "success").unwrap();
        let child = Command::new("python3")
            .args(["-I", "-S"])
            .arg(root.path().join("server.py"))
            .arg(root.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("manual acceptance requires python3 and openssl");
        let mut server = Self {
            root,
            child,
            base: String::new(),
        };
        let deadline = Instant::now() + Duration::from_secs(35);
        loop {
            if let Ok(port) = std::fs::read_to_string(server.root.path().join("ready")) {
                server.base = format!("https://localhost:{port}");
                break;
            }
            assert!(
                server.child.try_wait().unwrap().is_none(),
                "TLS helper exited before ready"
            );
            assert!(Instant::now() < deadline, "TLS helper startup timeout");
            std::thread::sleep(Duration::from_millis(20));
        }
        server
    }
    fn events(&self) -> Vec<Value> {
        std::fs::read_to_string(self.root.path().join("events.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
    fn trusted_client(&self) -> reqwest::Client {
        let ca = std::fs::read(self.root.path().join("ca.pem")).unwrap();
        client_builder(&self.base)
            .unwrap()
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest::Certificate::from_pem(&ca).unwrap())
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap()
    }
    fn config(&self) -> JevSettings {
        let path = self.root.path().join("dummy-key");
        std::fs::write(&path, "synthetic-key-not-real").unwrap();
        crate::util::set_owner_only(&path).unwrap();
        JevSettings {
            api_key_env: None,
            api_key_file: Some(path),
            base_url: Some(self.base.clone()),
            model: Some("fixture".into()),
            api_key: None,
        }
    }
}

fn opts(repo: &Path, rank: crate::audit::RankStrategy) -> crate::audit::ScanOptions {
    crate::audit::ScanOptions {
        repo_path: repo.into(),
        profile: "deep".into(),
        report: None,
        sarif: None,
        cyclonedx: None,
        fail_on: "none".into(),
        gates: vec![],
        max_modules: 2,
        poc: false,
        poc_image: crate::sandbox::DEFAULT_POC_IMAGE.into(),
        save: false,
        cross_check_top: 0,
        dual_finder_top: 0,
        fail_on_needs_human: false,
        no_prior: true,
        rank,
        trace: None,
        source_receipts: false,
        time_budget: Some(Duration::from_secs(5)),
        refuter_runs: 1,
        finder_parse_retries: crate::audit::DEFAULT_FINDER_PARSE_RETRIES,
        verifier_parse_retries: crate::audit::DEFAULT_VERIFIER_PARSE_RETRIES,
        refuter_policy: crate::audit::RefuterPolicy::CURRENT,
        refuter_score: false,
        refuter_score_threshold: None,
        prescreen: None,
        role_caps: Default::default(),
        fix_test_command: None,
        finders: vec![],
        verifiers: vec![],
        poc_models: vec![],
        roster: vec![],
    }
}

#[tokio::test]
#[ignore = "manual loopback TLS acceptance; requires python3 and openssl; no external calls"]
async fn tls_metadata_opt_in_and_explicit_fallback() {
    let server = Loopback::start();
    let repo = tempfile::tempdir().unwrap();
    std::fs::write(repo.path().join("first.py"), SOURCE).unwrap();
    std::fs::write(
        repo.path().join("second.py"),
        "def add(a, b):\n    return a + b\n",
    )
    .unwrap();
    let profile = crate::audit::intake::build_profile(repo.path()).await;
    let ranked = vec![
        ModuleTarget {
            module_path: "first".into(),
            score: 1,
            high_risk: false,
            files: vec!["first.py".into()],
        },
        ModuleTarget {
            module_path: "second".into(),
            score: 1,
            high_risk: false,
            files: vec!["second.py".into()],
        },
    ];
    let cfg = server.config();

    // Exercise the production audit dispatch decision, without scanners/models.
    for rank in [
        crate::audit::RankStrategy::default(),
        crate::audit::RankStrategy::Heuristic,
    ] {
        let step = crate::audit::run_audit_step(
            repo.path(),
            &opts(repo.path(), rank),
            &profile,
            crate::audit::AuditContext {
                refusals: &Default::default(),
                trace: &Default::default(),
                progress: &crate::audit::NoProgress,
                scan_deadline: None,
            },
        )
        .await;
        assert_eq!(step.ranker, "heuristic");
        assert!(!step.rank_degraded);
    }
    assert!(
        server.events().is_empty(),
        "non-opted-in audit contacted Jev"
    );

    // Production still rejects our untrusted CA; its real caller records fallback.
    let fallback = crate::audit::run_audit_step(
        repo.path(),
        &opts(repo.path(), crate::audit::RankStrategy::Jev(cfg.clone())),
        &profile,
        crate::audit::AuditContext {
            refusals: &Default::default(),
            trace: &Default::default(),
            progress: &crate::audit::NoProgress,
            scan_deadline: None,
        },
    )
    .await;
    assert_eq!(fallback.ranker, "jev");
    assert!(fallback.rank_degraded);
    assert!(
        !server
            .events()
            .iter()
            .any(|event| event["kind"] == "request")
    );

    // The receiver records TLS failure after the client observes its error.
    let capture_deadline = Instant::now() + Duration::from_secs(1);
    while !server
        .events()
        .iter()
        .any(|event| event["kind"] == "tls_rejected")
        && Instant::now() < capture_deadline
    {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        server
            .events()
            .iter()
            .any(|event| event["kind"] == "tls_rejected"),
        "production client did not reach test-CA TLS handshake; proxy/environment may have blocked it"
    );

    // Only this test client trusts the ephemeral test CA. No production toggle.
    let out = rerank_with_client(
        repo.path(),
        &profile,
        ranked.clone(),
        &cfg,
        &server.trusted_client(),
    )
    .await
    .unwrap();
    assert_eq!(out[0].module_path, "second");
    let captured = server.events();
    let requests: Vec<_> = captured
        .iter()
        .filter(|event| event["kind"] == "request")
        .collect();
    assert_eq!(requests.len(), 1);
    let received = requests[0];
    assert_eq!(received["path"], "/v1/systemone");
    assert!(received["tls"].as_str().unwrap().starts_with("TLS"));
    assert_eq!(received["authorization"], "Bearer synthetic-key-not-real");
    assert!(
        !received
            .to_string()
            .contains("JEV_TLS_SYNTHETIC_SOURCE_MARKER")
    );
    assert_metadata_only(
        &received["body"],
        Some(repo.path()),
        &["first.py".into(), "second.py".into()],
    )
    .unwrap();
    let file = received["body"]["questions"]["f0"]["instructions"]["file"]
        .as_object()
        .unwrap();
    let keys: std::collections::BTreeSet<_> = file.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        std::collections::BTreeSet::from([
            "path",
            "ext",
            "bytes",
            "is_entry_point",
            "security_touches",
            "total_touches"
        ])
    );
    let top_keys: std::collections::BTreeSet<_> = received["body"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        top_keys,
        std::collections::BTreeSet::from(["state", "model", "questions"])
    );
    assert_eq!(file["bytes"], SOURCE.len());
    assert_eq!(file["path"], "first.py");

    for (mode, expected) in [("error", "503"), ("malformed", "parse failed")] {
        std::fs::write(server.root.path().join("mode"), mode).unwrap();
        let error = rerank_with_client(
            repo.path(),
            &profile,
            ranked.clone(),
            &cfg,
            &server.trusted_client(),
        )
        .await
        .unwrap_err();
        assert!(error.contains(expected), "{error}");
    }
    let events = server.events();
    assert_eq!(
        events.iter().filter(|e| e["kind"] == "request").count(),
        3,
        "unexpected retries"
    );
    let result = json!({"kind":"synthetic-loopback-TLS-transport","default_and_heuristic_requests":0,"production_untrusted_ca_fallback":fallback.rank_degraded,"trusted_test_ca_requests":3,"metadata_only":true,"source_marker_absent":true,"http_503_and_parse_error_explicit":true,"real_provider_calls":0,"events":events,"boundary":"test CA is trusted only by an injected test client; not a live Jev-service or model-behavior test"});
    if let Some(dir) = std::env::var_os("VETTALON_TRANSPORT_EVIDENCE_DIR") {
        let dir = PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        use std::io::Write;
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join("jev-tls.json"))
            .expect("evidence output must not already exist");
        output
            .write_all(&serde_json::to_vec_pretty(&result).unwrap())
            .unwrap();
    }
    println!(
        "TLS metadata acceptance: default/heuristic=0, trusted POST=3, fallback=true, external providers=0"
    );
}
