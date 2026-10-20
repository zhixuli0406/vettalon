//! Manual local-TLS and bounded public-fixture transport checks; no downloaded code is executed.
use super::{DependencyTarget, Ecosystem, fetch, osv, run};
use fetch::SourceFetcher;
use osv::OsvClient;
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha512};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const TLS_SERVER: &str = r#"
import http.server,json,pathlib,ssl,subprocess,sys,time
root=pathlib.Path(sys.argv[1])
def openssl(*args): subprocess.run(['openssl',*args],cwd=root,check=True,capture_output=True,timeout=10)
openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.pem','-days','1','-subj','/CN=Disposable hunt test CA','-addext','basicConstraints=critical,CA:TRUE')
openssl('req','-newkey','rsa:2048','-nodes','-keyout','server.key','-out','server.csr','-subj','/CN=api.osv.dev')
(root/'ext').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:api.osv.dev,DNS:crates.io,DNS:static.crates.io,DNS:registry.npmjs.org,DNS:evil.invalid\n')
openssl('x509','-req','-in','server.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-out','server.pem','-days','1','-extfile','ext')
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(root/'server.pem',root/'server.key')
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self): self.respond()
    def do_POST(self): self.respond()
    def respond(self):
        size=int(self.headers.get('Content-Length','0'))
        if size>200000: self.send_error(413);return
        body=self.rfile.read(size)
        event=dict(host=self.headers.get('Host'),path=self.path,method=self.command,body=json.loads(body) if body else None,tls=self.connection.version())
        with (root/'events').open('a') as stream:stream.write(json.dumps(event)+'\n')
        mode=(root/'mode').read_text();location=None
        if mode=='same' and self.path!='/final':location='https://api.osv.dev/final'
        if mode=='cdn' and self.headers.get('Host')=='crates.io':location='https://static.crates.io/archive'
        if mode=='escape':location='https://evil.invalid/final'
        if mode=='http':location='http://api.osv.dev/final'
        if mode=='port':location='https://api.osv.dev:444/final'
        if mode=='loop':location='https://api.osv.dev/v1/query'
        if mode=='registry-http':location='http://crates.io/archive'
        if mode=='registry-port':location='https://crates.io:444/archive'
        if mode=='registry-loop':location='https://crates.io/archive'
        if location:
            self.send_response(307);self.send_header('Location',location);self.send_header('Content-Length','0');self.end_headers();return
        if self.command=='GET': payload=(root/'archive.tgz').read_bytes()
        elif mode=='malformed':payload=b'not-json'
        else:
            vulns=[dict(id='SYNTHETIC-ADVISORY-NOT-REAL')] if mode=='matched' else []
            payload=json.dumps(dict(results=[dict(vulns=vulns)]) if self.path=='/v1/querybatch' else dict(vulns=vulns)).encode()
        self.send_response(200);self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload)
    def log_message(self,*args):pass
class Server(http.server.HTTPServer):
    def get_request(self):
        raw,address=self.socket.accept();raw.settimeout(2)
        return context.wrap_socket(raw,server_side=True),address
server=Server(('127.0.0.1',0),Handler);server.timeout=0.1
(root/'ready').write_text(str(server.server_port));deadline=time.monotonic()+60
while time.monotonic()<deadline:
    events=(root/'events').read_text().count('\n') if (root/'events').exists() else 0
    if events>=24:break
    server.handle_request()
server.server_close()
"#;

struct LocalTls {
    root: tempfile::TempDir,
    child: std::process::Child,
    addr: std::net::SocketAddr,
}
impl Drop for LocalTls {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl LocalTls {
    fn start() -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("server.py"), TLS_SERVER).unwrap();
        std::fs::write(root.path().join("mode"), "ok").unwrap();
        let mut archive = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        let data = b"Synthetic transport fixture, no security claim\n";
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o600);
        header.set_cksum();
        archive
            .append_data(&mut header, "fixture/source.txt", &data[..])
            .unwrap();
        std::fs::write(
            root.path().join("archive.tgz"),
            archive.into_inner().unwrap().finish().unwrap(),
        )
        .unwrap();
        let child = std::process::Command::new("python3")
            .args(["-I", "-S"])
            .arg(root.path().join("server.py"))
            .arg(root.path())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let mut server = Self {
            root,
            child,
            addr: "127.0.0.1:0".parse().unwrap(),
        };
        let deadline = Instant::now() + Duration::from_secs(35);
        loop {
            if let Ok(port) = std::fs::read_to_string(server.root.path().join("ready")) {
                server.addr = format!("127.0.0.1:{port}").parse().unwrap();
                break;
            }
            assert!(server.child.try_wait().unwrap().is_none());
            assert!(Instant::now() < deadline, "TLS startup deadline");
            std::thread::sleep(Duration::from_millis(20));
        }
        server
    }
    fn client(&self, builder: reqwest::ClientBuilder) -> reqwest::Client {
        let mut builder = builder
            .no_proxy()
            .tls_built_in_root_certs(false)
            .add_root_certificate(
                reqwest::Certificate::from_pem(
                    &std::fs::read(self.root.path().join("ca.pem")).unwrap(),
                )
                .unwrap(),
            )
            .timeout(Duration::from_secs(3));
        for host in [
            "api.osv.dev",
            "crates.io",
            "static.crates.io",
            "registry.npmjs.org",
            "evil.invalid",
        ] {
            builder = builder.resolve(host, self.addr);
        }
        builder.build().unwrap()
    }
    fn mode(&self, mode: &str) {
        std::fs::write(self.root.path().join("mode"), mode).unwrap();
    }
    fn events(&self) -> Vec<Value> {
        std::fs::read_to_string(self.root.path().join("events"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}
fn target(ecosystem: Ecosystem, name: &str, version: &str) -> DependencyTarget {
    DependencyTarget {
        ecosystem,
        name: name.into(),
        version: version.into(),
        direct: true,
    }
}
fn write_new(path: &Path, value: &Value) {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .expect("evidence must not exist");
    file.write_all(&serde_json::to_vec_pretty(value).unwrap())
        .unwrap();
}

#[tokio::test]
#[ignore = "manual local TLS registry/OSV redirects; Python3+openssl; zero external calls"]
async fn local_tls_hunt_transport_policies_and_osv_states() {
    let server = LocalTls::start();
    let client = osv::HttpOsvClient::for_transport_test(server.client(osv::osv_client_builder()));
    let t = target(Ecosystem::Npm, "synthetic-fixture", "1.0.0");
    for (mode, status) in [
        ("ok", osv::OsvStatus::Unmatched),
        ("matched", osv::OsvStatus::Matched),
        ("malformed", osv::OsvStatus::Failed),
    ] {
        server.mode(mode);
        let rows = osv::scan_known(std::slice::from_ref(&t), &client).await;
        assert_eq!(rows[0].osv.status, status);
    }
    server.mode("same");
    assert!(client.known_vulns(&t).await.unwrap().is_empty());
    for mode in ["escape", "http", "port", "loop"] {
        server.mode(mode);
        assert!(client.known_vulns(&t).await.is_err(), "{mode}");
    }
    assert!(!server.events().iter().any(|e| e["host"] == "evil.invalid"));
    server.mode("cdn");
    let fetcher = fetch::HttpSourceFetcher::for_transport_test(
        server.client(fetch::fetch_client_builder()),
        1024 * 1024,
        None,
    );
    let dir = tempfile::tempdir().unwrap();
    let stats = fetcher
        .fetch_into(&target(Ecosystem::Cargo, "fixture", "1.0.0"), dir.path())
        .await
        .unwrap();
    assert_eq!(stats.files, 1);
    assert!(dir.path().join("fixture/source.txt").exists());
    server.mode("escape");
    assert!(
        fetcher
            .fetch_into(&target(Ecosystem::Cargo, "fixture", "1.0.0"), dir.path())
            .await
            .is_err()
    );
    for mode in ["registry-http", "registry-port", "registry-loop"] {
        server.mode(mode);
        assert!(
            fetcher
                .fetch_into(&target(Ecosystem::Cargo, "fixture", "1.0.0"), dir.path())
                .await
                .is_err(),
            "{mode}"
        );
    }
    let before = server.events().len();
    assert!(
        server
            .client(fetch::fetch_client_builder())
            .get("http://crates.io/initial")
            .send()
            .await
            .is_err()
    );
    assert_eq!(server.events().len(), before);
    let events = server.events();
    assert!(events.len() <= 24);
    assert!(
        events
            .iter()
            .all(|e| e["tls"] == "TLSv1.3" || e["tls"] == "TLSv1.2")
    );
    assert_eq!(
        events[0]["body"]["queries"][0],
        json!({"version":"1.0.0","package":{"name":"synthetic-fixture","ecosystem":"npm"}})
    );
    if let Some(dir) = std::env::var_os("VETTALON_HUNT_TRANSPORT_EVIDENCE_DIR") {
        let dir = PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        write_new(
            &dir.join("local-tls.json"),
            &json!({"kind":"self-built-loopback-TLS","real_external_calls":0,"events":events,"osv_states":["matched","unmatched","failed"],"registry_https_cdn_redirect":true,"cross_host_downgrade_port_loop_blocked":true}),
        );
    }
}

const CARGO_HASH: &str = "4e7648175b45a9a48536d676f68d918270699102aa8dab5496df06904c914600";
const NPM_SRI: &str = "sha512-Wu1VHeILBK8KAWJUAiSZQX94GmOE45Rg6/538fKwiloUu21KncEkYGPqob2oSZ5mUT73vLGrHQjKw3KMPwfDzg==";
const NPM_SHA512: &str = "5aed551de20b04af0a016254022499417f781a6384e39460ebfe77f1f2b08a5a14bb6d4a9dc1246063eaa1bda8499e66513ef7bcb1ab1d08cac3728c3f07c3ce";

fn pinned_targets() -> Vec<DependencyTarget> {
    vec![
        target(Ecosystem::Cargo, "cfg-if", "1.0.5"),
        target(Ecosystem::Npm, "is-number", "6.0.0"),
    ]
}
fn pinned_project(dir: &Path) {
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname='transport-fixture'\nversion='0.0.0'\n[dependencies]\ncfg-if='=1.0.5'\n",
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"),format!("version=3\n[[package]]\nname='transport-fixture'\nversion='0.0.0'\ndependencies=['cfg-if']\n[[package]]\nname='cfg-if'\nversion='1.0.5'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='{CARGO_HASH}'\n")).unwrap();
    std::fs::write(dir.join("package.json"),json!({"name":"transport-fixture","version":"0.0.0","private":true,"dependencies":{"is-number":"6.0.0"}}).to_string()).unwrap();
    std::fs::write(dir.join("package-lock.json"),json!({"name":"transport-fixture","version":"0.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"transport-fixture","version":"0.0.0","dependencies":{"is-number":"6.0.0"}},"node_modules/is-number":{"version":"6.0.0","resolved":"https://registry.npmjs.org/is-number/-/is-number-6.0.0.tgz","integrity":NPM_SRI,"license":"MIT"}}}).to_string()).unwrap();
}

struct CountOsv {
    inner: osv::HttpOsvClient,
    calls: Arc<std::sync::atomic::AtomicUsize>,
    coordinates: Arc<Mutex<Vec<DependencyTarget>>>,
}
#[async_trait::async_trait]
impl OsvClient for CountOsv {
    async fn known_vulns(&self, _: &DependencyTarget) -> Result<Vec<osv::KnownVuln>, String> {
        Err("single queries not permitted in bounded acceptance".into())
    }
    async fn known_vulns_batch(
        &self,
        targets: &[DependencyTarget],
    ) -> Result<Vec<Vec<osv::KnownVuln>>, String> {
        if self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) != 0
            || targets != pinned_targets()
        {
            return Err("OSV coordinate/request budget exceeded".into());
        }
        *self.coordinates.lock().unwrap() = targets.to_vec();
        self.inner.known_vulns_batch(targets).await
    }
}
struct CountFetch {
    inner: fetch::HttpSourceFetcher,
    calls: Arc<std::sync::atomic::AtomicUsize>,
}
#[async_trait::async_trait]
impl SourceFetcher for CountFetch {
    async fn fetch_into(
        &self,
        t: &DependencyTarget,
        dir: &Path,
    ) -> Result<fetch::ExtractStats, String> {
        if self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= 2
            || !pinned_targets().contains(t)
        {
            return Err("fetch coordinate/request budget exceeded".into());
        }
        self.inner.fetch_into(t, dir).await
    }
}

struct ReadAndAudit {
    inner: run::EngineAuditor,
    trees: Arc<Mutex<Vec<Value>>>,
}
fn tree_hashes(root: &Path, dir: &Path, files: &mut Vec<Value>) -> Result<(), String> {
    for entry in std::fs::read_dir(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let kind = entry.file_type().map_err(|e| e.to_string())?;
        if kind.is_dir() {
            tree_hashes(root, &entry.path(), files)?;
        } else if kind.is_file() {
            let bytes = std::fs::read(entry.path()).map_err(|e| e.to_string())?;
            files.push(json!({"path":entry.path().strip_prefix(root).unwrap().to_string_lossy(),"bytes":bytes.len(),"sha256":hex::encode(Sha256::digest(&bytes))}));
        } else {
            return Err("non-regular extracted entry".into());
        }
    }
    Ok(())
}
#[async_trait::async_trait]
impl run::DirAuditor for ReadAndAudit {
    async fn audit(&self, dir: &Path) -> Result<Vec<crate::audit::schema::Finding>, String> {
        Ok(self.audit_with_evidence(dir).await?.findings)
    }
    async fn audit_with_evidence(&self, dir: &Path) -> Result<run::DirAuditResult, String> {
        let mut files = Vec::new();
        tree_hashes(dir, dir, &mut files)?;
        files.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
        self.trees
            .lock()
            .unwrap()
            .push(json!({"kind":"read-only-extracted-source-hashes","files":files}));
        self.inner.audit_with_evidence(dir).await
    }
}

async fn mock_model(captures: Arc<Mutex<Vec<Value>>>) -> (String, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        for _ in 0..3 {
            let Ok(Ok((stream, _))) =
                tokio::time::timeout(Duration::from_secs(120), listener.accept()).await
            else {
                return;
            };
            let mut stream = tokio::io::BufReader::new(stream);
            let mut length = 0;
            let mut headers = 0;
            loop {
                let mut line = String::new();
                let Ok(Ok(n)) =
                    tokio::time::timeout(Duration::from_secs(5), stream.read_line(&mut line)).await
                else {
                    return;
                };
                headers += n;
                if n == 0 || headers > 65536 {
                    return;
                }
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse::<usize>().unwrap_or(0);
                }
            }
            if length > 2_000_000 {
                return;
            }
            let mut body = vec![0; length];
            if !matches!(
                tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut body)).await,
                Ok(Ok(_))
            ) {
                return;
            }
            let value: Value = serde_json::from_slice(&body).unwrap();
            let count = {
                let mut captures = captures.lock().unwrap();
                captures.push(value);
                captures.len()
            };
            let (status, body) = if count <= 2 {
                (
                    "200 OK",
                    r#"{"choices":[{"message":{"content":"[]"},"finish_reason":"stop"}]}"#,
                )
            } else {
                (
                    "503 Service Unavailable",
                    r#"{"error":"mock completion budget exceeded"}"#,
                )
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.get_mut().write_all(response.as_bytes()).await;
        }
    });
    (format!("http://{address}/v1"), handle)
}

#[tokio::test]
#[ignore = "one approved live registry/OSV round: 2 fixed coordinates, <=3 initiations, no real models or source execution"]
async fn bounded_live_public_hunt_transport() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let output = PathBuf::from(
        std::env::var_os("VETTALON_HUNT_LIVE_OUTPUT")
            .expect("fresh VETTALON_HUNT_LIVE_OUTPUT required"),
    );
    std::fs::create_dir(&output).expect("live output must be a new directory");
    let fixture = tempfile::tempdir().unwrap();
    pinned_project(fixture.path());
    assert_eq!(
        super::targets_from_dir(fixture.path()).unwrap(),
        pinned_targets()
    );
    write_new(
        &output.join("started.json"),
        &json!({"status":"started","coordinates":pinned_targets(),"limits":{"api_registry_initiations":3,"redirect_hops":4,"archive_body_bytes":5*1024*1024,"request_secs":15,"overall_secs":120,"mock_completions":2},"real_model_calls":0,"source_execution":false}),
    );
    let redirects = Arc::new(Mutex::new(Vec::<Value>::new()));
    let artifacts = Arc::new(Mutex::new(Vec::<Value>::new()));
    let osv_calls = Arc::new(AtomicUsize::new(0));
    let fetch_calls = Arc::new(AtomicUsize::new(0));
    let coordinates = Arc::new(Mutex::new(Vec::new()));
    let captures = Arc::new(Mutex::new(Vec::<Value>::new()));
    let trees = Arc::new(Mutex::new(Vec::<Value>::new()));
    let mut osv_builder = osv::osv_client_builder().timeout(Duration::from_secs(15));
    let mut fetch_builder = fetch::fetch_client_builder().timeout(Duration::from_secs(15));
    for (builder, policy) in [
        (&mut osv_builder, osv::osv_redirect_policy()),
        (&mut fetch_builder, fetch::fetch_redirect_policy()),
    ] {
        let observed = redirects.clone();
        let replacement=std::mem::take(builder).redirect(reqwest::redirect::Policy::custom(move |attempt|{let mut log=observed.lock().unwrap();log.push(json!({"status":attempt.status().as_u16(),"url":attempt.url().as_str(),"previous":attempt.previous().iter().map(|u|u.as_str()).collect::<Vec<_>>()}));if log.len()>4{return attempt.error("live redirect budget exhausted");}drop(log);policy.redirect(attempt)}));
        *builder = replacement;
    }
    let observed = artifacts.clone();
    let observer: fetch::ArchiveObserver = Arc::new(move |url, final_url, bytes| {
        let sha256 = hex::encode(Sha256::digest(bytes));
        let sha512 = hex::encode(Sha512::digest(bytes));
        let expected = if url.contains("crates.io/") {
            CARGO_HASH
        } else {
            NPM_SHA512
        };
        let actual = if url.contains("crates.io/") {
            &sha256
        } else {
            &sha512
        };
        let ok = actual == expected;
        let mut records = observed.lock().unwrap();
        records.push(json!({"url":url,"final_url":final_url,"archive_bytes":bytes.len(),"sha256":sha256,"sha512":sha512,"expected_digest":expected,"npm_sri":if url.contains("npmjs.org"){Some(NPM_SRI)}else{None},"integrity_matches_pinned_lock":ok}));
        if records
            .iter()
            .map(|v| v["archive_bytes"].as_u64().unwrap())
            .sum::<u64>()
            > 5 * 1024 * 1024
        {
            return Err("overall archive body budget exceeded".into());
        }
        if !ok {
            return Err("archive digest does not match pinned lock".into());
        }
        Ok(())
    });
    let osv = CountOsv {
        inner: osv::HttpOsvClient::for_transport_test(osv_builder.build().unwrap()),
        calls: osv_calls.clone(),
        coordinates: coordinates.clone(),
    };
    let fetcher = CountFetch {
        inner: fetch::HttpSourceFetcher::for_transport_test(
            fetch_builder.build().unwrap(),
            2 * 1024 * 1024,
            Some(observer),
        ),
        calls: fetch_calls.clone(),
    };
    let (base, model_task) = mock_model(captures.clone()).await;
    let finder = crate::llm::ModelHandle {
        id: "fixed-loopback-fixture".into(),
        family: "synthetic-no-inference".into(),
        caller: Arc::new(crate::llm::http::OpenAiCompatCaller {
            spec: crate::llm::http::HttpSpec {
                base_url: base,
                model: "fixed-empty-array-mock".into(),
                api_key_env: None,
                max_tokens: 256,
                temperature: 0.0,
                timeout: Duration::from_secs(15),
            },
            client: reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(15))
                .retry(reqwest::retry::never())
                .build()
                .unwrap(),
        }),
    };
    let home = tempfile::tempdir().unwrap();
    let auditor = ReadAndAudit {
        inner: run::EngineAuditor {
            home: home.path().into(),
            finders: vec![finder],
            verifiers: vec![],
            poc_models: vec![],
            roster: vec![],
            max_modules: 1,
            poc: false,
        },
        trees: trees.clone(),
    };
    let options = run::HuntOptions {
        max_deps: 2,
        include_transitive: false,
        reaudit_known: true,
        per_dep_timeout: Duration::from_secs(30),
        dep_concurrency: 1,
        ..Default::default()
    };
    let started = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(120),
        run::run_hunt(fixture.path(), &options, &osv, &fetcher, &auditor),
    )
    .await;
    model_task.abort();
    let _ = model_task.await;
    let (report, error) = match result {
        Ok(Ok(report)) => (Some(report), None),
        Ok(Err(error)) => (None, Some(error)),
        Err(_) => (None, Some("overall 120s deadline exhausted".into())),
    };
    let receipt = json!({"kind":"bounded-public-registry-and-OSV-with-mock-review","elapsed_ms":started.elapsed().as_millis(),"real_model_calls":0,"source_hooks_executed":false,"osv_batch_initiations":osv_calls.load(Ordering::SeqCst),"osv_coordinates":coordinates.lock().unwrap().clone(),"fetch_initiations":fetch_calls.load(Ordering::SeqCst),"redirects":redirects.lock().unwrap().clone(),"artifacts":artifacts.lock().unwrap().clone(),"source_trees":trees.lock().unwrap().clone(),"mock_completions":captures.lock().unwrap().clone(),"hunt_report":report,"error":error,"boundary":"real registry/OSV transport; fixed [] replies are engineering mock evidence, not detection quality, clean code or vulnerability confirmation; integrity matches pinned local lock values only"});
    write_new(&output.join("receipt.json"), &receipt);
    assert!(
        receipt["error"].is_null(),
        "bounded run incomplete; retained receipt, do not retry: {}",
        receipt["error"]
    );
    assert_eq!(receipt["osv_batch_initiations"], 1);
    assert_eq!(receipt["fetch_initiations"], 2);
    assert!(receipt["redirects"].as_array().unwrap().len() <= 4);
    let artifacts = receipt["artifacts"].as_array().unwrap();
    assert_eq!(
        artifacts.len(),
        2,
        "fetch/integrity failure retained; do not retry"
    );
    assert!(
        artifacts
            .iter()
            .all(|a| a["integrity_matches_pinned_lock"] == true)
    );
    assert!(
        artifacts
            .iter()
            .map(|a| a["archive_bytes"].as_u64().unwrap())
            .sum::<u64>()
            <= 5 * 1024 * 1024
    );
    let report = receipt["hunt_report"].as_object().unwrap();
    assert_eq!(report["total_targets"], 2);
    let rows = report["audited"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|row| row["fetch"]["status"] == "succeeded"));
    assert!(
        rows.iter()
            .all(|row| row["osv"]["status"] == "matched" || row["osv"]["status"] == "unmatched"),
        "OSV failure retained, no retry"
    );
    assert_eq!(
        receipt["mock_completions"].as_array().unwrap().len(),
        2,
        "mock call cap or missing review; inspect retained receipt"
    );
    assert!(
        rows.iter()
            .all(|row| row["findings"].as_array().unwrap().is_empty())
    );
    println!(
        "bounded live transport: coordinates=2, OSV batch=1, archive GET=2, mock completions=2, real models=0; receipt preserves actual run/child statuses"
    );
}

#[test]
fn bounded_fixture_has_two_direct_targets_and_local_digest_pins() {
    let fixture = tempfile::tempdir().unwrap();
    pinned_project(fixture.path());
    assert_eq!(
        super::targets_from_dir(fixture.path()).unwrap(),
        pinned_targets()
    );
    let npm: Value = serde_json::from_str(include_str!(
        "../../../../fixtures/sbom/npm/package-lock.json"
    ))
    .unwrap();
    let package = &npm["packages"]["node_modules/is-number"];
    assert_eq!(package["version"], "6.0.0");
    assert_eq!(package["integrity"], NPM_SRI);
    assert!(package.get("dependencies").is_none());
    let cargo: toml::Value = toml::from_str(include_str!("../../../../Cargo.lock")).unwrap();
    let package = cargo["package"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"].as_str() == Some("cfg-if") && p["version"].as_str() == Some("1.0.5"))
        .unwrap();
    assert_eq!(package["checksum"].as_str(), Some(CARGO_HASH));
}
