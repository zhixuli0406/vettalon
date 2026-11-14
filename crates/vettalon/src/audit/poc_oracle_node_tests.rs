use super::*;
use crate::audit::schema::sha256_hex;
use crate::audit::target_poc::{node_phase_result, parse_node_verdict};
use serde_json::{Value, json};
use std::io::Write;
use std::process::{Command, Stdio};

fn secrets() -> OracleSecrets {
    OracleSecrets {
        canary: "vtlc00000000000000000000000000000000".into(),
        marker: "vtlm11111111111111111111111111111111".into(),
    }
}

fn python(source: &str, input: &str) -> String {
    let mut child = Command::new("python3")
        .args(["-I", "-B", "-c", source])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("D7 tests require python3");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn python_target_runner_bytes_are_pinned_before_d7() {
    // Computed from the pre-D7 templates, before adding the Node branch.
    let expected = [
        "d630dd3adb97d1749de09837cefe924f273547bedb324a8b50474756110c9378",
        "3db159b6ff3ad33ffe97114a8ca98a36417786768bbbaf2f425947ba28eeae1f",
        "7c7b34fc533957d40e28ca3e7f04f86418e90983d1ca7fa0c283c2a1010b674a",
        "cb13e14eb75c215a8a89af5409fab552a2e2afd970a779165c889ccc2b073c8c",
        "cfa476501071f48a12d1fc7f2e7317ad08ef1560a0664d44fa2b6dcf7d005e19",
        "a3e9a789c3e31befe22e0af18a51d569d0c73a1c4f6250b093d695ed0bbde870",
    ];
    let mut index = 0;
    for class in [
        OracleClass::CommandInjection,
        OracleClass::PathTraversal,
        OracleClass::Sqli,
    ] {
        for input in [fixture_inputs(class)[0], benign_input(class)] {
            assert_eq!(
                sha256_hex(target_runner(class, &secrets(), input).as_bytes()),
                expected[index]
            );
            index += 1;
        }
    }
}

#[test]
fn d11a_pin_node_target_runner_bytes() {
    // D11a pin: must not change when SSRF is added
    let expected = [
        "41ff1df5216934310c21138259dbf689eda4c2f9cd5af444064a76a3533b16ca",
        "a89f75b08c180a3725fa84e2bde9bc139751409b463937b48058f34716b66770",
        "4d6122faf5ba37a46ceb881614eba1069c4fc65d87f068a1f0ae774e67beb45c",
        "f3188eeeba49a85ccc1fa61ad02279d9ae7edcadddb587a2709d0ad58a1dab6b",
        "bf185cbc3c6052e0fa1c5600109a2db9a99f2ac1252e425a136b7df913f706e1",
        "39f32cc87109ff3cceed45404cfb9e7336b38c916709373ae61748521ce3a238",
    ];
    let mut index = 0;
    for class in [
        OracleClass::CommandInjection,
        OracleClass::PathTraversal,
        OracleClass::Sqli,
    ] {
        for input in [fixture_inputs(class)[0], benign_input(class)] {
            // D11a pin: must not change when SSRF is added
            let actual = sha256_hex(node_target_runner(class, &secrets(), input, None).as_bytes());
            assert_eq!(actual, expected[index]);
            index += 1;
        }
    }
    // Sqli driver currently renders identical bytes; pin that explicitly too.
    let driver_hash = sha256_hex(
        node_target_runner(
            OracleClass::Sqli,
            &secrets(),
            fixture_inputs(OracleClass::Sqli)[0],
            Some(NodeSqlDriver::Sqlite3),
        )
        .as_bytes(),
    );
    assert_eq!(driver_hash, expected[4]);
}

#[test]
fn node_runner_keeps_marker_and_child_secret_boundary() {
    let s = secrets();
    for class in [
        OracleClass::CommandInjection,
        OracleClass::PathTraversal,
        OracleClass::Sqli,
    ] {
        let runner = node_target_runner(class, &s, fixture_inputs(class)[0], None);
        assert!(!runner.contains(&s.marker));
        assert_eq!(runner.matches("MARKER, FIXTURE = ").count(), 1);
        assert!(runner.starts_with(NODE_RUNNER_SETUP));
        assert!(runner.contains(&s.canary)); // Same public evidence fixture as Python.
        assert!(!RUNNER_INVOKE_NODE.contains("CANARY"));
        assert!(!RUNNER_INVOKE_NODE.contains("MARKER"));
        assert!(!RUNNER_INVOKE_NODE.contains("NODE_OPTIONS"));
        assert!(!RUNNER_INVOKE_NODE.contains("NODE_PATH"));
        assert!(runner.contains("pass_fds=(write_fd,)"));
        assert!(
            runner.contains(
                "os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600"
            )
        );
        assert!(runner.contains("read_fd = os.open(event_path, os.O_RDONLY | os.O_NOFOLLOW)"));
        assert!(
            runner.find("os.unlink(event_path)").unwrap()
                < runner.find("child = subprocess.run(").unwrap()
        );
        assert!(runner.contains("['/usr/local/bin/node', '--require', '/workspace/vtl_hook.cjs', '--no-addons', '--max-old-space-size=320', '--disable-warning=ExperimentalWarning', '/workspace/sink.mjs', payload_hex, result_path]"));
        assert!(runner.rfind("reap()\n").unwrap() < runner.rfind("emit(fields)").unwrap());
    }
}

fn command_event(text: &str) -> Value {
    json!({"v":1,"seq":1,"class":"CWE-78","api":"child_process.exec","file":text,"argv":[],"shell":true})
}

fn path_event(path: &str) -> Value {
    json!({"v":1,"seq":1,"class":"CWE-22","api":"fs.readFileSync","raw":path,"path":path,"inside_base":false})
}

fn sql_event(query: &str, params: Value) -> Value {
    json!({"v":1,"seq":1,"class":"CWE-89","driver":"sqlite3","api":"all","query":query,"params":params,"executable":true})
}

fn line(event: &Value) -> String {
    format!("{event}\n")
}

fn evaluate_cases(cases: Value) -> Vec<Value> {
    let source = format!(
        "import os, sys, json, stat, tempfile\n{}\n{}\n{}",
        RUNNER_REPORTING,
        RUNNER_REACH_NODE,
        r#"results = []
for case in json.load(sys.stdin):
    NODE_CLASS, NODE_PROBE = case['class'], case['probe']
    with tempfile.TemporaryFile() as fh:
        fh.write(case['data'].encode('utf-8'))
        fh.flush()
        fd = fh.fileno() if not case.get('missing') else -1
        results.append(evaluate_reach(fd, case.get('payload', 'vtl_secret')))
print(json.dumps(results))
"#,
    );
    serde_json::from_str(&python(&source, &cases.to_string())).unwrap()
}

#[test]
fn node_reach_probe_table_for_attack_and_benign() {
    let cases = [
        ("CWE-78", "vtl_secret", command_event("cat /tmp/vtl_secret")),
        ("CWE-78", "vtlbenign", command_event("echo vtlbenign")),
        ("CWE-22", "/tmp/vtl_secret", path_event("/tmp/vtl_secret")),
        (
            "CWE-22",
            "/tmp/vtl_base/safe.txt",
            path_event("/tmp/vtl_base/safe.txt"),
        ),
        (
            "CWE-89",
            "vtl_secret",
            sql_event("select token from vtl_secret", json!([])),
        ),
        ("CWE-89", "apple", sql_event("select ?", json!(["apple"]))),
        (
            "CWE-89",
            "vtl_secret",
            sql_event("select ?", json!(["vtl_secret"])),
        ),
    ];
    let mut inputs = Vec::new();
    for (class, probe, event) in &cases {
        inputs.push(json!({"class":class,"probe":probe,"data":line(event)}));
        inputs.push(json!({"class":class,"probe":"not-a-probe","data":line(event)}));
    }
    let output = evaluate_cases(json!(inputs));
    for (index, result) in output.iter().enumerate() {
        assert_eq!(result[0], if index % 2 == 0 { "true" } else { "false" });
        assert_eq!(result[1]["reach_source"], "in_process_hook");
        assert_eq!(result[1]["events_total"], 1);
    }
    assert_eq!(output[8][1]["first_match"]["payload_in_text"], true);
    assert_eq!(output[12][1]["first_match"]["payload_in_text"], false);
    let wrong_path = evaluate_cases(json!([
        {"class":"CWE-22","probe":"/tmp/vtl_secret","data":line(&path_event("/tmp/vtl_secret.bak"))},
        {"class":"CWE-78","probe":"vtl_secret","data":line(&sql_event("vtl_secret", json!([])))}
    ]));
    assert!(wrong_path.iter().all(|r| r[0] == "false"));
}

#[test]
fn node_reach_rejects_forged_malformed_truncated_and_saturated_files() {
    let good = command_event("vtl_secret");
    let mut bad = vec![
        String::new(),
        "{\n".into(),
        good.to_string(),
        "[]\n".into(),
        "x".repeat(65537),
    ];
    bad.push(line(&good) + &line(&good)); // Duplicate sequence, even after a match.
    bad.push(line(&good).replace("\"seq\":1", "\"seq\":2"));
    bad.push(line(&good).replace("\"seq\":1", "\"seq\":true"));
    bad.push(line(&good).replace("\"seq\":1", "\"seq\":1,\"seq\":1"));
    bad.push(line(&good).replace("\"v\":1", "\"v\":true"));
    bad.push(line(&good).replace("child_process.exec", "forged_api"));
    let mut truncated = good.clone();
    truncated["truncated"] = json!(true);
    bad.push(line(&truncated));
    let mut forged = good.clone();
    forged["reached"] = json!(true);
    bad.push(line(&forged));
    let mut oversized = good.clone();
    oversized["file"] = json!("vtl_secret".repeat(500));
    bad.push(line(&oversized));
    let mut saturated = String::new();
    for seq in 1..=256 {
        let mut event = good.clone();
        event["seq"] = json!(seq);
        saturated.push_str(&line(&event));
    }
    bad.push(saturated);
    // The hook may stop before writing the next <= 4096-byte event.
    let mut near_cap = String::new();
    for seq in 1..=20 {
        let mut event = good.clone();
        event["seq"] = json!(seq);
        event["file"] = json!("x".repeat(3000));
        near_cap.push_str(&line(&event));
    }
    bad.push(near_cap);
    let mut cases: Vec<Value> = bad
        .into_iter()
        .map(|data| json!({"class":"CWE-78","probe":"vtl_secret","data":data}))
        .collect();
    cases.push(json!({"class":"CWE-78","probe":"vtl_secret","data":line(&good),"missing":true}));
    for result in evaluate_cases(json!(cases)) {
        assert_eq!(result[0], "unknown", "{result}");
        assert!(result[1]["first_match"].is_null());
    }
    // A well-formed forgery cannot be distinguished in process. It stays
    // explicitly untrusted and is only an additional gate on the Python rule.
    let forged =
        evaluate_cases(json!([{"class":"CWE-78","probe":"vtl_secret","data":line(&good)}]));
    assert_eq!(forged[0][0], "true");
    assert_eq!(forged[0][1]["reach_source"], "in_process_hook");
}

#[test]
fn node_runner_fake_child_checks_fd_env_effect_and_exit_protocol() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_str().unwrap();
    let fake = dir.path().join("child.py");
    std::fs::write(&fake, r#"import os, sys, json, stat, fcntl, sqlite3
payload = json.loads(bytes.fromhex(sys.argv[1]))
result_path = sys.argv[2]
assert sys.stdin.read() == ''
assert not os.path.exists(os.path.join(os.path.dirname(__file__), 'fixture.json'))
assert 'fixture-value' not in ' '.join(sys.argv)
assert 'sql_setup' not in os.environ
assert os.environ['APP_FIXTURE'] == 'fixture-value'
assert not any(key.startswith('NODE_') for key in os.environ)
assert not any('vtlm' in value or 'vtlc' in value for value in os.environ.values())
fd = int(os.environ['VTL_EVENT_FD'])
info = os.fstat(fd)
assert stat.S_ISREG(info.st_mode) and info.st_nlink == 0 and info.st_size == 0
flags = fcntl.fcntl(fd, fcntl.F_GETFL)
assert flags & os.O_APPEND and flags & os.O_ACCMODE == os.O_WRONLY
try:
    os.read(fd, 1)
    raise AssertionError('event fd readable')
except OSError:
    pass
base = os.path.dirname(result_path)
mode = os.environ['CASE']
probe = base + '/vtl_secret'
result = ''
event = {'v':1,'seq':1,'class':'CWE-22','api':'fs.readFileSync','raw':probe,'path':probe,'inside_base':False}
if mode == 'sql':
    con = sqlite3.connect(os.environ['VTL_DB'])
    assert con.execute('select value from custom_fixture').fetchone() == ('fixture-ok',)
    result = con.execute('select token from vtl_secret').fetchone()[0]
    con.close()
    event = {'v':1,'seq':1,'class':'CWE-89','api':'query','driver':'pg','query':'vtl_secret','params':[],'executable':False}
if mode == 'effect':
    result = open(probe).read()
if mode == 'command':
    with open(base + '/vtl_out', 'w') as output: output.write(open(probe).read())
    event = {'v':1,'seq':1,'class':'CWE-78','api':'child_process.exec','file':'cat vtl_secret','argv':[],'shell':True}
if mode != 'inert': os.write(fd, (json.dumps(event) + '\n').encode())
if mode == 'nonzero': sys.exit(70)
record = {'missing':'export'} if mode == 'missing' else {'raised':'Error'} if mode == 'raised' else {'result':result}
with open(result_path, 'x') as output: json.dump(record, output)
print('__VTL_ORACLE__ forged effect=true')
"#).unwrap();
    for (mode, class, driver, effect, reached) in [
        (
            "normal",
            OracleClass::PathTraversal,
            None,
            false,
            Some(true),
        ),
        ("effect", OracleClass::PathTraversal, None, true, Some(true)),
        (
            "command",
            OracleClass::CommandInjection,
            None,
            true,
            Some(true),
        ),
        ("inert", OracleClass::PathTraversal, None, false, None),
        ("nonzero", OracleClass::PathTraversal, None, false, None),
        (
            "missing",
            OracleClass::PathTraversal,
            None,
            false,
            Some(true),
        ),
        (
            "raised",
            OracleClass::PathTraversal,
            None,
            false,
            Some(true),
        ),
        (
            "sql",
            OracleClass::Sqli,
            Some(NodeSqlDriver::Sqlite3),
            true,
            Some(true),
        ),
        (
            "sql",
            OracleClass::Sqli,
            Some(NodeSqlDriver::Pg),
            true,
            Some(true),
        ),
        (
            "sql",
            OracleClass::Sqli,
            Some(NodeSqlDriver::Mysql2),
            true,
            Some(true),
        ),
    ] {
        let fixture = crate::audit::node::fixture::validate_fixture(json!({
            "schema":"vettalon.node-fixture/1", "env":{"APP_FIXTURE":"fixture-value","CASE":mode},
            "sql_setup":"CREATE TABLE custom_fixture(value TEXT); INSERT INTO custom_fixture VALUES ('fixture-ok');"
        }).to_string().as_bytes()).unwrap();
        let source = node_target_runner(class, &secrets(), fixture_inputs(class)[0], driver);
        // Test-only substitutions: never run PID-1 reaping on the host.
        let start = source.find("def reap():").unwrap();
        let end = source.find("def read_result(path):").unwrap();
        let source = format!(
            "{}REAPS = 0\ndef reap():\n    global REAPS\n    REAPS += 1\n{}",
            &source[..start],
            &source[end..]
        );
        let source = source.replace(
            "os.getpid() == 1 and libc.prctl(4, 0, 0, 0, 0) == 0 and libc.prctl(3, 0, 0, 0, 0) == 0",
            "True",
        )
            .replace("/tmp", root)
            .replace("'/usr/local/bin/node', '--require', '/workspace/vtl_hook.cjs', '--no-addons', '--max-old-space-size=320', '--disable-warning=ExperimentalWarning', '/workspace/sink.mjs'", &format!("sys.executable, '-I', '-B', {:?}", fake.to_str().unwrap()))
            .replace("/workspace", root);
        let output = python(
            &(source + "\nassert REAPS == 2\n"),
            &crate::audit::node::dispatch::runner_envelope(
                &runner_input(&secrets()),
                Some(&fixture),
            ),
        );
        assert!(!output.contains("forged"));
        let verdict =
            parse_node_verdict(&output, &secrets().marker, OracleClass::CommandInjection).unwrap();
        assert_eq!(verdict.base.effect, effect, "{mode}");
        assert_eq!(verdict.reached, reached, "{mode}");
        assert_eq!(verdict.missing, mode == "missing");
        assert_eq!(verdict.base.raised, mode == "raised");
        assert_eq!(verdict.base.error, mode == "nonzero");
        assert!(verdict.executable); // Dialect rejection belongs to the host gate.
        if matches!(driver, Some(NodeSqlDriver::Pg | NodeSqlDriver::Mysql2)) {
            assert_eq!(
                node_phase_result(&verdict, driver, false),
                Err("sql_dialect_not_executable")
            );
        }
        assert!(!dir.path().join("vtl_events").exists());
        assert!(!dir.path().join("vtl_target_result").exists());
    }
}

#[test]
fn node_envelope_refuses_bad_lengths_and_trailing_data_without_echoing_secrets() {
    let source = NODE_RUNNER_SETUP.replace(
        "os.getpid() == 1 and libc.prctl(4, 0, 0, 0, 0) == 0 and libc.prctl(3, 0, 0, 0, 0) == 0",
        "True",
    );
    let marker = secrets().marker;
    let valid = crate::audit::node::dispatch::runner_envelope(&marker, None);
    for input in [
        "65\nprivate-secret".to_string(),
        "invalid\nprivate-secret".into(),
        format!("{}\n{marker}65537\nprivate-secret", marker.len()),
        format!("{}\n{marker}40\nprivate-secret", marker.len()),
        format!("{valid}private-secret"),
    ] {
        let mut child = Command::new("python3")
            .args(["-I", "-B", "-c", &source])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(3));
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("invalid Node envelope"));
        assert!(!error.contains("private-secret"));
        assert!(!error.contains(&marker));
    }
}

// SSRF has not been added to the host verdict grammar yet (D11e). Keep this
// helper local: tests must not relax the production parser to accept surfaced.
fn ssrf_fields(output: &std::process::Output) -> std::collections::BTreeMap<String, String> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let prefix = format!("__VTL_ORACLE__ {} ", secrets().marker);
    let lines: Vec<_> = stdout
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix))
        .collect();
    assert_eq!(lines.len(), 1, "{stdout}");
    lines[0]
        .split_whitespace()
        .map(|field| {
            let (key, value) = field.split_once('=').unwrap();
            (key.to_owned(), value.to_owned())
        })
        .collect()
}

fn ssrf_python_available() -> bool {
    match Command::new("python3").arg("--version").output() {
        Ok(output) => output.status.success(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => panic!("cannot start python3: {error}"),
    }
}

fn ssrf_python(source: &str) -> std::process::Output {
    let mut child = Command::new("python3")
        .args(["-I", "-B", "-c", source])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            crate::audit::node::dispatch::runner_envelope(&runner_input(&secrets()), None)
                .as_bytes(),
        )
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn ssrf_poc_oracle_fake_child_listener_and_network_protocol() {
    if !ssrf_python_available() {
        eprintln!("skipping SSRF runner tests: python3 absent");
        return;
    }
    use std::net::TcpListener;
    // Each production phase has its own netns. Serialize the host scenarios and
    // reserve both ports while choosing them; substitute only the test text if
    // low ports are unavailable (e.g. an unprivileged host or a local service).
    let low_ports = TcpListener::bind(("0.0.0.0", 80))
        .and_then(|http| TcpListener::bind(("0.0.0.0", 443)).map(|tls| (http, tls)));
    let (http, tls) = low_ports.unwrap_or_else(|_| {
        (
            TcpListener::bind(("0.0.0.0", 0)).unwrap(),
            TcpListener::bind(("0.0.0.0", 0)).unwrap(),
        )
    });
    let http_port = http.local_addr().unwrap().port();
    let tls_port = tls.local_addr().unwrap().port();
    drop((http, tls));
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_str().unwrap();
    let fake = dir.path().join("child.py");
    std::fs::write(&fake, r#"import os, sys, json, socket, stat, fcntl, struct
payload = json.loads(bytes.fromhex(sys.argv[1]))
result_path = sys.argv[2]
mode, http_port, tls_port = sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
assert sys.stdin.read() == ''
assert not any('vtlm' in v or 'vtlc' in v for v in os.environ.values())
assert not any(k.startswith('NODE_') for k in os.environ)
assert 'VTL_BASE' not in os.environ and 'VTL_DB' not in os.environ
fds = [int(os.environ[key]) for key in ('VTL_EVENT_FD', 'VTL_NET_EVENT_FD')]
assert len(set(fds)) == 2
for fd in fds:
    info = os.fstat(fd)
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 0 and info.st_size == 0
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    assert flags & os.O_APPEND and flags & os.O_ACCMODE == os.O_WRONLY
if sys.platform.startswith('linux'):
    for name in os.listdir('/proc/self/fd'):
        try:
            info = os.fstat(int(name))
        except OSError:
            continue
        assert not stat.S_ISSOCK(info.st_mode), 'listening socket inherited'
event = {'v':1, 'seq':1, 'class':'CWE-918', 'api':'fetch', 'url':payload,
         'href':payload, 'method':'GET', 'truncated':False}
os.write(fds[1], (json.dumps(event) + '\n').encode())
# A malformed old-hook event must not affect SSRF reach.
os.write(fds[0], b'not a network event\n')
result = ''
record = None
request = b'GET /changed-path HTTP/1.1\r\nHost: localhost\r\n\r\n'
if mode in ('http', 'drain', 'exit', 'fragment', 'invalid-http', 'http10', 'long', 'slow', 'tls', 'tls-http-port', 'garbage', 'exception'):
    port = tls_port if mode == 'tls' else http_port
    with socket.create_connection(('127.0.0.1', port), timeout=4) as conn:
        try:
            if mode == 'fragment':
                conn.sendall(request[:7])
                conn.sendall(request[7:])
            elif mode in ('tls', 'tls-http-port'):
                conn.sendall(b'\x16\x03\x01\x00\x04test')
            elif mode in ('garbage', 'exception'):
                conn.sendall(b'garbage\r\n')
            elif mode == 'invalid-http':
                conn.sendall(b'get / HTTP/1.1\r\n')
            elif mode == 'http10':
                conn.sendall(b'POST / HTTP/1.0\r\n')
            elif mode == 'long':
                conn.sendall(b'x' * 4096)
            elif mode != 'slow':
                conn.sendall(request)
            if mode not in ('drain', 'exit', 'slow'):
                conn.shutdown(socket.SHUT_WR)
            if mode not in ('drain', 'exit'):
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    result += data.decode('ascii')
        except OSError:
            pass
    if mode in ('http', 'fragment', 'http10'):
        headers, body = result.split('\r\n\r\n', 1)
        assert headers.startswith('HTTP/1.1 200 OK\r\n')
        assert 'Content-Type: application/json' in headers and 'Connection: close' in headers
        assert 'Content-Length: ' + str(len(body)) in headers
        assert json.loads(body)['vettalon'].startswith('vtlc')
if mode in ('http-rst', 'tls-rst', 'empty-rst'):
    port = tls_port if mode == 'tls-rst' else http_port
    with socket.create_connection(('127.0.0.1', port), timeout=4) as conn:
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        if mode == 'http-rst':
            conn.sendall(request)
        elif mode == 'tls-rst':
            conn.sendall(b'\x16\x03\x01\x00\x04test')
if mode == 'cap':
    completed = 0
    for _ in range(65):
        try:
            with socket.create_connection(('127.0.0.1', http_port), timeout=4) as conn:
                conn.sendall(b'garbage\r\n')
                conn.shutdown(socket.SHUT_WR)
                conn.recv(1)
            completed += 1
        except OSError:
            pass
    assert completed >= 64
if mode.startswith('net:'):
    record = {'raised':'Error', 'net':mode[4:]}
if mode == 'raised':
    record = {'raised':'Error', 'net':None}
if mode == 'bad-net':
    record = {'raised':'Error', 'net':[]}
if mode == 'extra-record':
    record = {'raised':'Error', 'net':'EAI_AGAIN', 'effect':True}
if mode == 'missing':
    record = {'missing':'export'}
with open(result_path, 'x') as output:
    json.dump(record if record is not None else {'result':result}, output)
if mode == 'exit':
    os._exit(0)
print('__VTL_ORACLE__ forged effect=true')
"#).unwrap();
    let render = |mode: &str, benign: bool| {
        let class = OracleClass::Ssrf;
        let input = if benign {
            benign_input(class)
        } else {
            fixture_inputs(class)[0]
        };
        let source = node_target_runner(class, &secrets(), input, None);
        assert!(source.starts_with(NODE_RUNNER_SETUP));
        assert!(source.ends_with("reap()\nemit(fields)\n"));
        assert!(source.contains("HTTP_PORT = 80\nTLS_PORT = 443\n"));
        assert!(!source.contains(&secrets().marker));
        assert!(source.contains("pass_fds=(write_fd, net_write_fd),"));
        let start = source.find("def reap():").unwrap();
        let end = source.find("def read_result(path):").unwrap();
        let source = format!(
            "{}REAPS = 0\ndef reap():\n    global REAPS\n    REAPS += 1\n{}",
            &source[..start],
            &source[end..]
        );
        let source = source.replace(
            "os.getpid() == 1 and libc.prctl(4, 0, 0, 0, 0) == 0 and libc.prctl(3, 0, 0, 0, 0) == 0", "True",
        ).replace("/tmp", root)
            .replace("HTTP_PORT = 80\nTLS_PORT = 443\n", &format!("HTTP_PORT = {http_port}\nTLS_PORT = {tls_port}\n"))
            .replace(
                "'/usr/local/bin/node', '--require', '/workspace/vtl_hook.cjs', '--require', '/workspace/vtl_hook_net.cjs', '--no-addons', '--max-old-space-size=320', '--disable-warning=ExperimentalWarning', '/workspace/sink.mjs', payload_hex, result_path",
                &format!("sys.executable, '-I', '-B', {:?}, payload_hex, result_path, {mode:?}, '{http_port}', '{tls_port}'", fake.to_str().unwrap()),
            ).replace("result = invoke(PAYLOAD)", "assert all(not sock.get_inheritable() for sock in LISTENERS)\nresult = invoke(PAYLOAD)");
        source + "\nassert REAPS == 2\n"
    };
    for mode in [
        "http",
        "http10",
        "fragment",
        "tls",
        "tls-http-port",
        "garbage",
        "invalid-http",
        "long",
        "slow",
        "none",
        "exit",
        "drain",
        "http-rst",
        "tls-rst",
        "empty-rst",
        "cap",
        "exception",
        "raised",
        "bad-net",
        "extra-record",
        "missing",
    ] {
        let mut source = render(mode, false);
        if mode == "drain" || mode.ends_with("-rst") {
            // Force the request to remain queued until invoke/reap have returned.
            source = source.replace(
                "        READY.set()\n",
                "        READY.set()\n        STOP.wait()\n",
            );
        }
        if mode.ends_with("-rst") {
            // Verify that even an empty reset is recorded before continuing.
            source.push_str("assert len(REQUESTS) == 1\n");
            let kind = match mode {
                "http-rst" => "http",
                "tls-rst" => "tls",
                _ => "other",
            };
            source.push_str(&format!("assert REQUESTS[0][2] == {kind:?}\n"));
        }
        if mode == "exception" {
            source = source.replace("def read_request(conn, port, family):\n", "def read_request(conn, port, family):\n    raise RuntimeError('injected listener failure')\n");
        }
        let output = ssrf_python(&source);
        let fields = ssrf_fields(&output);
        assert_eq!(
            fields["effect"],
            matches!(
                mode,
                "http" | "http10" | "fragment" | "tls" | "exit" | "drain" | "http-rst" | "tls-rst"
            )
            .to_string(),
            "{mode}: {fields:?}"
        );
        assert_eq!(
            fields["surfaced"],
            matches!(mode, "http" | "http10" | "fragment").to_string(),
            "{mode}"
        );
        assert_eq!(fields["functional"], "false", "{mode}");
        assert_eq!(
            fields.get("error").map(String::as_str),
            matches!(mode, "cap" | "exception" | "bad-net" | "extra-record").then_some("true"),
            "{mode}: {fields:?}"
        );
        assert_eq!(
            fields.get("raised").map(String::as_str),
            (mode == "raised").then_some("true"),
            "{mode}"
        );
        assert_eq!(
            fields.get("missing").map(String::as_str),
            (mode == "missing").then_some("true")
        );
        assert_eq!(fields["reached"], "true", "{mode}");
        assert!(!String::from_utf8_lossy(&output.stdout).contains("forged"));
        assert!(!dir.path().join("vtl_events").exists());
        assert!(!dir.path().join("vtl_net_events").exists());
        assert!(!dir.path().join("vtl_target_result").exists());
    }
    for code in [
        "ENOTFOUND",
        "EAI_AGAIN",
        "EAI_FAIL",
        "EAI_NODATA",
        "ENETUNREACH",
        "EHOSTUNREACH",
        "ECONNREFUSED",
        "ECONNRESET",
        "EADDRNOTAVAIL",
        "ETIMEDOUT",
        "EPIPE",
        "EPROTO",
        "UND_ERR_SOCKET",
        "UND_ERR_CONNECT_TIMEOUT",
        "EACCES",
    ] {
        let fields = ssrf_fields(&ssrf_python(&render(&format!("net:{code}"), true)));
        assert_eq!(fields["effect"], "false");
        assert_eq!(
            fields["functional"],
            matches!(
                code,
                "ENOTFOUND" | "EAI_AGAIN" | "EAI_FAIL" | "EAI_NODATA" | "ENETUNREACH"
            )
            .to_string(),
            "{code}"
        );
        assert_eq!(
            fields.get("raised").map(String::as_str),
            (code == "EACCES").then_some("true"),
            "{code}"
        );
        assert!(!fields.contains_key("error"), "{code}: {fields:?}");
    }
    // Exercise failure of either required port, not only the first bind.
    for port in [http_port, tls_port] {
        let source = render("none", false).replace(
            "try:\n    for port in (HTTP_PORT, TLS_PORT):",
            &format!("held = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\nheld.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\nheld.bind(('0.0.0.0', {port}))\nheld.listen(1)\ntry:\n    for port in (HTTP_PORT, TLS_PORT):"),
        );
        let output = ssrf_python(&source);
        assert_eq!(output.status.code(), Some(4));
        assert!(output.stdout.is_empty());
        assert_eq!(String::from_utf8_lossy(&output.stderr).lines().count(), 1);
    }
    // IPv6 is deliberately optional on hosts where the loopback is disabled.
    let source = render("http", false).replace(
        "    sock = socket.socket(family, socket.SOCK_STREAM)",
        "    if family == socket.AF_INET6:\n        raise OSError('IPv6 unavailable')\n    sock = socket.socket(family, socket.SOCK_STREAM)",
    );
    let output = ssrf_python(&source);
    let fields = ssrf_fields(&output);
    assert_eq!(fields["effect"], "true");
    assert!(!fields.contains_key("error"));
    assert_eq!(String::from_utf8_lossy(&output.stderr).lines().count(), 2);
}

#[test]
fn ssrf_poc_oracle_is_refused_outside_node_target() {
    let class = OracleClass::Ssrf;
    assert_eq!(class.label(), "server-side request forgery");
    assert_eq!(fixture_inputs(class), &["http://127.0.0.1/vtl_ssrf"]);
    assert_eq!(benign_input(class), "https://example.com/vtl_benign");
    assert!(
        crate::audit::variants::variant_set(class)
            .variants
            .is_empty()
    );
    assert!(
        !crate::audit::variants::variant_set_for(class, crate::audit::target_poc::Runtime::Node,)
            .is_empty()
    );
    assert_eq!(
        anti_cheat_static(class, "def run(payload): pass").as_deref(),
        Some("unsupported_oracle_class")
    );
    for kind in [RunnerKind::Scan, RunnerKind::Fix, RunnerKind::Target] {
        assert_eq!(
            runner_source(class, &secrets(), fixture_inputs(class)[0], kind),
            RUNNER_UNSUPPORTED
        );
    }
    let regression = node_regression_runner(class, &secrets(), fixture_inputs(class)[0]);
    assert!(regression.starts_with(NODE_RUNNER_SETUP));
    assert!(regression.ends_with("reap()\nemit(fields)\n"));
    let red = crate::audit::regression_test::node_red_runner(class, &secrets(), "");
    assert!(red.starts_with(NODE_RUNNER_SETUP));
    if ssrf_python_available() {
        let output = Command::new("python3")
            .args(["-I", "-B", "-c", RUNNER_UNSUPPORTED])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(3));
        assert!(output.stdout.is_empty());
    }
}
