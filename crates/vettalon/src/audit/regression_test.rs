//! Standalone regression test for a finding the sandbox has reproduced.
//!
//! The generated file is ordinary Python `unittest` with no Vettalon
//! dependency, so a developer can keep it in their repository. It uses the
//! harness's own inputs and effect checks (`fixture_inputs`, `benign_input`):
//! it fails while the effect is present and passes once that input no longer
//! has it, which says nothing about other inputs. An assertion failure means
//! the effect was seen. A target that cannot load is a test ERROR, so a
//! deleted function can never read as fixed and can never pass the red check.
//!
//! Everything taken from a report is hex-encoded JSON data; the only other
//! report value in the file is a masked display id, validated as ASCII letters,
//! digits, hyphens and underscores before masking. Nothing here changes a finding's status.

use serde::{Deserialize, Serialize};

use super::poc_oracle::{OracleClass, benign_input, fixture_inputs};
use super::schema::Finding;
use super::target_poc::TargetCall;

/// Printed once by [`red_runner`]; the marker is minted per run and never
/// reaches the target, whose stdout and stderr are discarded anyway.
const RED_PREFIX: &str = "__VTL_REGRESSION__ ";
const ATTACK_TEST: &str = "test_attack_has_no_effect";
const BENIGN_TEST: &str = "test_benign_input_still_works";

/// The result of running a generated test against the unfixed snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegressionTestRecord {
    /// Digest of the generated file; set only when it went through the check.
    pub sha256: Option<String>,
    /// The attack test failed its assertion on the unfixed source.
    pub red_observed: bool,
    pub benign_passed: bool,
    /// Why no test was produced. `None` exactly when one was.
    pub reason: Option<String>,
}

impl RegressionTestRecord {
    pub(crate) fn refused(reason: &str) -> Self {
        Self {
            sha256: None,
            red_observed: false,
            benign_passed: false,
            reason: Some(reason.into()),
        }
    }
}

fn class_label(class: OracleClass) -> &'static str {
    match class {
        OracleClass::CommandInjection => "command injection (CWE-78)",
        OracleClass::PathTraversal => "path traversal (CWE-22)",
        OracleClass::Sqli => "SQL injection (CWE-89)",
    }
}

/// `prepare()` mirrors the runner preconditions in `poc_oracle::runner_source`;
/// paths stay fixed because a TargetCall literal may name them.
fn class_body(class: OracleClass) -> &'static str {
    match class {
        OracleClass::CommandInjection => {
            r#"def prepare(canary):
    write_new(SECRET, canary)
    return {}


def effect(record, canary):
    try:
        with open(OUT, encoding='utf-8', errors='replace') as fh:
            return fh.read().strip() == canary
    except OSError:
        return False


FUNCTIONAL_TEXT = None
"#
        }
        OracleClass::PathTraversal => {
            r#"def prepare(canary):
    os.mkdir(BASE, 0o700)
    MADE_BASE.append(BASE)
    write_new(os.path.join(BASE, 'safe.txt'), 'vtl_safe_content')
    write_new(SECRET, canary)
    return {'VTL_BASE': BASE}


def effect(record, canary):
    return canary in record.get('result', '')


FUNCTIONAL_TEXT = 'vtl_safe_content'
"#
        }
        OracleClass::Sqli => {
            r#"def prepare(canary):
    import sqlite3

    write_new(DB, '')
    con = sqlite3.connect(DB)
    con.execute('CREATE TABLE items(id INTEGER, name TEXT)')
    con.execute("INSERT INTO items VALUES (1, 'apple')")
    con.execute('CREATE TABLE vtl_secret(token TEXT)')
    con.execute('INSERT INTO vtl_secret VALUES (?)', (canary,))
    con.commit()
    con.close()
    return {'VTL_DB': DB}


def effect(record, canary):
    return canary in record.get('result', '')


FUNCTIONAL_TEXT = 'apple'
"#
        }
    }
}

const CHILD: &str = r#"
import importlib.machinery, importlib.util, inspect, json, os, sys, types
root, plan_hex, value_hex, out = sys.argv[1:5]
plan = json.loads(bytes.fromhex(plan_hex).decode('utf-8'))
value = json.loads(bytes.fromhex(value_hex).decode('utf-8'))
def emit(record):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    with os.fdopen(os.open(out, flags, 0o600), 'w', encoding='utf-8') as fh:
        json.dump(record, fh)
path = os.path.join(root, *plan['file'].split('/'))
try:
    loader = importlib.machinery.SourceFileLoader('_vettalon_target', path)
    source = loader.get_data(path)
    spec = importlib.util.spec_from_loader('_vettalon_target', loader, origin=path)
    module = importlib.util.module_from_spec(spec) if spec is not None else types.ModuleType('_vettalon_target')
    module.__file__ = path
    exec(loader.source_to_code(source, path), module.__dict__)
    function = module.__dict__.get(plan['function'])
    if not callable(function):
        raise RuntimeError('target function unavailable')
except BaseException as exc:
    emit({'status': 'load_error', 'type': type(exc).__name__})
    sys.exit(3)
args = [value if item['kind'] == 'payload' else item['value'] for item in plan['args']]
try:
    result = function(*args)
except Exception as exc:
    emit({'status': 'raised', 'type': type(exc).__name__})
    sys.exit(0)
if inspect.isawaitable(result):
    emit({'status': 'load_error', 'type': 'async target unsupported'})
    sys.exit(3)
emit({'status': 'ok', 'result': str(result)})
"#;

const TEMPLATE: &str = r#"#!/usr/bin/env python3
"""Regression test generated by `vettalon reproduce --emit-test`.

Finding @FINDING@: @LABEL@.

Vettalon reproduced this effect in a sandbox. The attack test fails while the
effect is present and passes once this input no longer has it. Passing does
not prove the vulnerability is gone and does not change the finding's status.

Run it from the repository root, or set VETTALON_REPO_ROOT. It creates and
removes /tmp/vtl_* and runs the target in a subprocess.
"""
import json
import os
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

PLAN_HEX = '@PLAN_HEX@'
ATTACK_INPUT = @ATTACK@
BENIGN_INPUT = @BENIGN@
SECRET = '/tmp/vtl_secret'
OUT = '/tmp/vtl_out'
BASE = '/tmp/vtl_base'
DB = '/tmp/vtl.db'
CREATED = []
MADE_BASE = []
CHILD = r'''@CHILD@'''


def refuse_existing(path):
    if os.path.lexists(path):
        raise RuntimeError(path + ' already exists; remove it and rerun (tests sharing these paths cannot run in parallel)')


def write_new(path, text):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    info = os.fstat(fd)
    CREATED.append((path, info.st_dev, info.st_ino))
    with os.fdopen(fd, 'w', encoding='utf-8') as fh:
        fh.write(text)


def remove_created(canary):
    # Identity is checked so a file another process put in place survives.
    for path, device, inode in reversed(CREATED):
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            continue
        if (info.st_dev, info.st_ino) == (device, inode):
            os.unlink(path)
    CREATED.clear()
    # The only file the target writes: it is ours if it holds this run's canary.
    try:
        with open(OUT, encoding='utf-8', errors='replace') as fh:
            ours = fh.read().strip() == canary
    except OSError:
        ours = False
    if ours:
        os.unlink(OUT)
    if MADE_BASE:
        MADE_BASE.clear()
        os.rmdir(BASE)


@CLASS_BODY@

@unittest.skipUnless(os.name == 'posix', 'the fixed /tmp paths need a POSIX host')
class VettalonRegressionTest(unittest.TestCase):
    def setUp(self):
        self.root = os.environ.get('VETTALON_REPO_ROOT') or os.getcwd()
        self.canary = 'vtlc' + secrets.token_hex(16)
        self.scratch = tempfile.mkdtemp(prefix='vettalon-regression-')
        self.addCleanup(shutil.rmtree, self.scratch, ignore_errors=True)
        for path in (SECRET, OUT, BASE, DB):
            refuse_existing(path)
        self.addCleanup(remove_created, self.canary)
        self.env = prepare(self.canary)

    def invoke(self, value):
        out = os.path.join(self.scratch, secrets.token_hex(8))
        env = {'HOME': '/tmp'}
        env.update(self.env)
        command = [
            sys.executable, '-I', '-B', '-c', CHILD,
            self.root, PLAN_HEX, json.dumps(value).encode('utf-8').hex(), out,
        ]
        subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            timeout=30,
            check=False,
        )
        try:
            with open(out, encoding='utf-8') as fh:
                record = json.load(fh)
        except OSError as exc:
            raise RuntimeError('the target exited without a result') from exc
        if record['status'] == 'load_error':
            raise RuntimeError('the target could not run: ' + record['type'])
        return record

    def test_attack_has_no_effect(self):
        record = self.invoke(ATTACK_INPUT)
        self.assertFalse(
            effect(record, self.canary),
            'the input still has the effect Vettalon reproduced',
        )

    def test_benign_input_still_works(self):
        record = self.invoke(BENIGN_INPUT)
        self.assertEqual(record['status'], 'ok', 'the benign input raised')
        self.assertFalse(effect(record, self.canary), 'the benign input has the effect')
        if FUNCTIONAL_TEXT is not None:
            self.assertIn(FUNCTIONAL_TEXT, record['result'])


if __name__ == '__main__':
    unittest.main()
"#;

/// Render the test file. `call` must have passed the same validation as the
/// reproduction it came from; it is revalidated here because the output is
/// meant to be committed and run on developer machines.
pub fn generate(
    finding: &Finding,
    class: OracleClass,
    call: &TargetCall,
) -> Result<String, &'static str> {
    call.validate()?;
    if finding.id.is_empty()
        || !finding
            .id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err("invalid_finding_id");
    }
    let plan = serde_json::to_vec(call).map_err(|_| "invalid_target_call")?;
    let literal =
        |input: &str| serde_json::to_string(input).map_err(|_| "invalid_regression_input");
    Ok(TEMPLATE
        .replace(
            "@FINDING@",
            &crate::util::mask_sensitive_text(crate::util::truncate_bytes(&finding.id, 256)),
        )
        .replace("@LABEL@", class_label(class))
        .replace("@PLAN_HEX@", &hex::encode(plan))
        .replace("@ATTACK@", &literal(fixture_inputs(class)[0])?)
        .replace("@BENIGN@", &literal(benign_input(class))?)
        .replace("@CHILD@", CHILD)
        .replace("@CLASS_BODY@", class_body(class)))
}

/// Fixed runner for the sandbox red check; the test file is mounted as
/// `/workspace/sink.py` and the prepared tree as `/workspace/tree`.
pub(crate) fn red_runner(marker: &str) -> String {
    format!(
        r#"import importlib.util
import os
import unittest
MARKER = '{marker}'
os.environ['VETTALON_REPO_ROOT'] = '/workspace/tree'
def state(name, result):
    wanted = lambda rows: any(test.id().rsplit('.', 1)[-1] == name for test, _ in rows)
    if wanted(result.errors):
        return 'error'
    return 'fail' if wanted(result.failures) else 'pass'
spec = importlib.util.spec_from_file_location('vettalon_regression', '/workspace/sink.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
result = unittest.TestResult()
unittest.defaultTestLoader.loadTestsFromModule(module).run(result)
print('{RED_PREFIX}' + MARKER + ' ran=' + str(result.testsRun) + ' skipped=' + str(len(result.skipped))
      + ' attack=' + state('{ATTACK_TEST}', result) + ' benign=' + state('{BENIGN_TEST}', result))
"#
    )
}

/// Read the single marker-bound verdict. Anything else is not a red result.
pub(crate) fn parse_red_verdict(output: &str, marker: &str) -> Result<(bool, bool), &'static str> {
    let expected = format!("{RED_PREFIX}{marker} ");
    let mut lines = output
        .lines()
        .filter_map(|line| line.trim().strip_prefix(expected.as_str()));
    let line = lines.next().ok_or("regression_verdict_missing")?;
    if lines.next().is_some() {
        return Err("duplicate_regression_verdict");
    }
    match line.split_whitespace().collect::<Vec<_>>().as_slice() {
        ["ran=2", "skipped=0", attack, benign] => {
            Ok((*attack == "attack=fail", *benign == "benign=pass"))
        }
        _ => Err("invalid_regression_verdict"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::schema::{FindingKind, Severity};
    use crate::audit::target_poc::TargetArgument;
    use std::path::Path;
    use std::process::{Command, Output};
    use std::sync::Mutex;

    /// The generated tests share fixed /tmp paths.
    static HOST_RUN: Mutex<()> = Mutex::new(());

    fn finding(id: &str) -> Finding {
        let mut finding = Finding::candidate(
            "ai_audit",
            FindingKind::Other,
            Severity::High,
            "t",
            "app.py",
            Some(1),
            "x",
            "ai-audit/test",
            vec![],
        );
        finding.id = id.into();
        finding
    }

    fn call(function: &str, args: Vec<TargetArgument>) -> TargetCall {
        TargetCall {
            file: "app.py".into(),
            function: function.into(),
            args,
        }
    }

    fn run_generated(test: &str, source: &str) -> Output {
        let repo = tempfile::tempdir().unwrap();
        std::fs::write(repo.path().join("app.py"), source).unwrap();
        let path = repo.path().join("test_vettalon_generated.py");
        std::fs::write(&path, test).unwrap();
        Command::new("python3")
            .args(["-B", "-m", "unittest", "test_vettalon_generated"])
            .current_dir(repo.path())
            .output()
            .unwrap()
    }

    fn outcome(output: &Output) -> String {
        let text = String::from_utf8_lossy(&output.stderr);
        text.lines()
            .filter(|line| line.starts_with("FAIL: ") || line.starts_with("ERROR: "))
            .map(|line| line.split(' ').take(2).collect::<Vec<_>>().join(" "))
            .collect::<Vec<_>>()
            .join(",")
    }

    fn python3_present() -> bool {
        Command::new("python3").arg("--version").output().is_ok()
    }

    /// (class, target call, unfixed source, fixed source)
    fn cases() -> Vec<(OracleClass, TargetCall, &'static str, &'static str)> {
        vec![
            (
                OracleClass::CommandInjection,
                call("run", vec![TargetArgument::Payload]),
                "import subprocess\ndef run(name):\n    subprocess.run('echo ' + name, shell=True, stdout=subprocess.DEVNULL)\n",
                "import subprocess\ndef run(name):\n    subprocess.run(['echo', name], stdout=subprocess.DEVNULL)\n",
            ),
            (
                OracleClass::PathTraversal,
                call("read", vec![TargetArgument::Payload]),
                "import os\ndef read(name):\n    with open(os.path.join(os.environ['VTL_BASE'], name)) as fh:\n        return fh.read()\n",
                "import os\ndef read(name):\n    base = os.path.realpath(os.environ['VTL_BASE'])\n    path = os.path.realpath(os.path.join(base, name))\n    if not path.startswith(base + os.sep):\n        return ''\n    with open(path) as fh:\n        return fh.read()\n",
            ),
            (
                OracleClass::Sqli,
                call("find", vec![TargetArgument::Payload]),
                "import os, sqlite3\ndef find(name):\n    con = sqlite3.connect(os.environ['VTL_DB'])\n    return str(con.execute(\"SELECT name FROM items WHERE name = '\" + name + \"'\").fetchall())\n",
                "import os, sqlite3\ndef find(name):\n    con = sqlite3.connect(os.environ['VTL_DB'])\n    return str(con.execute('SELECT name FROM items WHERE name = ?', (name,)).fetchall())\n",
            ),
        ]
    }

    #[test]
    fn generated_test_is_red_then_green_for_every_class() {
        if !python3_present() {
            return;
        }
        let _guard = HOST_RUN.lock().unwrap_or_else(|e| e.into_inner());
        for (class, target, unfixed, fixed) in cases() {
            let test = generate(&finding("abc123"), class, &target).unwrap();
            let red = run_generated(&test, unfixed);
            assert!(!red.status.success(), "{class:?}");
            assert_eq!(
                outcome(&red),
                format!("FAIL: {ATTACK_TEST}"),
                "{class:?}: {}",
                String::from_utf8_lossy(&red.stderr)
            );
            let green = run_generated(&test, fixed);
            assert!(
                green.status.success(),
                "{class:?}: {}",
                String::from_utf8_lossy(&green.stderr)
            );
        }
        for path in [
            "/tmp/vtl_secret",
            "/tmp/vtl_out",
            "/tmp/vtl_base",
            "/tmp/vtl.db",
        ] {
            assert!(
                std::fs::symlink_metadata(path).is_err(),
                "{path} left behind"
            );
        }
    }

    #[test]
    fn a_removed_or_broken_target_errors_and_a_rejecting_fix_passes() {
        if !python3_present() {
            return;
        }
        let _guard = HOST_RUN.lock().unwrap_or_else(|e| e.into_inner());
        let (class, target, _, _) = cases().remove(2);
        let test = generate(&finding("abc123"), class, &target).unwrap();

        let removed = run_generated(&test, "def other(name):\n    return name\n");
        assert_eq!(
            outcome(&removed),
            format!("ERROR: {ATTACK_TEST},ERROR: {BENIGN_TEST}")
        );
        let broken = run_generated(&test, "def find(name:\n");
        assert_eq!(
            outcome(&broken),
            format!("ERROR: {ATTACK_TEST},ERROR: {BENIGN_TEST}")
        );
        let exits = run_generated(&test, "import sys\ndef find(name):\n    sys.exit(0)\n");
        assert_eq!(
            outcome(&exits),
            format!("ERROR: {ATTACK_TEST},ERROR: {BENIGN_TEST}")
        );
        let rejects = run_generated(
            &test,
            "def find(name):\n    if \"'\" in name:\n        raise ValueError('rejected')\n    return \"[('apple',)]\"\n",
        );
        assert!(
            rejects.status.success(),
            "{}",
            String::from_utf8_lossy(&rejects.stderr)
        );
        let always_empty = run_generated(&test, "def find(name):\n    return ''\n");
        assert_eq!(outcome(&always_empty), format!("FAIL: {BENIGN_TEST}"));
    }

    #[test]
    fn literals_reach_the_call_in_position() {
        if !python3_present() {
            return;
        }
        let _guard = HOST_RUN.lock().unwrap_or_else(|e| e.into_inner());
        let target = call(
            "read",
            vec![
                TargetArgument::Literal {
                    value: serde_json::json!("/tmp/vtl_base"),
                },
                TargetArgument::Payload,
            ],
        );
        let test = generate(&finding("abc123"), OracleClass::PathTraversal, &target).unwrap();
        let red = run_generated(
            &test,
            "import os\ndef read(base, name):\n    with open(os.path.join(base, name)) as fh:\n        return fh.read()\n",
        );
        assert_eq!(outcome(&red), format!("FAIL: {ATTACK_TEST}"));
    }

    #[cfg(unix)]
    #[test]
    fn a_planted_symlink_is_refused_and_left_alone() {
        if !python3_present() {
            return;
        }
        let _guard = HOST_RUN.lock().unwrap_or_else(|e| e.into_inner());
        let victim = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(victim.path(), "preserve").unwrap();
        std::os::unix::fs::symlink(victim.path(), Path::new("/tmp/vtl_secret")).unwrap();
        let (class, target, unfixed, _) = cases().remove(0);
        let test = generate(&finding("abc123"), class, &target).unwrap();
        let run = run_generated(&test, unfixed);
        std::fs::remove_file("/tmp/vtl_secret").unwrap();
        assert!(!run.status.success());
        assert_eq!(std::fs::read_to_string(victim.path()).unwrap(), "preserve");
        let text = String::from_utf8_lossy(&run.stderr);
        assert!(text.contains("already exists"), "{text}");
    }

    #[test]
    fn an_existing_path_is_refused_and_keeps_its_contents() {
        if !python3_present() {
            return;
        }
        let _guard = HOST_RUN.lock().unwrap_or_else(|e| e.into_inner());
        let base = Path::new("/tmp/vtl_base");
        std::fs::create_dir(base).unwrap();
        std::fs::write(base.join("keep"), "preserve").unwrap();
        let (class, target, unfixed, _) = cases().remove(1);
        let test = generate(&finding("abc123"), class, &target).unwrap();
        let run = run_generated(&test, unfixed);
        let kept = std::fs::read_to_string(base.join("keep"));
        std::fs::remove_dir_all(base).unwrap();
        assert!(!run.status.success());
        assert_eq!(kept.unwrap(), "preserve");
    }

    #[test]
    fn cleanup_spares_a_file_it_did_not_create() {
        if !python3_present() {
            return;
        }
        let _guard = HOST_RUN.lock().unwrap_or_else(|e| e.into_inner());
        // Create the replacement before swapping so the original inode remains
        // allocated and cleanup can verify that it leaves the replacement.
        let source = "import os\ndef run(name):\n    open('/tmp/vtl_secret.swap', 'w').write('other')\n    os.replace('/tmp/vtl_secret.swap', '/tmp/vtl_secret')\n";
        let (class, target, _, _) = cases().remove(0);
        let test = generate(&finding("abc123"), class, &target).unwrap();
        let repo = tempfile::tempdir().unwrap();
        std::fs::write(repo.path().join("app.py"), source).unwrap();
        std::fs::write(repo.path().join("test_vettalon_generated.py"), test).unwrap();
        let run = Command::new("python3")
            .args(["-B", "-m", "unittest"])
            .arg(format!(
                "test_vettalon_generated.VettalonRegressionTest.{BENIGN_TEST}"
            ))
            .current_dir(repo.path())
            .output()
            .unwrap();
        let kept = std::fs::read_to_string("/tmp/vtl_secret");
        let _ = std::fs::remove_file("/tmp/vtl_secret");
        assert!(
            run.status.success(),
            "{}",
            String::from_utf8_lossy(&run.stderr)
        );
        assert_eq!(kept.unwrap(), "other");
    }

    #[test]
    fn report_strings_never_become_source() {
        let target = call(
            "read",
            vec![
                TargetArgument::Literal {
                    value: serde_json::json!("'''\nimport evil\n"),
                },
                TargetArgument::Payload,
            ],
        );
        let test = generate(&finding("abc123"), OracleClass::Sqli, &target).unwrap();
        assert!(!test.contains("import evil"));
        let plan_hex = test
            .split("PLAN_HEX = '")
            .nth(1)
            .unwrap()
            .split('\'')
            .next()
            .unwrap();
        let decoded: TargetCall = serde_json::from_slice(&hex::decode(plan_hex).unwrap()).unwrap();
        assert_eq!(decoded, target);
        assert!(
            test.contains(&serde_json::to_string(fixture_inputs(OracleClass::Sqli)[0]).unwrap())
        );

        assert_eq!(
            generate(&finding("abc\n\"\"\"evil"), OracleClass::Sqli, &target),
            Err("invalid_finding_id")
        );
        assert_eq!(
            generate(&finding(""), OracleClass::Sqli, &target),
            Err("invalid_finding_id")
        );
        let bad = call("__import__", vec![TargetArgument::Payload]);
        assert_eq!(
            generate(&finding("abc123"), OracleClass::Sqli, &bad),
            Err("invalid_target_function")
        );
    }

    #[test]
    fn the_verdict_must_be_single_marker_bound_and_complete() {
        let line = |rest: &str| format!("{RED_PREFIX}vtlmarker {rest}\n");
        let red = line("ran=2 skipped=0 attack=fail benign=pass");
        assert_eq!(parse_red_verdict(&red, "vtlmarker"), Ok((true, true)));
        assert_eq!(
            parse_red_verdict(
                &line("ran=2 skipped=0 attack=error benign=pass"),
                "vtlmarker"
            ),
            Ok((false, true))
        );
        assert_eq!(
            parse_red_verdict(&red, "othermarker"),
            Err("regression_verdict_missing")
        );
        assert_eq!(
            parse_red_verdict(&format!("{red}{red}"), "vtlmarker"),
            Err("duplicate_regression_verdict")
        );
        for bad in [
            "ran=0 skipped=0 attack=pass benign=pass",
            "ran=2 skipped=2 attack=pass benign=pass",
            "ran=2 skipped=0 attack=fail",
        ] {
            assert_eq!(
                parse_red_verdict(&line(bad), "vtlmarker"),
                Err("invalid_regression_verdict"),
                "{bad}"
            );
        }
    }
}
