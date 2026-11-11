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

/// Printed once by [`red_runner`], after a newline; the marker is minted per
/// run, reaches the runner on stdin only and never reaches the test or the
/// target, whose stdout and stderr are discarded anyway.
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

/// Program of the child process that runs the project test. It makes itself
/// non-dumpable before loading `/workspace/sink.py`, so code the test starts
/// (the target runs in a grandchild) cannot open its `/proc/<pid>/fd` or
/// ptrace it. It reports the `TestResult` as one small JSON record on the
/// inherited, already unlinked result file descriptor `argv[1]`, which it
/// first marks non-inheritable so no process the test starts receives it.
/// Its stdin, stdout and stderr are /dev/null. Exit 0 only after a complete
/// write; any other exit (including `sys.exit` from the test module) leaves
/// no usable record.
const RED_CHILD: &str = r#"import ctypes, json, os, sys
def main():
    fd = int(sys.argv[1])
    os.set_inheritable(fd, False)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(4, 0, 0, 0, 0) != 0 or libc.prctl(3, 0, 0, 0, 0) != 0:
        os._exit(3)
    import importlib.util, unittest
    spec = importlib.util.spec_from_file_location('vettalon_regression', '/workspace/sink.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = unittest.TestResult()
    unittest.defaultTestLoader.loadTestsFromModule(module).run(result)
    def state(name):
        wanted = lambda rows: any(test.id().rsplit('.', 1)[-1] == name for test, _ in rows)
        if wanted(result.errors):
            return 'error'
        return 'fail' if wanted(result.failures) else 'pass'
    record = {'ran': result.testsRun, 'skipped': len(result.skipped),
              'attack': state('@ATTACK@'), 'benign': state('@BENIGN@')}
    data = json.dumps(record, ensure_ascii=True, separators=(',', ':')).encode('ascii')
    while data:
        data = data[os.write(fd, data):]
    os._exit(0)
main()
"#;

/// The red runner after `poc_oracle::RUNNER_SETUP`:
/// that start-up has already installed the hard-stop signal handlers and the
/// alarm, read the marker from stdin to EOF, checked the runner is PID 1 and
/// made it non-dumpable (verified), exiting 3 with nothing marked otherwise.
///
/// No project code runs in this process. The runner creates the result file
/// (`O_EXCL|O_NOFOLLOW|O_NONBLOCK`) and unlinks it while it is the only
/// process in the container, so only the runner and the test child hold it.
/// After the child exits, `reap()` kills and waits for everything the test
/// left behind; the record is then read through the runner's own descriptor
/// (fstat, regular file, size cap, strict fields), `reap()` runs again and
/// ONE marked line is written, starting with a newline so bytes pushed into
/// the pipe without a trailing newline cannot swallow its prefix. Any failure
/// exits 3 without a marked line.
const RED_BODY: &str = r#"RED_PREFIX = '@PREFIX@'
RESULT_LIMIT = 4096
CHILD = r'''@CHILD@'''
def emit(fields):
    sys.stdout.write('\n' + RED_PREFIX + MARKER + ' ' + fields + '\n')
    sys.stdout.flush()
def fail(why):
    sys.stderr.write('vettalon regression harness: ' + why + '; no verdict\n')
    sys.stderr.flush()
    os._exit(3)
def reap():
    # PID 1: kill(-1) reaches every other process in the container and every
    # orphan is re-parented here. Kill and wait until no child is left.
    while True:
        try:
            os.kill(-1, signal.SIGKILL)
        except OSError:
            pass
        try:
            os.waitpid(-1, 0)
        except ChildProcessError:
            return
def read_record(fd):
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_size > RESULT_LIMIT:
        raise RuntimeError('invalid test result')
    data = os.pread(fd, RESULT_LIMIT + 1, 0)
    if len(data) > RESULT_LIMIT:
        raise RuntimeError('invalid test result')
    record = json.loads(data.decode('ascii'))
    if not isinstance(record, dict) or set(record) != {'ran', 'skipped', 'attack', 'benign'}:
        raise RuntimeError('invalid test result')
    for key in ('ran', 'skipped'):
        if type(record[key]) is not int or not 0 <= record[key] <= 1000:
            raise RuntimeError('invalid test result')
    for key in ('attack', 'benign'):
        if type(record[key]) is not str or record[key] not in ('pass', 'fail', 'error'):
            raise RuntimeError('invalid test result')
    return record
def main():
    reap()
    path = '/tmp/vtl_regression_result'
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NONBLOCK | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    os.unlink(path)
    env = dict(os.environ)
    env['VETTALON_REPO_ROOT'] = '/workspace/tree'
    code = None
    try:
        child = subprocess.run(
            [sys.executable, '-I', '-B', '-c', CHILD, str(fd)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            pass_fds=(fd,),
            timeout=100,
            check=False,
        )
        code = child.returncode
    finally:
        reap()
    if code != 0:
        fail('test child exited with code ' + str(code))
    record = read_record(fd)
    os.close(fd)
    reap()
    emit('ran=' + str(record['ran']) + ' skipped=' + str(record['skipped'])
         + ' attack=' + record['attack'] + ' benign=' + record['benign'])
try:
    main()
except Exception:
    fail('harness error')
"#;

/// Fixed runner for the sandbox red check; the test file is mounted as
/// `/workspace/sink.py` and the prepared tree as `/workspace/tree`. It holds
/// no marker: the marker reaches it on stdin (`poc_oracle::runner_input`),
/// and it must run as PID 1 of its container (`TargetSandbox::run`, i.e.
/// `DockerSandbox::run_workspace_with_tree`).
///
/// Why the test and the target cannot forge the red line:
/// - the marker is not in the runner text, a file, an argument or the
///   environment; the runner reads it from stdin and is non-dumpable before
///   any project code exists, so its memory and `/proc/1/fd` are closed;
/// - project code only runs in the test child (itself non-dumpable) and its
///   descendants, all with stdio on /dev/null, so none has a descriptor for
///   the runner's stdout;
/// - the record comes back through an unlinked file only the runner and the
///   test child hold, read after `reap()` has removed every other process;
/// - the host counts a verdict only with exit 0 and exactly one occurrence
///   of the marked prefix, at the start of a line.
///
/// Not covered: a test that imports the target into its own process lets
/// that code write the record, as it could already change the test's outcome
/// directly.
pub(crate) fn red_runner() -> String {
    let child = RED_CHILD
        .replace("@ATTACK@", ATTACK_TEST)
        .replace("@BENIGN@", BENIGN_TEST);
    let mut runner = String::from(super::poc_oracle::RUNNER_SETUP);
    runner.push_str(
        &RED_BODY
            .replace("@PREFIX@", RED_PREFIX)
            .replace("@CHILD@", &child),
    );
    runner
}

/// The fields after `PREFIX MARKER ` on the single marked line. A non-zero
/// exit, no occurrence, more than one occurrence of the marked
/// prefix anywhere in the output, or one not at the start of a line is no
/// verdict.
fn marked_fields<'a>(exit: i64, output: &'a str, marker: &str) -> Result<&'a str, &'static str> {
    if exit != 0 {
        return Err("regression_test_execution_error");
    }
    let tag = format!("{RED_PREFIX}{marker}");
    match output.matches(tag.as_str()).count() {
        0 => return Err("regression_verdict_missing"),
        1 => {}
        _ => return Err("duplicate_regression_verdict"),
    }
    let expected = format!("{tag} ");
    output
        .lines()
        .find_map(|line| line.trim_end().strip_prefix(expected.as_str()))
        .ok_or("invalid_regression_verdict")
}

/// Read the single marker-bound verdict of a run that exited 0. Anything
/// else is not a red result.
pub(crate) fn parse_red_verdict(
    exit: i64,
    output: &str,
    marker: &str,
) -> Result<(bool, bool), &'static str> {
    let line = marked_fields(exit, output, marker)?;
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
        let line = |rest: &str| format!("\n{RED_PREFIX}vtlmarker {rest}\n");
        let red = line("ran=2 skipped=0 attack=fail benign=pass");
        assert_eq!(parse_red_verdict(0, &red, "vtlmarker"), Ok((true, true)));
        assert_eq!(
            parse_red_verdict(
                0,
                &line("ran=2 skipped=0 attack=error benign=pass"),
                "vtlmarker"
            ),
            Ok((false, true))
        );
        assert_eq!(
            parse_red_verdict(0, &red, "othermarker"),
            Err("regression_verdict_missing")
        );
        assert_eq!(
            parse_red_verdict(0, &format!("{red}{red}"), "vtlmarker"),
            Err("duplicate_regression_verdict")
        );
        for bad in [
            "ran=0 skipped=0 attack=pass benign=pass",
            "ran=2 skipped=2 attack=pass benign=pass",
            "ran=2 skipped=0 attack=fail",
        ] {
            assert_eq!(
                parse_red_verdict(0, &line(bad), "vtlmarker"),
                Err("invalid_regression_verdict"),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_non_zero_exit_or_a_second_marked_prefix_is_no_verdict() {
        let real = format!("\n{RED_PREFIX}vtlmarker ran=2 skipped=0 attack=pass benign=pass\n");
        let forged = format!("\n{RED_PREFIX}vtlmarker ran=2 skipped=0 attack=fail benign=pass\nZ");
        for exit in [1, 3, 137, -1] {
            assert_eq!(
                parse_red_verdict(exit, &real, "vtlmarker"),
                Err("regression_test_execution_error"),
                "{exit}"
            );
        }
        // The R2-1 forgery: a line pushed into stdout without a trailing
        // newline, before the runner's own line. With or without the
        // runner's leading newline there are two marked prefixes.
        let swallowed = format!("{forged}{}", real.trim_start());
        for output in [format!("{forged}{real}"), swallowed] {
            assert_eq!(
                parse_red_verdict(0, &output, "vtlmarker"),
                Err("duplicate_regression_verdict"),
                "{output:?}"
            );
        }
        // The only marked prefix, but not at the start of a line.
        let glued = format!("Z{}", real.trim_start());
        assert_eq!(
            parse_red_verdict(0, &glued, "vtlmarker"),
            Err("invalid_regression_verdict")
        );
        // A marked prefix elsewhere on a line still counts as a second one.
        let echoed = format!("noise {RED_PREFIX}vtlmarker\n{real}");
        assert_eq!(
            parse_red_verdict(0, &echoed, "vtlmarker"),
            Err("duplicate_regression_verdict")
        );
    }

    fn position(haystack: &str, needle: &str) -> usize {
        haystack
            .find(needle)
            .unwrap_or_else(|| panic!("{needle:?} missing"))
    }

    #[test]
    fn the_red_runner_holds_no_marker_and_is_hardened_before_any_test_code() {
        let runner = red_runner();
        // Same start-up as the oracle runner: signals, alarm, marker from
        // stdin to EOF, PID 1, PR_SET_DUMPABLE=0 and PR_GET_DUMPABLE == 0.
        assert!(runner.starts_with(crate::audit::poc_oracle::RUNNER_SETUP));
        assert!(runner.contains("marker = sys.stdin.buffer.read()"));
        assert!(runner.contains("os.getpid() == 1"));
        assert!(runner.contains("signal.alarm(HARD_LIMIT_SECS)"));
        assert!(!runner.contains("MARKER = '"));
        let secrets = crate::audit::poc_oracle::OracleSecrets::fresh();
        assert!(!runner.contains(&secrets.marker));
        // The runner is non-dumpable before the test child exists.
        let setup_prctl = position(&runner, "libc.prctl(4, 0, 0, 0, 0) == 0");
        let spawn = position(&runner, "subprocess.run(");
        assert!(setup_prctl < spawn);
        // No project code in the runner: the test module loads in the child,
        // which is itself non-dumpable before it loads it.
        let child = runner.split("CHILD = r'''").nth(1).unwrap();
        let child = child.split("'''").next().unwrap();
        assert!(position(child, "libc.prctl(4, 0, 0, 0, 0) != 0") < position(child, "exec_module"));
        assert!(position(child, "os.set_inheritable(fd, False)") < position(child, "exec_module"));
        let parent = runner.replace(child, "");
        assert!(!parent.contains("exec_module"));
        assert!(!parent.contains("unittest"));
        assert!(!parent.contains("/workspace/sink.py"));
        // The child has no handle on the runner's stdout.
        for stdio in [
            "stdin=subprocess.DEVNULL",
            "stdout=subprocess.DEVNULL",
            "stderr=subprocess.DEVNULL",
            "pass_fds=(fd,)",
        ] {
            assert!(parent.contains(stdio), "{stdio}");
        }
        // Bounded result read through the runner's own descriptor.
        assert!(parent.contains("os.O_EXCL | os.O_NONBLOCK | os.O_NOFOLLOW"));
        assert!(position(&parent, "os.open(path") < position(&parent, "os.unlink(path)"));
        assert!(parent.contains("os.fstat(fd)"));
        assert!(parent.contains("info.st_size > RESULT_LIMIT"));
        // One marked write, starting with a newline, after the last reap().
        assert_eq!(runner.matches("sys.stdout.write").count(), 1);
        assert!(!runner.contains("print("));
        assert!(runner.contains(r"sys.stdout.write('\n' + RED_PREFIX + MARKER + ' '"));
        let reaped = position(&parent, "    os.close(fd)\n    reap()\n    emit('ran=");
        assert!(reaped > position(&parent, "        reap()\n    if code != 0:"));
        assert_eq!(parent.matches("emit('ran=").count(), 1);
        assert!(runner.contains(&format!("RED_PREFIX = '{RED_PREFIX}'")));
        assert!(runner.contains(&format!("state('{ATTACK_TEST}')")));
        assert!(runner.contains(&format!("state('{BENIGN_TEST}')")));
    }

    /// Off PID 1 (any host run) the runner refuses before running anything.
    #[test]
    fn the_red_runner_fails_closed_outside_its_container() {
        if !python3_present() {
            return;
        }
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("runner.py");
        std::fs::write(&script, red_runner()).unwrap();
        let mut child = Command::new("python3")
            .args(["-I", "-B"])
            .arg(&script)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let marker = crate::audit::poc_oracle::OracleSecrets::fresh().marker;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(format!("{marker}\n").as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(3));
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(!stdout.contains(RED_PREFIX), "{stdout}");
    }
}
