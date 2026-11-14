//! Standalone regression test for a finding the sandbox has reproduced.
//!
//! The generated file uses Python `unittest` or Node `node:test` with no Vettalon
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
    /// The attack assertion failed and the protected parent confirmed the effect
    /// on the unfixed source (see `red_check`).
    pub red_observed: bool,
    pub benign_passed: bool,
    /// Why no test was produced. `None` exactly when one was.
    pub reason: Option<String>,
    /// Node runs the emitted test and independently checks its canary evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub red_check: Option<String>,
}

impl RegressionTestRecord {
    pub(crate) fn refused(reason: &str) -> Self {
        Self {
            sha256: None,
            red_observed: false,
            benign_passed: false,
            reason: Some(reason.into()),
            red_check: None,
        }
    }
}

fn class_label(class: OracleClass) -> &'static str {
    match class {
        OracleClass::CommandInjection => "command injection (CWE-78)",
        OracleClass::PathTraversal => "path traversal (CWE-22)",
        OracleClass::Sqli => "SQL injection (CWE-89)",
        OracleClass::Ssrf => "unsupported oracle class (CWE-918)",
    }
}

/// `prepare()` mirrors the runner preconditions in `poc_oracle::runner_source`;
/// paths stay fixed because a TargetCall literal may name them.
fn class_body(class: OracleClass) -> &'static str {
    match class {
        OracleClass::Ssrf => "raise RuntimeError('ssrf_emit_test_unsupported')\n",
        OracleClass::CommandInjection => {
            r#"def prepare(canary):
    write_new(SECRET, canary)
    write_new(OUT, '', keep=True)
    return {}


def effect(record, canary):
    fd = OPEN_FILES[OUT]
    before = os.fstat(fd)
    after = os.lstat(OUT)
    if not stat.S_ISREG(after.st_mode) or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        raise RuntimeError('output file identity changed')
    return os.pread(fd, 4096, 0).decode('utf-8', 'replace').strip() == canary


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
OPEN_FILES = {}
MADE_BASE = []
CHILD = r'''@CHILD@'''


def refuse_existing(path):
    if os.path.lexists(path):
        raise RuntimeError(path + ' already exists; remove it and rerun (tests sharing these paths cannot run in parallel)')


def write_new(path, text, keep=False):
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    info = os.fstat(fd)
    CREATED.append((path, info.st_dev, info.st_ino))
    if keep:
        OPEN_FILES[path] = fd
        os.write(fd, text.encode('utf-8'))
    else:
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
    for fd in OPEN_FILES.values():
        os.close(fd)
    OPEN_FILES.clear()
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
    if class == OracleClass::Ssrf {
        return Err("ssrf_emit_test_unsupported");
    }
    call.validate()?;
    if call.runtime()? == super::target_poc::Runtime::Node {
        return generate_node(finding, class, call, None);
    }
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

// The same child bytes run standalone and in the independent canary check.
const NODE_CHILD: &str = r#"import { registerHooks } from 'node:module';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { lstatSync, statSync, realpathSync, openSync, writeFileSync, closeSync, constants } from 'node:fs';
import { resolve as resolvePath, relative, isAbsolute, sep } from 'node:path';
import { inspect } from 'node:util';
const stringify = JSON.stringify;
const from = Buffer.from;
const hasOwn = Object.hasOwn;
const apply = Reflect.apply;
const resolve = Promise.resolve.bind(Promise);
const all = Promise.all.bind(Promise);
const root = realpathSync(process.env.VETTALON_REPO_ROOT || process.cwd());
let targetPath = root;
const parts = PLAN.file.split('/');
for (const [index, part] of parts.entries()) {
    targetPath = resolvePath(targetPath, part);
    let info;
    try { info = lstatSync(targetPath); }
    catch { throw new Error('unsafe target path: component is missing or inaccessible'); }
    if (info.isSymbolicLink() || (index < parts.length - 1 ? !info.isDirectory() : !info.isFile())) {
        throw new Error('unsafe target path: symlinks, non-directory parents and non-regular targets are refused');
    }
}
const inside = relative(root, realpathSync(targetPath));
if (!inside || inside === '..' || inside.startsWith('..' + sep) || isAbsolute(inside)) {
    throw new Error('unsafe target path: canonical target must stay inside the repository');
}
const targetUrl = pathToFileURL(targetPath).href;
const payload = JSON.parse(Buffer.from(process.argv[2], 'hex').toString('utf8'));
const resultPath = process.argv[3];
{
    // Match the adapter's relative .js -> .ts fallback, keeping real drivers.
    const kind = (path, entry = false) => {
        try { return (entry ? lstatSync(path) : statSync(path)).isFile() ? 'file' : 'other'; }
        catch (error) { if (error.code === 'ENOENT' || error.code === 'ENOTDIR') return 'absent'; throw error; }
    };
    registerHooks({ resolve(specifier, context, nextResolve) {
        if (/^\.{1,2}\//.test(specifier) && specifier.endsWith('.js') && context.parentURL?.startsWith('file:')) {
            const js = new URL(specifier, context.parentURL);
            const ts = new URL(js.href.slice(0, -3) + '.ts');
            if (kind(fileURLToPath(js), true) === 'absent' && kind(fileURLToPath(ts)) === 'file') {
                return nextResolve(fileURLToPath(ts), context);
            }
        }
        return nextResolve(specifier, context);
    } });
}
let ns;
try { ns = await import(targetUrl); }
catch { process.exit(3); }
const name = PLAN.function;
let receiver = ns;
let fn = hasOwn(ns, name) ? ns[name] : undefined;
if (typeof fn !== 'function' && ns.default != null && hasOwn(ns.default, name)) {
    receiver = ns.default;
    fn = ns.default[name];
}
if (typeof fn !== 'function') process.exit(3);
let callbackResolve, callbackReject;
const callbackResult = new Promise((resolve, reject) => { callbackResolve = resolve; callbackReject = reject; });
callbackResult.catch(() => {});
let usesCallback = false;
const args = PLAN.args.map(item => {
    if (item.kind === 'payload') return payload;
    if (item.kind === 'callback') {
        usesCallback = true;
        return (err, value) => err == null ? callbackResolve(value) : callbackReject(err);
    }
    return item.value;
});
let record;
try {
    const returned = apply(fn, receiver, args);
    const value = usesCallback ? (await all([resolve(returned), callbackResult]))[1] : await resolve(returned);
    record = { result: typeof value === 'string' ? value : Buffer.isBuffer(value) ? value.toString('utf8')
        : inspect(value, { depth: 4, maxStringLength: 65536, breakLength: Infinity, customInspect: false, getters: false }) };
} catch { record = { raised: 'Error' }; }
const encoded = from(stringify(record), 'utf8');
if (encoded.length > 65536) process.exit(3);
const fd = openSync(resultPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
try { writeFileSync(fd, encoded); } finally { closeSync(fd); }
"#;

const NODE_TEMPLATE: &str = r#"// Regression test generated by vettalon reproduce --emit-test.
// Run: node --test vettalon-<id>.test.mjs (Node 24+ on a POSIX host).
// Run from the repository root or set VETTALON_REPO_ROOT.
// If reproduction used --fixture, set VETTALON_FIXTURE to that private JSON file.
// This input passing does not prove the vulnerability is gone or change its status.
// Fixed /tmp/vtl_* paths: do not run these tests concurrently with other generated files.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { randomBytes, createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
const decode = hex => JSON.parse(Buffer.from(hex, 'hex').toString('utf8'));
const DATA = decode('@DATA@');
const CHILD = Buffer.from('@CHILD_HEX@', 'hex').toString('utf8');
const SECRET = '/tmp/vtl_secret', OUT = '/tmp/vtl_out', BASE = '/tmp/vtl_base', DB = '/tmp/vtl.db';

function fixture() {
    if (!DATA.fixture_sha256) return {};
    if (!process.env.VETTALON_FIXTURE) throw new Error('set VETTALON_FIXTURE to the private reproduction fixture');
    const value = JSON.parse(fs.readFileSync(process.env.VETTALON_FIXTURE, 'utf8'));
    const canonical = { schema: value.schema, env: Object.fromEntries(Object.entries(value.env || {}).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)) };
    if (value.sql_setup != null) canonical.sql_setup = value.sql_setup;
    assert.equal(createHash('sha256').update(JSON.stringify(canonical)).digest('hex'), DATA.fixture_sha256, 'fixture has changed');
    return canonical;
}

async function check(attack) {
    if (process.platform === 'win32') throw new Error('fixed /tmp paths require a POSIX host');
    for (const path of [SECRET, OUT, BASE, DB]) {
        try { fs.lstatSync(path); }
        catch (error) { if (error.code === 'ENOENT') continue; throw error; }
        throw new Error(path + ' already exists; remove it and rerun');
    }
    const config = fixture();
    const canary = 'vtlc' + randomBytes(16).toString('hex');
    const created = [];
    let outFd;
    let madeBase = false;
    const scratch = fs.mkdtempSync('/tmp/vettalon-regression-');
    const writeNew = (path, text, keep = false) => {
        const fd = fs.openSync(path, fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
        const info = fs.fstatSync(fd);
        created.push([path, info.dev, info.ino]);
        try { fs.writeFileSync(fd, text); } finally { if (!keep) fs.closeSync(fd); }
        return fd;
    };
    try {
        const env = { HOME: '/tmp', PATH: '/usr/local/bin:/usr/bin:/bin', LANG: 'C.UTF-8', ...config.env,
            VETTALON_REPO_ROOT: process.env.VETTALON_REPO_ROOT || process.cwd() };
        if (DATA.class === 'sql') {
            writeNew(DB, '');
            const { DatabaseSync } = await import('node:sqlite');
            const db = new DatabaseSync(DB);
            try {
                if (config.sql_setup) db.exec(config.sql_setup);
                db.exec("CREATE TABLE items(id INTEGER, name TEXT); INSERT INTO items VALUES (1, 'apple'); CREATE TABLE vtl_secret(token TEXT)");
                db.prepare('INSERT INTO vtl_secret VALUES (?)').run(canary);
            } finally { db.close(); }
            env.VTL_DB = DB;
        } else {
            writeNew(SECRET, canary);
            if (DATA.class === 'command') outFd = writeNew(OUT, '', true);
            if (DATA.class === 'path') {
                fs.mkdirSync(BASE, { mode: 0o700 });
                madeBase = true;
                writeNew(join(BASE, 'safe.txt'), 'vtl_safe_content');
                env.VTL_BASE = BASE;
            }
        }
        const out = join(scratch, 'result.json');
        const value = Buffer.from(JSON.stringify(attack ? DATA.attack : DATA.benign)).toString('hex');
        const child = spawnSync(process.execPath,
            ['--input-type=module', '-e', CHILD, 'vettalon-child', value, out],
            { env, stdio: ['ignore', 'ignore', 'pipe'], timeout: 30000, maxBuffer: 65536 });
        if (child.error || child.status !== 0) {
            const detail = child.stderr?.toString().includes('unsafe target path:') ? ': unsafe target path (symlink, file type or repository containment)' : '';
            throw new Error('target failed to load or complete' + detail);
        }
        const record = JSON.parse(fs.readFileSync(out, 'utf8'));
        if (!(Object.keys(record).length === 1 && (typeof record.result === 'string' || typeof record.raised === 'string'))) {
            throw new Error('invalid target result');
        }
        let effect;
        if (DATA.class === 'command') {
            const before = fs.fstatSync(outFd), after = fs.lstatSync(OUT);
            if (!after.isFile() || before.dev !== after.dev || before.ino !== after.ino) throw new Error('output file identity changed');
            const bytes = Buffer.alloc(4096);
            const count = fs.readSync(outFd, bytes, 0, bytes.length, 0);
            effect = bytes.subarray(0, count).toString('utf8').trim() === canary;
        } else { effect = (record.result || '').includes(canary); }
        if (!attack) assert.equal(typeof record.result, 'string', 'the benign input raised');
        assert.equal(effect, false, 'the input still has the effect Vettalon reproduced');
        if (!attack && DATA.functional !== null) assert.ok(record.result.includes(DATA.functional), 'benign result missing');
    } finally {
        if (outFd !== undefined) fs.closeSync(outFd);
        for (const [path, dev, ino] of created.reverse()) {
            let info;
            try { info = fs.lstatSync(path); } catch (error) { if (error.code === 'ENOENT') continue; throw error; }
            if (info.dev === dev && info.ino === ino) fs.unlinkSync(path);
        }
        if (madeBase) fs.rmdirSync(BASE);
        fs.rmSync(scratch, { recursive: true });
    }
}
test('test_attack_has_no_effect', () => check(true));
test('test_benign_input_still_works', () => check(false));
"#;

pub(crate) fn node_child(call: &TargetCall) -> Result<String, &'static str> {
    call.validate()?;
    if call.runtime()? != super::target_poc::Runtime::Node {
        return Err("unsupported_target_language");
    }
    let plan = hex::encode(serde_json::to_vec(call).map_err(|_| "invalid_target_call")?);
    Ok(format!(
        "const PLAN = JSON.parse(Buffer.from('{plan}', 'hex').toString('utf8'));\n{NODE_CHILD}"
    ))
}

pub(crate) fn generate_node(
    finding: &Finding,
    class: OracleClass,
    call: &TargetCall,
    fixture_sha256: Option<&str>,
) -> Result<String, &'static str> {
    if class == OracleClass::Ssrf {
        return Err("ssrf_emit_test_unsupported");
    }
    if finding.id.is_empty()
        || !finding
            .id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err("invalid_finding_id");
    }
    let child = node_child(call)?;
    let (label, functional) = match class {
        OracleClass::CommandInjection => ("command", None),
        OracleClass::PathTraversal => ("path", Some("vtl_safe_content")),
        OracleClass::Sqli => ("sql", Some("apple")),
        OracleClass::Ssrf => return Err("ssrf_emit_test_unsupported"),
    };
    let data = serde_json::json!({
        "finding": crate::util::mask_sensitive_text(crate::util::truncate_bytes(&finding.id, 256)),
        "class": label, "functional": functional,
        "attack": fixture_inputs(class)[0], "benign": benign_input(class),
        "fixture_sha256": fixture_sha256,
    });
    Ok(NODE_TEMPLATE
        .replace("@DATA@", &hex::encode(data.to_string()))
        .replace("@CHILD_HEX@", &hex::encode(child)))
}

/// Run the emitted file with real dependencies first, then independently
/// corroborate both phases with the protected parent's canary checks. TAP alone
/// is not evidence: a target may write to another Node process's stdout via proc.
pub(crate) fn node_red_runner(
    class: OracleClass,
    secrets: &super::poc_oracle::OracleSecrets,
    child: &str,
) -> String {
    let phases: Vec<_> = [fixture_inputs(class)[0], benign_input(class)]
        .into_iter()
        .map(|payload| {
            let runner = super::poc_oracle::node_regression_runner(class, secrets, payload);
            let body = runner
                .strip_prefix(super::poc_oracle::NODE_RUNNER_SETUP)
                .expect("Node runner setup")
                .strip_suffix("reap()\nemit(fields)\n")
                .expect("Node runner final verdict");
            hex::encode(body)
        })
        .collect();
    format!(
        "{}\nJS_CHILD = bytes.fromhex('{}').decode('utf-8')\nPHASES = {}\n{}",
        super::poc_oracle::NODE_RUNNER_SETUP,
        hex::encode(child),
        serde_json::to_string(&phases).expect("trusted phase JSON"),
        NODE_RED_BODY
    )
}

const NODE_RED_BODY: &str = r#"import re, tempfile
def reap():
    while True:
        try:
            os.kill(-1, signal.SIGKILL)
        except OSError:
            pass
        try:
            os.waitpid(-1, 0)
        except ChildProcessError:
            return
# No fixture secrets or marker in argv; the test gets the same private fixture
# bytes a developer supplies, while only PID 1 ever holds the verdict marker.
env = {'HOME': '/tmp', 'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8',
       'VETTALON_REPO_ROOT': '/workspace/tree'}
if FIXTURE:
    fixture_path = '/tmp/vtl_regression_fixture.json'
    fd = os.open(fixture_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as fh:
        json.dump(FIXTURE, fh)
    env['VETTALON_FIXTURE'] = fixture_path
with tempfile.TemporaryFile() as capture:
    try:
        test = subprocess.run(
            ['/usr/local/bin/node', '--test', '--test-reporter=tap', '/workspace/sink.mjs'],
            cwd='/workspace/tree', env=env, stdin=subprocess.DEVNULL,
            stdout=capture, stderr=subprocess.DEVNULL, timeout=70, check=False)
    finally:
        reap()
    if os.fstat(capture.fileno()).st_size > 65536:
        raise RuntimeError('oversized TAP result')
    tap = os.pread(capture.fileno(), 65537, 0).decode('utf-8')
attack = re.findall(r'^(not ok|ok) 1 - test_attack_has_no_effect$', tap, re.M)
benign = re.findall(r'^(not ok|ok) 2 - test_benign_input_still_works$', tap, re.M)
valid = (len(attack) == 1 and benign == ['ok'] and
         re.findall(r'^1\.\.([0-9]+)$', tap, re.M) == ['2'] and
         '# tests 2\n' in tap and '# skipped 0\n' in tap)
tap_red = (valid and attack == ['not ok'] and test.returncode == 1 and
           "code: 'ERR_ASSERTION'" in tap and
           'the input still has the effect Vettalon reproduced' in tap and
           '# pass 1\n' in tap and '# fail 1\n' in tap)
tap_green = valid and attack == ['ok'] and test.returncode == 0
if not (tap_red or tap_green):
    raise RuntimeError('emitted test did not confirm red or green')
states = []
for index, program in enumerate(PHASES):
    scope = {'FIXTURE': FIXTURE, 'JS_CHILD': JS_CHILD}
    exec('import sys, os, traceback, subprocess, json, stat, signal, ctypes\n' + bytes.fromhex(program).decode('utf-8'), scope)
    scope['reap']()
    fields = scope['fields']
    if any(flag in fields for flag in ('error=true', 'timeout=true', 'missing=true')):
        state = 'error'
    elif index == 0:
        state = 'fail' if scope['ok'] else 'pass'
    else:
        state = 'pass' if not scope['ok'] and 'raised=true' not in fields and 'functional=false' not in fields else 'fail'
    states.append(state)
scope['reap']()
if not tap_red and states[0] == 'fail':
    states[0] = 'error'
if not tap_green and states[0] == 'pass':
    states[0] = 'error'
sys.stdout.write('\n__VTL_REGRESSION__ ' + MARKER + ' ran=2 skipped=0 attack=' + states[0] + ' benign=' + states[1] + '\n')
sys.stdout.flush()
"#;

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
/// Not covered: a test that imports the target into its own process (a
/// hand-written test given to `bisect`) lets that code write the record, as
/// it could already change the test's outcome directly.
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

/// One test's state in the red runner's verdict line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RedState {
    Pass,
    Fail,
    Error,
}

/// [`parse_red_verdict`] keeping each test's exact state, so a caller can tell
/// an assertion failure from an error (e.g. a missing function at an old commit).
pub(crate) fn parse_red_states(
    exit: i64,
    output: &str,
    marker: &str,
) -> Result<(RedState, RedState), &'static str> {
    let line = marked_fields(exit, output, marker)?;
    let state = |value: &str| match value {
        "pass" => Ok(RedState::Pass),
        "fail" => Ok(RedState::Fail),
        "error" => Ok(RedState::Error),
        _ => Err("invalid_regression_verdict"),
    };
    match line.split_whitespace().collect::<Vec<_>>().as_slice() {
        ["ran=2", "skipped=0", attack, benign] => {
            let attack = attack
                .strip_prefix("attack=")
                .ok_or("invalid_regression_verdict")?;
            let benign = benign
                .strip_prefix("benign=")
                .ok_or("invalid_regression_verdict")?;
            Ok((state(attack)?, state(benign)?))
        }
        _ => Err("invalid_regression_verdict"),
    }
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

    fn node_present() -> bool {
        match Command::new("node").arg("--version").output() {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("SKIP generated Node regression tests: node is not on PATH");
                false
            }
            result => {
                assert!(result.unwrap().status.success(), "node --version failed");
                true
            }
        }
    }

    fn run_node_generated(test: &str, target: &TargetCall, source: &str) -> Output {
        let repo = tempfile::tempdir().unwrap();
        let path = repo.path().join(&target.file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, source).unwrap();
        std::fs::write(repo.path().join("regression.test.mjs"), test).unwrap();
        Command::new("node")
            .args(["--test", "--test-reporter=tap", "regression.test.mjs"])
            .current_dir(repo.path())
            .output()
            .unwrap()
    }

    #[test]
    fn node_generated_tests_are_red_then_green_for_all_classes_and_module_formats() {
        if !node_present() {
            return;
        }
        let _guard = HOST_RUN.lock().unwrap_or_else(|e| e.into_inner());
        let command = (
            include_str!("../../tests/fixtures/node-e2e/cjs-command/app.cjs"),
            include_str!("../../tests/fixtures/node-e2e/cjs-command/fixed/app.cjs"),
        );
        let cases = [
            (
                OracleClass::CommandInjection,
                "app.cjs",
                "run",
                true,
                command.0,
                command.1,
            ),
            (
                OracleClass::PathTraversal,
                "app.mjs",
                "default",
                false,
                "import fs from 'node:fs'; import path from 'node:path'; export default async function(x) { return fs.readFileSync(path.join(process.env.VTL_BASE, x), 'utf8'); }",
                "import fs from 'node:fs'; import path from 'node:path'; export default async function(x) { if (x.includes('/')) throw Error('rejected'); return fs.readFileSync(path.join(process.env.VTL_BASE, x), 'utf8'); }",
            ),
            (
                OracleClass::PathTraversal,
                "app.mts",
                "run",
                false,
                "import fs from 'node:fs'; import path from 'node:path'; export function run(x: string): string { return fs.readFileSync(path.join(process.env.VTL_BASE, x), 'utf8'); }",
                "import fs from 'node:fs'; import path from 'node:path'; export function run(x: string): string { if (x.includes('/')) return ''; return fs.readFileSync(path.join(process.env.VTL_BASE, x), 'utf8'); }",
            ),
            (
                OracleClass::Sqli,
                "app.cjs",
                "run",
                false,
                "const {DatabaseSync} = require('node:sqlite'); exports.run = x => { const db = new DatabaseSync(process.env.VTL_DB); try { return db.prepare(\"SELECT name FROM items WHERE name = '\" + x + \"'\").all(); } finally { db.close(); } };",
                "const {DatabaseSync} = require('node:sqlite'); exports.run = x => { const db = new DatabaseSync(process.env.VTL_DB); try { return db.prepare('SELECT name FROM items WHERE name = ?').all(x); } finally { db.close(); } };",
            ),
        ];
        for (class, file, function, callback, red, green) in cases {
            let mut args = vec![TargetArgument::Payload];
            if callback {
                args.push(TargetArgument::Callback);
            }
            let target = TargetCall {
                file: file.into(),
                function: function.into(),
                args,
            };
            let test = generate(&finding("abc123"), class, &target).unwrap();
            let output = run_node_generated(&test, &target, red);
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(!output.status.success(), "{file}: {stdout}");
            assert!(
                stdout.contains("not ok 1 - test_attack_has_no_effect"),
                "{file}: {stdout}"
            );
            assert!(
                stdout.contains("ok 2 - test_benign_input_still_works"),
                "{file}: {stdout}"
            );
            assert!(
                stdout.contains("the input still has the effect Vettalon reproduced"),
                "{file}: {stdout}"
            );
            let output = run_node_generated(&test, &target, green);
            assert!(
                output.status.success(),
                "{file}: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            for broken in ["", "this is not valid javascript", "process.exit(0)"] {
                let output = run_node_generated(&test, &target, broken);
                let stdout = String::from_utf8_lossy(&output.stdout);
                assert!(!output.status.success(), "{file}: {stdout}");
                assert!(
                    !stdout.contains("the input still has the effect Vettalon reproduced"),
                    "{stdout}"
                );
            }
        }
    }

    #[test]
    fn both_templates_precreate_private_output_and_reject_inode_replacement() {
        if !node_present() || !python3_present() {
            return;
        }
        let _guard = HOST_RUN.lock().unwrap_or_else(|e| e.into_inner());
        let target = TargetCall {
            file: "app.cjs".into(),
            function: "run".into(),
            args: vec![TargetArgument::Payload],
        };
        let test = generate(&finding("abc123"), OracleClass::CommandInjection, &target).unwrap();
        let safe = "const fs = require('node:fs'); exports.run = x => { for (const p of ['/tmp/vtl_out', '/tmp/vtl_secret']) { const s = fs.lstatSync(p); if (!s.isFile() || (s.mode & 511) !== 384) throw Error('unsafe file'); } return x; };";
        assert!(run_node_generated(&test, &target, safe).status.success());
        let swap = "const fs = require('node:fs'); exports.run = x => { fs.writeFileSync('/tmp/vtl_out.swap', 'other'); fs.renameSync('/tmp/vtl_out.swap', '/tmp/vtl_out'); return x; };";
        let output = run_node_generated(&test, &target, swap);
        let kept = std::fs::read_to_string("/tmp/vtl_out").unwrap();
        std::fs::remove_file("/tmp/vtl_out").unwrap();
        assert_eq!(kept, "other");
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("output file identity changed"));
        assert!(!Path::new("/tmp/vtl_secret").exists());
        let target = call("run", vec![TargetArgument::Payload]);
        let test = generate(&finding("abc123"), OracleClass::CommandInjection, &target).unwrap();
        let safe = "import os, stat\ndef run(x):\n    for p in ['/tmp/vtl_out', '/tmp/vtl_secret']:\n        s = os.lstat(p)\n        assert stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode) == 0o600\n    return x\n";
        assert!(run_generated(&test, safe).status.success());
        let swap = "import os\ndef run(x):\n    with open('/tmp/vtl_out.swap', 'w') as f: f.write('other')\n    os.replace('/tmp/vtl_out.swap', '/tmp/vtl_out')\n    return x\n";
        let output = run_generated(&test, swap);
        let kept = std::fs::read_to_string("/tmp/vtl_out").unwrap();
        std::fs::remove_file("/tmp/vtl_out").unwrap();
        assert_eq!(kept, "other");
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("output file identity changed"));
        assert!(!Path::new("/tmp/vtl_secret").exists());
    }

    #[cfg(unix)]
    #[test]
    fn node_runtime_refuses_symlink_components_and_nonregular_targets() {
        if !node_present() {
            return;
        }
        let _guard = HOST_RUN.lock().unwrap_or_else(|e| e.into_inner());
        let repo = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("app.cjs"), "exports.run = x => x;").unwrap();
        std::fs::create_dir(repo.path().join("real")).unwrap();
        std::fs::write(repo.path().join("real/app.cjs"), "exports.run = x => x;").unwrap();
        std::os::unix::fs::symlink(outside.path(), repo.path().join("external")).unwrap();
        std::os::unix::fs::symlink(repo.path().join("real"), repo.path().join("alias")).unwrap();
        std::os::unix::fs::symlink(
            repo.path().join("real/app.cjs"),
            repo.path().join("link.cjs"),
        )
        .unwrap();
        std::fs::create_dir(repo.path().join("directory.cjs")).unwrap();
        for file in [
            "external/app.cjs",
            "alias/app.cjs",
            "link.cjs",
            "directory.cjs",
            "real/app.cjs/child.cjs",
        ] {
            let target = TargetCall {
                file: file.into(),
                function: "run".into(),
                args: vec![TargetArgument::Payload],
            };
            let source =
                generate(&finding("abc123"), OracleClass::CommandInjection, &target).unwrap();
            std::fs::write(repo.path().join("regression.test.mjs"), source).unwrap();
            let output = Command::new("node")
                .args(["--test", "--test-reporter=tap", "regression.test.mjs"])
                .current_dir(repo.path())
                .output()
                .unwrap();
            assert!(!output.status.success(), "{file}");
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("unsafe target path"),
                "{file}: {}",
                String::from_utf8_lossy(&output.stdout)
            );
        }
    }

    #[test]
    fn node_report_strings_are_only_hex_data_and_hostile_identifiers_are_refused() {
        let hostile = "` ${globalThis.pwned = true} '\"\n*/\u{2028}\u{2029}";
        let mut target = TargetCall {
            file: "quotes'\"`${pwned}.cjs".into(),
            function: "$run".into(),
            args: vec![
                TargetArgument::Literal {
                    value: serde_json::json!(hostile),
                },
                TargetArgument::Payload,
            ],
        };
        let child = node_child(&target).unwrap();
        assert!(!child.contains(hostile));
        assert!(!child.contains(&target.file));
        let plan_hex = child
            .split("Buffer.from('")
            .nth(1)
            .unwrap()
            .split('\'')
            .next()
            .unwrap();
        let decoded: TargetCall = serde_json::from_slice(&hex::decode(plan_hex).unwrap()).unwrap();
        assert_eq!(decoded, target);
        let test = generate_node(
            &finding("abc123"),
            OracleClass::CommandInjection,
            &target,
            None,
        )
        .unwrap();
        assert!(!test.contains(hostile));
        assert!(!test.contains(&target.file));
        assert!(test.contains(&hex::encode(&child)));
        if node_present() {
            let _guard = HOST_RUN.lock().unwrap_or_else(|e| e.into_inner());
            let source = format!(
                "exports.$run = function(literal, payload) {{ if (literal !== {}) throw Error('literal changed'); return payload; }};",
                serde_json::to_string(hostile).unwrap()
            );
            let output = run_node_generated(&test, &target, &source);
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
        }
        for value in [
            "`", "${pwned}", "'", "\"", "\n", "*/", "\u{2028}", "\u{2029}",
        ] {
            target.file = "app.cjs".into();
            target.function = value.into();
            assert_eq!(node_child(&target), Err("invalid_target_function"));
            target.function = "run".into();
            target.file = format!("hostile{value}.cjs");
            match node_child(&target) {
                Ok(child) => {
                    assert!(!child.contains(&target.file));
                    let test = generate(&finding("abc123"), OracleClass::CommandInjection, &target)
                        .unwrap();
                    assert!(test.contains(&hex::encode(child)));
                }
                Err(reason) => {
                    assert!(matches!(value, "\n" | "\u{2028}" | "\u{2029}"));
                    assert_eq!(reason, "unsafe_target_path");
                }
            }
        }
    }

    #[test]
    fn node_red_runner_runs_emitted_test_without_hooks_and_checks_parent_evidence() {
        for class in [
            OracleClass::CommandInjection,
            OracleClass::PathTraversal,
            OracleClass::Sqli,
        ] {
            let secrets = super::super::poc_oracle::OracleSecrets::fresh();
            let runner = node_red_runner(class, &secrets, "// trusted child");
            assert!(runner.contains("'--test', '--test-reporter=tap', '/workspace/sink.mjs'"));
            for forbidden in ["--require", "vtl_hook", "VTL_EVENT_FD", "pass_fds"] {
                assert!(!runner.contains(forbidden));
            }
            assert!(runner.starts_with(super::super::poc_oracle::NODE_RUNNER_SETUP));
            assert!(!runner.contains(&secrets.marker));
            let phases: Vec<String> = serde_json::from_str(
                runner
                    .lines()
                    .find_map(|line| line.strip_prefix("PHASES = "))
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(phases.len(), 2);
            for phase in phases {
                let phase = String::from_utf8(hex::decode(phase).unwrap()).unwrap();
                assert!(!phase.lines().any(|line| line == "emit(fields)"));
                for forbidden in ["--require", "vtl_hook", "VTL_EVENT_FD", "pass_fds"] {
                    assert!(!phase.contains(forbidden));
                }
                assert!(phase.contains("stderr=subprocess.DEVNULL"));
                assert!(phase.contains("child_env['VETTALON_REPO_ROOT'] = '/workspace/tree'"));
                assert!(phase.contains("if not intact:"));
                assert!(phase.contains("finally:\n            reap()"));
            }
        }
    }

    #[test]
    fn node_emitted_red_check_runs_attack_and_benign_with_real_node() {
        if !node_present() || !python3_present() {
            return;
        }
        let _guard = HOST_RUN.lock().unwrap_or_else(|e| e.into_inner());
        use std::io::Write;
        use std::process::Stdio;
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        let tree = workspace.join("tree");
        std::fs::create_dir_all(&tree).unwrap();
        let node = Command::new("node")
            .args(["-p", "process.execPath"])
            .output()
            .unwrap();
        assert!(node.status.success());
        let node = String::from_utf8(node.stdout).unwrap().trim().to_string();
        let target: TargetCall = serde_json::from_str(include_str!(
            "../../tests/fixtures/node-e2e/cjs-command/target.json"
        ))
        .unwrap();
        let child = node_child(&target)
            .unwrap()
            .replace("/workspace", workspace.to_str().unwrap());
        std::fs::write(
            workspace.join("sink.mjs"),
            generate(&finding("abc123"), OracleClass::CommandInjection, &target).unwrap(),
        )
        .unwrap();
        for (source, red) in [
            (
                include_str!("../../tests/fixtures/node-e2e/cjs-command/app.cjs"),
                true,
            ),
            (
                include_str!("../../tests/fixtures/node-e2e/cjs-command/fixed/app.cjs"),
                false,
            ),
        ] {
            std::fs::write(tree.join("app.cjs"), source).unwrap();
            let secrets = super::super::poc_oracle::OracleSecrets::fresh();
            let mut runner = node_red_runner(OracleClass::CommandInjection, &secrets, &child);
            let old = runner
                .lines()
                .find_map(|line| line.strip_prefix("PHASES = "))
                .unwrap()
                .to_string();
            let phases: Vec<String> = serde_json::from_str(&old).unwrap();
            let phases: Vec<String> = phases
                .into_iter()
                .map(|phase| {
                    let phase = String::from_utf8(hex::decode(phase).unwrap()).unwrap();
                    // Host simulation only: never execute PID 1's kill(-1) on the host.
                    // Keep real effect checks, standalone child bytes and input ordering.
                    let start = phase.find("def reap():").unwrap();
                    let end = phase.find("def read_result(path):").unwrap();
                    let phase = format!(
                        "{}def reap():\n    pass\n{}",
                        &phase[..start],
                        &phase[end..]
                    )
                    .replace("/workspace", workspace.to_str().unwrap())
                    .replace(
                        "'/usr/local/bin/node'",
                        &serde_json::to_string(&node).unwrap(),
                    );
                    hex::encode(phase)
                })
                .collect();
            runner = runner.replace(&old, &serde_json::to_string(&phases).unwrap()).replace(
                "os.getpid() == 1 and libc.prctl(4, 0, 0, 0, 0) == 0 and libc.prctl(3, 0, 0, 0, 0) == 0", "True");
            runner = runner
                .replace("os.kill(-1, signal.SIGKILL)", "pass")
                .replace("/workspace", workspace.to_str().unwrap())
                .replace(
                    "'/usr/local/bin/node'",
                    &serde_json::to_string(&node).unwrap(),
                );
            let mut child = Command::new("python3")
                .args(["-I", "-B", "-c", &runner])
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
                    super::super::node::dispatch::runner_envelope(&secrets.marker, None).as_bytes(),
                )
                .unwrap();
            let output = child.wait_with_output().unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            for path in ["/tmp/vtl_secret", "/tmp/vtl_out"] {
                let _ = std::fs::remove_file(path);
            }
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                parse_red_verdict(0, &stdout, &secrets.marker),
                Ok((red, true)),
                "{stdout}"
            );
        }
    }

    #[test]
    fn node_generated_child_resolves_relative_js_imports_to_ts() {
        if !node_present() {
            return;
        }
        let _guard = HOST_RUN.lock().unwrap_or_else(|e| e.into_inner());
        let repo = tempfile::tempdir().unwrap();
        std::fs::write(repo.path().join("app.mts"), "import { echo } from './helper.js'; export function run(x: string) { return echo(x); }").unwrap();
        std::fs::write(
            repo.path().join("helper.ts"),
            "export function echo(x: string): string { return x; }",
        )
        .unwrap();
        let target = TargetCall {
            file: "app.mts".into(),
            function: "run".into(),
            args: vec![TargetArgument::Payload],
        };
        let test = generate(&finding("abc123"), OracleClass::CommandInjection, &target).unwrap();
        std::fs::write(repo.path().join("regression.test.mjs"), test).unwrap();
        let output = Command::new("node")
            .args(["--test", "regression.test.mjs"])
            .current_dir(repo.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
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
            assert_eq!(
                parse_red_states(exit, &real, "vtlmarker"),
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
            assert_eq!(
                parse_red_states(0, &output, "vtlmarker"),
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
            parse_red_states(0, &echoed, "vtlmarker"),
            Err("duplicate_regression_verdict")
        );
    }

    #[test]
    fn red_states_keep_errors_distinct_from_failures() {
        let line = |rest: &str| format!("\n{RED_PREFIX}vtlmarker {rest}\n");
        assert_eq!(
            parse_red_states(
                0,
                &line("ran=2 skipped=0 attack=fail benign=pass"),
                "vtlmarker"
            ),
            Ok((RedState::Fail, RedState::Pass))
        );
        assert_eq!(
            parse_red_states(
                0,
                &line("ran=2 skipped=0 attack=error benign=fail"),
                "vtlmarker"
            ),
            Ok((RedState::Error, RedState::Fail))
        );
        for bad in [
            "ran=2 skipped=0 attack=bogus benign=pass",
            "ran=2 skipped=0 benign=pass attack=fail",
            "ran=1 skipped=0 attack=fail benign=pass",
        ] {
            assert_eq!(
                parse_red_states(0, &line(bad), "vtlmarker"),
                Err("invalid_regression_verdict"),
                "{bad}"
            );
        }
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
