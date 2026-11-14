//! Structured calls into the actual prepared Python source, never a rewritten sink.
//!
//! The call plan is data, not Python source.  Vettalon writes a fixed adapter
//! which hashes and compiles the selected source bytes inside a fresh,
//! network-disabled container.  Three independent containers run an attack,
//! a benign control, and an attack with fresh nonces.  A receipt remains
//! `Inconclusive` on stale/unsafe input, incomplete capture, a malformed
//! harness verdict, or any identity drift.  Nothing in this module changes a
//! finding's status.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::fix_diff;
use super::node::dispatch::{NodeExecution, NodeOptions, Session as NodeSession};
use super::poc::{POC_TIMEOUT, PocBudget};
use super::poc_oracle::{
    OracleClass, OracleSecrets, benign_input, classify_finding_target, classify_target,
    fixture_inputs, oracle_classes, runner_command, runner_input,
    target_runner as oracle_target_runner,
};
use super::regression_test::{self, RegressionTestRecord};
use super::schema::{Finding, sha256_hex};
use super::verification::{CompileInput, HostObservations, VerificationEvent, compile_ir};
use super::verification_context::{
    SnapshotExclusions, is_sha256, snapshot_digest, source_file_digest,
};
use std::sync::Arc;
use vettalon_contract::verification::{
    BackendKind, CleanupState, DerivedVerdict, ReplayGrade, TamperSignal,
};

const TARGET_CALL_MAX_BYTES: usize = 8 * 1024;
const TARGET_MAX_ARGS: usize = 16;
const TARGET_LITERAL_MAX_DEPTH: usize = 8;
const TARGET_SOURCE_MAX_BYTES: u64 = 4 * 1024 * 1024;
/// v2: the marker reaches the runner on stdin only, the runner is PID 1
/// and non-dumpable, and a raising target call reports `raised=true`.
const TARGET_HARNESS_VERSION: &str = "vettalon-target-oracle-v2";

/// Execution runtime selected solely by the target's file extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Runtime {
    Python,
    Node,
}

impl Runtime {
    pub fn for_file(file: &str) -> Result<Self, &'static str> {
        let safe = vettalon_contract::safe_path::SafeRepoPath::parse(file)
            .map_err(|_| "unsafe_target_path")?;
        // Preserve the original `.py` suffix rule, including dotfile basenames.
        match safe
            .as_str()
            .rsplit_once('.')
            .map(|(_, extension)| extension)
        {
            Some("py") => Ok(Runtime::Python),
            Some("js" | "cjs" | "mjs" | "ts" | "cts" | "mts") => Ok(Runtime::Node),
            _ => Err("unsupported_target_language"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TargetArgument {
    Payload,
    /// Node-only error-first callback; D7 supplies `(err, value)` handling.
    Callback,
    Literal {
        value: Value,
    },
}

impl<'de> Deserialize<'de> for TargetArgument {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
        enum Wire {
            Payload {},
            Callback {},
            Literal { value: Value },
        }
        Ok(match Wire::deserialize(deserializer)? {
            Wire::Payload {} => TargetArgument::Payload,
            Wire::Callback {} => TargetArgument::Callback,
            Wire::Literal { value } => TargetArgument::Literal { value },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetCall {
    pub file: String,
    pub function: String,
    pub args: Vec<TargetArgument>,
}

impl TargetCall {
    /// No content sniffing or module-format inference; Node handles ESM/CJS.
    pub fn runtime(&self) -> Result<Runtime, &'static str> {
        Runtime::for_file(&self.file)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        let safe = vettalon_contract::safe_path::SafeRepoPath::parse(&self.file)
            .map_err(|_| "unsafe_target_path")?;
        let runtime = self.runtime()?;
        let basename = safe.as_str().rsplit('/').next().unwrap_or("");
        if crate::util::is_secret_file(basename) {
            return Err("unsafe_target_path");
        }
        let valid_function = match runtime {
            Runtime::Python => valid_python_identifier(&self.function),
            Runtime::Node => valid_js_identifier(&self.function),
        };
        if !valid_function {
            return Err("invalid_target_function");
        }
        if self.args.is_empty() || self.args.len() > TARGET_MAX_ARGS {
            return Err("invalid_target_arguments");
        }
        if self
            .args
            .iter()
            .filter(|arg| matches!(arg, TargetArgument::Payload))
            .count()
            != 1
        {
            return Err("invalid_target_arguments");
        }
        let callbacks = self
            .args
            .iter()
            .filter(|arg| matches!(arg, TargetArgument::Callback))
            .count();
        if callbacks > usize::from(runtime == Runtime::Node) {
            return Err("invalid_target_arguments");
        }
        if self.args.iter().any(|arg| match arg {
            TargetArgument::Payload | TargetArgument::Callback => false,
            TargetArgument::Literal { value } => json_depth(value) > TARGET_LITERAL_MAX_DEPTH,
        }) {
            return Err("target_literal_too_deep");
        }
        let encoded = serde_json::to_vec(self).map_err(|_| "invalid_target_arguments")?;
        if encoded.len() > TARGET_CALL_MAX_BYTES {
            return Err("target_call_too_large");
        }
        Ok(())
    }
}

pub fn parse_target_call(input: &str) -> Result<TargetCall, &'static str> {
    if input.len() > TARGET_CALL_MAX_BYTES {
        return Err("target_call_too_large");
    }
    let call: TargetCall =
        vettalon_contract::strict_json::parse_strict_with_limit(input, TARGET_CALL_MAX_BYTES)
            .map_err(|_| "invalid_target_call")?;
    call.validate()?;
    Ok(call)
}

fn valid_python_identifier(value: &str) -> bool {
    const KEYWORDS: &[&str] = &[
        "False", "None", "True", "and", "as", "assert", "async", "await", "break", "class",
        "continue", "def", "del", "elif", "else", "except", "finally", "for", "from", "global",
        "if", "import", "in", "is", "lambda", "nonlocal", "not", "or", "pass", "raise", "return",
        "try", "while", "with", "yield", "match", "case",
    ];
    let mut chars = value.chars();
    matches!(chars.next(), Some(c) if c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
        && !value.starts_with("__")
        && !KEYWORDS.contains(&value)
}

/// ASCII exported bindings, with `default` explicitly allowed for ESM/CJS.
fn valid_js_identifier(value: &str) -> bool {
    // Includes strict-mode and module reserved words because the adapter is ESM.
    const RESERVED: &[&str] = &[
        "await",
        "break",
        "case",
        "catch",
        "class",
        "const",
        "continue",
        "debugger",
        "delete",
        "do",
        "else",
        "enum",
        "export",
        "extends",
        "false",
        "finally",
        "for",
        "function",
        "if",
        "implements",
        "import",
        "in",
        "instanceof",
        "interface",
        "let",
        "new",
        "null",
        "package",
        "private",
        "protected",
        "public",
        "return",
        "static",
        "super",
        "switch",
        "this",
        "throw",
        "true",
        "try",
        "typeof",
        "var",
        "void",
        "while",
        "with",
        "yield",
        "__proto__",
        "constructor",
        "prototype",
    ];
    let mut bytes = value.bytes();
    value.len() <= 64
        && matches!(bytes.next(), Some(b) if b.is_ascii_alphabetic() || b == b'_' || b == b'$')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'$')
        && !RESERVED.contains(&value)
}

fn json_depth(value: &Value) -> usize {
    match value {
        Value::Array(values) => 1 + values.iter().map(json_depth).max().unwrap_or(0),
        Value::Object(values) => 1 + values.values().map(json_depth).max().unwrap_or(0),
        _ => 0,
    }
}

/// Build the only Python adapter accepted by the target-bound path.  The
/// complete plan is hex-encoded JSON data, so literals can never become code.
pub(crate) fn build_target_adapter(
    call: &TargetCall,
    target_file_sha256: &str,
) -> Result<String, &'static str> {
    call.validate()?;
    if !is_sha256(target_file_sha256) {
        return Err("invalid_target_hash");
    }
    let plan = serde_json::to_vec(call).map_err(|_| "invalid_target_call")?;
    let target = format!("/workspace/tree/{}", call.file);
    Ok(format!(
        r#"import hashlib
import importlib.machinery
import importlib.util
import inspect
import json
import os
import sys
import types
PLAN = json.loads(bytes.fromhex({plan_hex:?}).decode('utf-8'))
TARGET_PATH = {target:?}
EXPECTED_SHA256 = {expected:?}
class _HarnessError(Exception):
    pass
def _load_target():
    loader = importlib.machinery.SourceFileLoader('_vettalon_target', TARGET_PATH)
    try:
        source = loader.get_data(TARGET_PATH)
    except OSError as exc:
        raise _HarnessError('target source unreadable') from exc
    if hashlib.sha256(source).hexdigest() != EXPECTED_SHA256:
        raise _HarnessError('target source identity mismatch')
    spec = importlib.util.spec_from_loader('_vettalon_target', loader, origin=TARGET_PATH)
    module = importlib.util.module_from_spec(spec) if spec is not None else types.ModuleType('_vettalon_target')
    module.__file__ = TARGET_PATH
    code = loader.source_to_code(source, TARGET_PATH)
    exec(code, module.__dict__)
    return module
def run(payload):
    module = _load_target()
    function = module.__dict__.get(PLAN['function'])
    if not callable(function):
        raise _HarnessError('target function unavailable')
    args = [payload if item['kind'] == 'payload' else item['value'] for item in PLAN['args']]
    result = function(*args)
    if inspect.isawaitable(result):
        raise _HarnessError('async target unsupported')
    return str(result)
def _main():
    if len(sys.argv) != 3:
        raise _HarnessError('invalid target invocation')
    try:
        payload = json.loads(bytes.fromhex(sys.argv[1]).decode('utf-8'))
    except Exception as exc:
        raise _HarnessError('invalid target payload') from exc
    if not isinstance(payload, str):
        raise _HarnessError('invalid target payload')
    # A Python exception from the target module or call is reported as
    # `raised` (exit 0); a harness failure above stays a non-zero exit.
    try:
        record = {{'result': run(payload)}}
    except _HarnessError:
        raise
    except Exception as exc:
        record = {{'raised': type(exc).__name__[:64]}}
    encoded = json.dumps(record, ensure_ascii=True, separators=(',', ':')).encode('utf-8')
    if len(encoded) > 65536:
        raise RuntimeError('target result too large')
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(sys.argv[2], flags, 0o600)
    with os.fdopen(fd, 'wb') as fh:
        fh.write(encoded)
if __name__ == '__main__':
    _main()
"#,
        plan_hex = hex::encode(plan),
        target = target,
        expected = target_file_sha256,
    ))
}

/// D8/D9 bind this distinct identity without changing Python receipts.
#[allow(dead_code)]
pub(crate) use super::verification_context::NODE_HARNESS_VERSION;

/// Basenames and exact embedded bytes mounted alongside the Node adapter.
#[allow(dead_code)]
pub(crate) const NODE_ASSETS: [(&str, &str); 4] = [
    (
        "vtl_hook.cjs",
        include_str!("../../assets/node/vtl_hook.cjs"),
    ),
    (
        "vtl_shim_sqlite3.cjs",
        include_str!("../../assets/node/vtl_shim_sqlite3.cjs"),
    ),
    (
        "vtl_shim_pg.cjs",
        include_str!("../../assets/node/vtl_shim_pg.cjs"),
    ),
    (
        "vtl_shim_mysql2.cjs",
        include_str!("../../assets/node/vtl_shim_mysql2.cjs"),
    ),
];

pub(crate) const NODE_NET_ASSET: (&str, &str) = (
    "vtl_hook_net.cjs",
    include_str!("../../assets/node/vtl_hook_net.cjs"),
);

pub(crate) fn node_assets_for(class: OracleClass) -> &'static [(&'static str, &'static str)] {
    const SSRF_ASSETS: [(&str, &str); 5] = [
        NODE_ASSETS[0],
        NODE_ASSETS[1],
        NODE_ASSETS[2],
        NODE_ASSETS[3],
        NODE_NET_ASSET,
    ];
    if class == OracleClass::Ssrf {
        &SSRF_ASSETS
    } else {
        &NODE_ASSETS
    }
}

/// Render a data-only plan. No path, export or literal is interpolated as JS.
#[allow(dead_code)] // D9 runtime dispatch.
pub(crate) fn build_node_adapter(
    call: &TargetCall,
    target_file_sha256: &str,
    class: OracleClass,
) -> Result<String, &'static str> {
    call.validate()?;
    if call.runtime()? != Runtime::Node {
        return Err("unsupported_target_language");
    }
    if !is_sha256(target_file_sha256) {
        return Err("invalid_target_hash");
    }
    let plan = serde_json::json!({"call": call, "target_file_sha256": target_file_sha256});
    let hex = hex::encode(serde_json::to_vec(&plan).map_err(|_| "invalid_target_call")?);
    // Preserve the legacy template byte-for-byte for the three existing classes.
    let adapter = if class == OracleClass::Ssrf {
        let mut adapter = NODE_ADAPTER.to_string();
        for (anchor, replacement) in NODE_NET_ADAPTER_REPLACEMENTS {
            adapter = replace_node_adapter_anchor(&adapter, anchor, replacement)?;
        }
        adapter
    } else {
        NODE_ADAPTER.to_string()
    };
    Ok(format!(
        "const PLAN = JSON.parse(Buffer.from('{hex}', 'hex').toString('utf8'));\n{adapter}"
    ))
}

fn replace_node_adapter_anchor(
    source: &str,
    anchor: &str,
    replacement: &str,
) -> Result<String, &'static str> {
    if source.match_indices(anchor).count() != 1 {
        return Err("invalid_node_adapter_template");
    }
    Ok(source.replace(anchor, replacement))
}

const NODE_NET_ADAPTER_REPLACEMENTS: [(&str, &str); 3] = [
    ("const stringify = JSON.stringify;", NODE_NET_ERROR_HELPERS),
    ("error?.code ===", "netOwnData(error, 'code') ==="),
    (
        "record = { raised:",
        "record = { net: networkCode(error), raised:",
    ),
];

// Capture helpers before importing any target code. Only own data properties
// participate; accessors and proxies are never diagnostic inputs.
const NODE_NET_ERROR_HELPERS: &str = r#"import { types as netTypes } from 'node:util';
const netIsProxy = netTypes.isProxy;
const netDescriptor = Object.getOwnPropertyDescriptor;
const netHasOwn = Object.hasOwn;
const netTest = Function.prototype.call.bind(RegExp.prototype.test);
function netOwnData(value, key) {
    if (value === null || (typeof value !== 'object' && typeof value !== 'function') || netIsProxy(value)) return undefined;
    const descriptor = netDescriptor(value, key);
    return descriptor && netHasOwn(descriptor, 'value') ? descriptor.value : undefined;
}
function networkCode(error) {
    try {
        for (let depth = 0; depth < 5; depth++) {
            if (error === null || (typeof error !== 'object' && typeof error !== 'function') || netIsProxy(error)) return null;
            const code = netOwnData(error, 'code');
            if (typeof code === 'string') {
                return netTest(/^[A-Z][A-Z0-9_]{1,39}$/, code) && !netTest(/[\r\n]/, code) ? code : null;
            }
            error = netOwnData(error, 'cause');
        }
    } catch {}
    return null;
}
const stringify = JSON.stringify;
"#;

const NODE_ADAPTER: &str = r#"import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { openSync, writeFileSync, closeSync, constants } from 'node:fs';
import { inspect } from 'node:util';
const stringify = JSON.stringify;
const from = Buffer.from;
const isBuffer = Buffer.isBuffer;
const bufferText = Function.prototype.call.bind(Buffer.prototype.toString);
const hasOwn = Object.hasOwn;
const apply = Reflect.apply;
const NativePromise = Promise;
const resolve = Promise.resolve.bind(Promise);
const all = Promise.all.bind(Promise);
const race = Promise.race.bind(Promise);
const setTimer = setTimeout;
const clearTimer = clearTimeout;
class HarnessError extends Error {}
if (process.argv.length !== 4) throw new HarnessError('invalid target invocation');
const payload = JSON.parse(bufferText(from(process.argv[2], 'hex'), 'utf8'));
if (typeof payload !== 'string') throw new HarnessError('invalid target payload');
const resultPath = process.argv[3];
const targetPath = '/workspace/tree/' + PLAN.call.file;
const targetUrl = pathToFileURL(targetPath).href;
const hook = createRequire(import.meta.url)('/workspace/vtl_hook.cjs');
if (typeof hook.configureTarget !== 'function') throw new HarnessError('node_hook_failed');
// One-shot identity configuration must precede the first target import.
hook.configureTarget({ target_url: targetUrl, target_file_sha256: PLAN.target_file_sha256 });
async function run() {
    const ns = await import(targetUrl);
    const name = PLAN.call.function;
    let receiver = ns;
    let fn = hasOwn(ns, name) ? ns[name] : undefined;
    if (typeof fn !== 'function' && ns.default != null && hasOwn(ns.default, name)) {
        receiver = ns.default;
        fn = ns.default[name];
    }
    if (typeof fn !== 'function') return { missing: 'export' };
    let callbackResolve, callbackReject;
    const callbackResult = new NativePromise((resolve, reject) => { callbackResolve = resolve; callbackReject = reject; });
    // Install the rejection handler before a synchronous error-first callback.
    callbackResult.catch(() => {});
    let usesCallback = false;
    const args = PLAN.call.args.map(item => {
        if (item.kind === 'payload') return payload;
        if (item.kind === 'callback') {
            usesCallback = true;
            return (err, value) => err == null ? callbackResolve(value) : callbackReject(err);
        }
        return item.value;
    });
    const returned = apply(fn, receiver, args);
    const value = usesCallback ? (await all([resolve(returned), callbackResult]))[1] : await resolve(returned);
    const result = typeof value === 'string' ? value : isBuffer(value) ? bufferText(value, 'utf8')
        : inspect(value, { depth: 4, maxStringLength: 65536, breakLength: Infinity, customInspect: false, getters: false });
    return { result };
}
let timer;
let record;
try {
    const budget = new NativePromise((_, reject) => {
        timer = setTimer(() => reject(new HarnessError('target time budget exceeded')), 25000);
    });
    record = await race([run(), budget]);
} catch (error) {
    if (error instanceof HarnessError || error?.code === 'ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX'
        || (typeof error?.message === 'string' && error.message.startsWith('node_hook_failed:'))) throw error;
    record = { raised: typeof error?.name === 'string' ? error.name.slice(0, 64) : 'Error' };
} finally {
    clearTimer(timer);
}
const encoded = from(stringify(record), 'utf8');
if (encoded.length > 65536) throw new HarnessError('target result too large');
const fd = openSync(resultPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
try { writeFileSync(fd, encoded); } finally { closeSync(fd); }
"#;

/// Length-prefix every component, including the class-specific hook/shim assets.
#[allow(dead_code)] // D8 IR binding.
pub(crate) fn node_harness_sha256(class: OracleClass, adapter_sha256: &str) -> String {
    let secrets = OracleSecrets {
        canary: "vtlc00000000000000000000000000000000".into(),
        marker: "vtlm11111111111111111111111111111111".into(),
    };
    let runners = super::poc_oracle::node_target_runners(class, &secrets, None);
    node_harness_sha256_with_runners(class, adapter_sha256, &runners, node_assets_for(class))
}

fn node_harness_sha256_with_runners(
    class: OracleClass,
    adapter_sha256: &str,
    runners: &[String; 3],
    assets: &[(&str, &str)],
) -> String {
    let class_id = match class {
        OracleClass::CommandInjection => "command_injection",
        OracleClass::PathTraversal => "path_traversal",
        OracleClass::Sqli => "sqli",
        OracleClass::Ssrf => "ssrf",
    };
    let parts = [NODE_HARNESS_VERSION, class_id, adapter_sha256]
        .into_iter()
        .chain(runners.iter().map(String::as_str))
        .chain(
            assets
                .iter()
                .flat_map(|(basename, source)| [*basename, *source]),
        );
    let mut material = Vec::new();
    for part in parts {
        material.extend_from_slice(&(part.len() as u64).to_be_bytes());
        material.extend_from_slice(part.as_bytes());
    }
    sha256_hex(&material)
}

/// Untrusted diagnostics, never evidence of an effect or successful execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeReachMatch {
    pub api: String,
    pub field: String,
    pub display: String,
    pub payload_in_text: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeReachSummary {
    pub reach_source: String,
    pub events_total: u16,
    pub first_match: Option<NodeReachMatch>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // D8 receipts and outcome derivation.
pub(super) struct NodeHarnessVerdict {
    pub base: HarnessVerdict,
    pub reached: Option<bool>,
    pub reach: NodeReachSummary,
    pub missing: bool,
    /// Informational wire field; the phase rule uses the host's plan driver.
    pub executable: bool,
}

#[allow(dead_code)] // D8/D9 consume Node verdicts.
pub(super) fn parse_node_verdict(
    output: &str,
    marker: &str,
    class: OracleClass,
) -> Result<NodeHarnessVerdict, &'static str> {
    let mut marked = output.lines().filter_map(|line| {
        let rest = line.trim().strip_prefix("__VTL_ORACLE__ ")?;
        let mut parts = rest.split_whitespace();
        (parts.next() == Some(marker)).then_some(parts)
    });
    let parts = marked.next().ok_or("target_verdict_missing")?;
    if marked.next().is_some() {
        return Err("duplicate_target_verdict");
    }
    let mut seen = std::collections::HashSet::new();
    let mut base = format!("__VTL_ORACLE__ {marker}");
    let mut reached = None;
    let mut reach = None;
    let mut missing = false;
    let mut executable = true;
    for part in parts {
        let (key, raw) = part.split_once('=').ok_or("invalid_target_verdict")?;
        if !seen.insert(key) {
            return Err("duplicate_target_verdict");
        }
        match key {
            "reached" => {
                reached = Some(match raw {
                    "true" => Some(true),
                    "false" => Some(false),
                    "unknown" => None,
                    _ => return Err("invalid_target_verdict"),
                })
            }
            "reach" => {
                if raw.is_empty()
                    || raw.len() > 4096
                    || raw.len() % 2 != 0
                    || !raw
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err("invalid_target_verdict");
                }
                let bytes = hex::decode(raw).map_err(|_| "invalid_target_verdict")?;
                let value = super::node::parse_strict(&bytes, 2048, 4)
                    .map_err(|_| "invalid_target_verdict")?;
                reach = Some(
                    serde_json::from_value::<NodeReachSummary>(value)
                        .map_err(|_| "invalid_target_verdict")?,
                );
            }
            "missing" if raw == "true" => missing = true,
            "executable" if raw == "false" => executable = false,
            "surfaced" if class == OracleClass::Ssrf => {
                base.push(' ');
                base.push_str(part);
            }
            "effect" | "functional" | "error" | "raised" | "timeout" => {
                base.push(' ');
                base.push_str(part);
            }
            _ => return Err("invalid_target_verdict"),
        }
    }
    let reached = reached.ok_or("target_verdict_missing")?;
    let reach = reach.ok_or("target_verdict_missing")?;
    if reach.reach_source != "in_process_hook"
        || reach.events_total >= 256
        || (reached == Some(true)) != reach.first_match.is_some()
        || (reached.is_some() && reach.events_total == 0)
        || reach.first_match.as_ref().is_some_and(|first| {
            first.api.is_empty()
                || first.api.len() > 64
                || first.display.len() > 512
                || !matches!(
                    first.field.as_str(),
                    "file" | "argv" | "path" | "query" | "params" | "url" | "href"
                )
        })
    {
        return Err("invalid_target_verdict");
    }
    Ok(NodeHarnessVerdict {
        base: parse_verdict(&base, marker)?,
        reached,
        reach,
        missing,
        executable,
    })
}

/// Additional Node gate only: D8 must still apply `derive_outcome`, including
/// the Python benign-functional rule. Forged reach can never bypass that rule.
#[allow(dead_code)] // Pure D8 phase rule, deliberately not wired into Python.
pub(super) fn node_phase_result(
    verdict: &NodeHarnessVerdict,
    plan_driver: Option<super::poc_oracle::NodeSqlDriver>,
    benign: bool,
) -> Result<bool, &'static str> {
    use super::poc_oracle::NodeSqlDriver;
    if matches!(plan_driver, Some(NodeSqlDriver::Pg | NodeSqlDriver::Mysql2)) {
        return Err("sql_dialect_not_executable");
    }
    if verdict.missing {
        return Err("target_missing");
    }
    if verdict.base.timeout {
        return Err("target_timeout");
    }
    if verdict.base.error || verdict.base.raised {
        return Err("target_execution_error");
    }
    match (verdict.base.effect, verdict.reached) {
        (effect, Some(true)) => Ok(effect),
        (true, _) => Err("effect_without_reach"),
        (false, _) if benign => Err("benign_not_reached"),
        (false, _) => Err("sink_not_reached"),
    }
}

/// Shared by typed fix verification so both the PoC and the before/after
/// check use the same no-tree-on-`sys.path` harness policy.
pub(crate) fn target_runner(class: OracleClass, secrets: &OracleSecrets, payload: &str) -> String {
    oracle_target_runner(class, secrets, payload)
}

/// Bind the IR to the generated runner templates and the exact target adapter.
/// Fixed representative secrets keep this identity deterministic while still
/// changing whenever runner generation or adapter bytes change.
pub(crate) fn target_harness_sha256(class: OracleClass, adapter_sha256: &str) -> String {
    let class_id = match class {
        OracleClass::CommandInjection => "command_injection",
        OracleClass::PathTraversal => "path_traversal",
        OracleClass::Sqli => "sqli",
        OracleClass::Ssrf => "ssrf",
    };
    let secrets = OracleSecrets {
        canary: "vtlc00000000000000000000000000000000".into(),
        marker: "vtlm11111111111111111111111111111111".into(),
    };
    let malicious = fixture_inputs(class)[0];
    let parts = [
        TARGET_HARNESS_VERSION.as_bytes().to_vec(),
        class_id.as_bytes().to_vec(),
        adapter_sha256.as_bytes().to_vec(),
        target_runner(class, &secrets, malicious).into_bytes(),
        target_runner(class, &secrets, benign_input(class)).into_bytes(),
        target_runner(class, &secrets, malicious).into_bytes(),
    ];
    let mut material = Vec::new();
    for part in parts {
        material.extend_from_slice(&(part.len() as u64).to_be_bytes());
        material.extend_from_slice(&part);
    }
    sha256_hex(&material)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetPocOutcome {
    EffectObserved,
    EffectAbsent,
    Inconclusive,
}

/// Node-only receipt metadata. All identities are host supplied; no fixture values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeRuntime {
    pub language: String,
    pub module_kind: String,
    pub export_kind: String,
    pub node_version: String,
    pub lockfile_sha256: Option<String>,
    pub lockfile_summary_sha256: Option<String>,
    pub deps_sha256: Option<String>,
    pub fixture_sha256: Option<String>,
    pub driver: Option<NodeDriver>,
    pub hook_bundle_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeDriver {
    Sqlite3,
    Pg,
    Mysql2,
}

impl NodeRuntime {
    pub fn identity(&self) -> super::verification_context::RuntimeIdentity {
        super::verification_context::RuntimeIdentity {
            node_version: self.node_version.clone(),
            lockfile_sha256: self.lockfile_sha256.clone(),
            lockfile_summary_sha256: self.lockfile_summary_sha256.clone(),
            deps_sha256: self.deps_sha256.clone(),
            fixture_sha256: self.fixture_sha256.clone(),
        }
    }

    pub fn valid(&self) -> bool {
        matches!(self.language.as_str(), "javascript" | "typescript")
            && matches!(self.module_kind.as_str(), "esm" | "cjs")
            && matches!(self.export_kind.as_str(), "named" | "default")
            && self.identity().valid()
            && is_sha256(&self.hook_bundle_sha256)
    }

    pub fn matches_file(&self, file: &str) -> bool {
        use vettalon_contract::verification::Language;
        self.valid()
            && matches!(
                (Language::for_target_file(file), self.language.as_str()),
                (Some(Language::JavaScript), "javascript")
                    | (Some(Language::TypeScript), "typescript")
            )
    }

    pub(crate) fn plan_driver(&self) -> Option<super::poc_oracle::NodeSqlDriver> {
        use super::poc_oracle::NodeSqlDriver;
        self.driver.map(|driver| match driver {
            NodeDriver::Sqlite3 => NodeSqlDriver::Sqlite3,
            NodeDriver::Pg => NodeSqlDriver::Pg,
            NodeDriver::Mysql2 => NodeSqlDriver::Mysql2,
        })
    }

    pub fn executable(&self) -> bool {
        !matches!(self.driver, Some(NodeDriver::Pg | NodeDriver::Mysql2))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetPocPhase {
    /// Diagnostic only: never contributes to effect or benign-control credit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surfaced: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reached: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reach_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reach_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reach: Option<NodeReachSummary>,
    /// Host plan decision, never the executable field in the verdict channel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<bool>,
    pub name: String,
    pub nonce_commitment: String,
    pub effect: Option<bool>,
    pub functional: Option<bool>,
    pub exit_code: Option<i64>,
    pub transcript_sha256: Option<String>,
    pub elapsed_ms: u64,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetPocReceipt {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<NodeRuntime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness_sha256: Option<String>,
    pub version: u32,
    pub outcome: TargetPocOutcome,
    pub phases: Vec<TargetPocPhase>,
    pub target_file: String,
    pub target_function: String,
    pub target_plan_sha256: Option<String>,
    pub target_file_sha256: Option<String>,
    pub source_sha256: Option<String>,
    pub exclusions: Option<SnapshotExclusions>,
    pub adapter_sha256: Option<String>,
    pub image_id: Option<String>,
    pub reason: Option<String>,
    /// Language-neutral, host-derived execution event. Missing on legacy or
    /// pre-execution failures; stored verdicts are re-derived on validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_event: Option<VerificationEvent>,
    /// Present only when a regression test was requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regression_test: Option<RegressionTestRecord>,
    /// Version 2: every replay of the three-phase protocol. Absent on
    /// version-1 receipts, which are read as a single requested replay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replays: Option<ReplaySummary>,
}

/// Node receipts use v3; Python continues writing byte-identical v2 receipts.
pub const TARGET_POC_RECEIPT_VERSION: u32 = 3;
const PYTHON_RECEIPT_VERSION: u32 = 2;
/// Upper bound for `--replays`. Each replay costs three containers, so a
/// run uses at most 60 containers plus one for the regression-test red check.
pub const MAX_REPLAYS: u32 = 20;

/// Refuse a replay count outside `1..=MAX_REPLAYS`.
pub fn validate_replays(replays: u32) -> Result<u32, &'static str> {
    if (1..=MAX_REPLAYS).contains(&replays) {
        Ok(replays)
    } else {
        Err("invalid_replay_count")
    }
}

/// One full three-phase run in fresh containers with fresh nonces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayRun {
    pub index: u32,
    pub outcome: TargetPocOutcome,
    pub reason: Option<String>,
    pub phases: Vec<TargetPocPhase>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaySummary {
    pub requested: u32,
    pub completed: u32,
    pub observed: u32,
    pub absent: u32,
    pub inconclusive: u32,
    pub runs: Vec<ReplayRun>,
}

impl ReplaySummary {
    fn from_runs(requested: u32, runs: Vec<ReplayRun>) -> Self {
        let count = |outcome| runs.iter().filter(|run| run.outcome == outcome).count() as u32;
        Self {
            requested,
            completed: runs.len() as u32,
            observed: count(TargetPocOutcome::EffectObserved),
            absent: count(TargetPocOutcome::EffectAbsent),
            inconclusive: count(TargetPocOutcome::Inconclusive),
            runs,
        }
    }

    /// Aggregate rule. Any inconclusive replay makes the aggregate
    /// inconclusive with the first such reason (replay order); otherwise
    /// every replay must agree, else `replay_inconsistent`. A summary with no
    /// runs returns `None` as reason: the receipt's own pre-execution refusal
    /// applies. Counts that do not match the runs never yield a verdict.
    pub fn aggregate(&self) -> (TargetPocOutcome, Option<String>) {
        const INCONCLUSIVE: TargetPocOutcome = TargetPocOutcome::Inconclusive;
        if self.runs.is_empty() {
            return (INCONCLUSIVE, None);
        }
        if *self != Self::from_runs(self.requested, self.runs.clone())
            || self.completed > self.requested
            || self
                .runs
                .iter()
                .enumerate()
                .any(|(i, run)| run.index != i as u32)
        {
            return (INCONCLUSIVE, Some("replay_summary_invalid".into()));
        }
        if let Some(run) = self.runs.iter().find(|run| run.outcome == INCONCLUSIVE) {
            let reason = run
                .reason
                .clone()
                .unwrap_or_else(|| "phase_incomplete".into());
            return (INCONCLUSIVE, Some(reason));
        }
        if self.completed != self.requested {
            return (INCONCLUSIVE, Some("replay_incomplete".into()));
        }
        let first = self.runs[0].outcome;
        if self.runs.iter().all(|run| run.outcome == first) {
            (first, None)
        } else {
            (INCONCLUSIVE, Some("replay_inconsistent".into()))
        }
    }
}

/// Phase names, in the order the three containers run.
pub(crate) const PHASE_NAMES: [&str; 3] = ["target", "benign_control", "fresh_nonce_rerun"];

/// The outcome a receipt's phases support for `class`: the attack shows the
/// effect, a healthy benign control does not, and the fresh-nonce re-run
/// shows it again (`effect_observed`); no effect anywhere with a healthy
/// control is `effect_absent`. Anything else, including a missing,
/// misnamed or incomplete phase, is `inconclusive`. The single rule used
/// both when a receipt is produced and when a stored one is read back.
pub(crate) fn derive_outcome(
    phases: &[TargetPocPhase],
    class: OracleClass,
    runtime: Option<&NodeRuntime>,
) -> TargetPocOutcome {
    if phases.len() != PHASE_NAMES.len()
        || phases
            .iter()
            .zip(PHASE_NAMES)
            .any(|(phase, name)| phase.name != name)
        || phases
            .iter()
            .any(|phase| phase.reason.is_some() || phase.effect.is_none())
    {
        return TargetPocOutcome::Inconclusive;
    }
    if let Some(runtime) = runtime
        && (!runtime.valid()
            || phases
                .iter()
                .any(|phase| phase.node_result(runtime).is_err()))
    {
        return TargetPocOutcome::Inconclusive;
    }
    let effects: Vec<bool> = phases.iter().filter_map(|phase| phase.effect).collect();
    let benign_healthy = match class {
        OracleClass::CommandInjection => phases[1].functional.is_none(),
        OracleClass::PathTraversal | OracleClass::Sqli | OracleClass::Ssrf => {
            phases[1].functional == Some(true)
        }
    };
    if effects == [true, false, true] && benign_healthy {
        TargetPocOutcome::EffectObserved
    } else if effects == [false, false, false] && benign_healthy {
        TargetPocOutcome::EffectAbsent
    } else {
        TargetPocOutcome::Inconclusive
    }
}

impl TargetPocPhase {
    /// D9 calls this only after parsing a successful runner exit. Reach is
    /// untrusted diagnostic data; the effect still comes from the runner.
    #[allow(dead_code)]
    pub(super) fn record_node_verdict(
        &mut self,
        verdict: &NodeHarnessVerdict,
        runtime: &NodeRuntime,
    ) {
        self.effect = Some(verdict.base.effect);
        self.functional = verdict.base.functional;
        self.surfaced = verdict.base.surfaced;
        self.reached = verdict.reached;
        self.reach_source = Some("in_process_hook".into());
        let mut reach = verdict.reach.clone();
        if let Some(first) = &mut reach.first_match {
            first.display = crate::util::mask_sensitive_text(&first.display);
            while first.display.len() > 512 {
                first.display.pop();
            }
        }
        self.reach_sha256 = Some(sha256_hex(
            &serde_json::to_vec(&reach).expect("reach serializes"),
        ));
        self.reach = Some(reach);
        self.executable = Some(runtime.executable());
        self.reason = node_phase_result(
            verdict,
            runtime.plan_driver(),
            self.name == "benign_control",
        )
        .err()
        .map(str::to_string);
    }

    fn node_result(&self, runtime: &NodeRuntime) -> Result<bool, &'static str> {
        if !runtime.executable() {
            return Err("sql_dialect_not_executable");
        }
        if self.reach_source.as_deref() != Some("in_process_hook")
            || self.executable != Some(runtime.executable())
        {
            return Err("node_hook_failed");
        }
        let verdict = NodeHarnessVerdict {
            base: HarnessVerdict {
                surfaced: self.surfaced,
                effect: self.effect.ok_or("phase_incomplete")?,
                functional: self.functional,
                error: false,
                raised: false,
                timeout: false,
            },
            reached: self.reached,
            reach: NodeReachSummary {
                reach_source: "in_process_hook".into(),
                events_total: 0,
                first_match: None,
            },
            missing: false,
            executable: runtime.executable(),
        };
        node_phase_result(
            &verdict,
            runtime.plan_driver(),
            self.name == "benign_control",
        )
    }
}

/// A receipt plus the regression test source, which exists only when the
/// sandbox saw that test fail on the unfixed snapshot.
#[derive(Debug, Clone)]
pub struct TargetPocWithTest {
    pub receipt: TargetPocReceipt,
    pub test_source: Option<String>,
}

impl TargetPocReceipt {
    /// Validate stored evidence before signing or attaching it. Replay outcomes
    /// are assertions to check, never inputs to the phase rule. A finding may
    /// supply the oracle for legacy receipts; otherwise a validated event or
    /// a recognized harness digest must identify it. Legacy Python receipts
    /// without either binding must have one outcome across compatible classes.
    pub(crate) fn validate_stored(
        &self,
        expected_class: Option<OracleClass>,
    ) -> Result<(TargetPocOutcome, Option<String>), String> {
        self.validate_stored_with_class(expected_class)
            .map(|(outcome, reason, _)| (outcome, reason))
    }

    /// Validate the receipt and return the class supported by its binding.
    /// Every harness digest and verification event must agree with the expected
    /// class, and the event must match the canonical IR rebuilt from the receipt.
    /// Unbound legacy Python receipts and empty refusals may have no class.
    pub(crate) fn validate_stored_with_class(
        &self,
        expected_class: Option<OracleClass>,
    ) -> Result<(TargetPocOutcome, Option<String>, Option<OracleClass>), String> {
        use vettalon_contract::verification::EffectKind;
        let runtime_kind = Runtime::for_file(&self.target_file)?;
        let empty_refusal = |phases: &[TargetPocPhase], outcome, reason: Option<&str>| {
            phases.is_empty()
                && outcome == TargetPocOutcome::Inconclusive
                && reason.is_some_and(|reason| !reason.trim().is_empty())
        };
        match (runtime_kind, &self.runtime, self.version) {
            (Runtime::Python, None, 1 | 2) => {}
            (Runtime::Node, Some(runtime), 3) if runtime.matches_file(&self.target_file) => {}
            (Runtime::Node, None, 3)
                if empty_refusal(&self.phases, self.outcome, self.reason.as_deref())
                    && self.replays.as_ref().is_some_and(|summary| {
                        summary.runs.iter().all(|run| {
                            empty_refusal(&run.phases, run.outcome, run.reason.as_deref())
                        })
                    }) => {}
            _ => return Err("receipt extension, language, runtime and version disagree".into()),
        }
        let mut class = expected_class;
        // Each present source must independently identify the same oracle.
        // Python receipts may store the harness only inside the event.
        for harness in self.harness_sha256.iter().chain(
            self.verification_event
                .as_ref()
                .map(|event| &event.ir.binding.harness_sha256),
        ) {
            let adapter = self
                .adapter_sha256
                .as_deref()
                .filter(|hash| is_sha256(hash))
                .ok_or("receipt harness requires an adapter digest")?;
            let harness_class = oracle_classes(runtime_kind)
                .iter()
                .copied()
                .find(|candidate| {
                    let digest = match runtime_kind {
                        Runtime::Node => node_harness_sha256(*candidate, adapter),
                        Runtime::Python => target_harness_sha256(*candidate, adapter),
                    };
                    digest == *harness
                })
                .ok_or("receipt harness digest is not recognized")?;
            if class.is_some_and(|class| class != harness_class) {
                return Err("receipt harness class disagrees with the finding or event".into());
            }
            class = Some(harness_class);
        }
        if let Some(event) = &self.verification_event {
            event.validate()?;
            let event_class = match event.ir.effect.kind {
                EffectKind::CommandExecution => OracleClass::CommandInjection,
                EffectKind::FileReadOutsideRoot => OracleClass::PathTraversal,
                EffectKind::SqlStateChange => OracleClass::Sqli,
                EffectKind::NetworkEgress => OracleClass::Ssrf,
                _ => return Err("receipt oracle class cannot be determined".into()),
            };
            if class.is_some_and(|class| class != event_class) {
                return Err("receipt oracle class disagrees with the finding or harness".into());
            }
            class = Some(event_class);
            // Standalone receipts have no independent finding ID or source line.
            // Finding-aware callers additionally bind those fields below.
            let canonical = self.canonical_ir(
                event_class,
                &event.ir.binding.finding_id,
                event.ir.subject.line,
            )?;
            if event.ir != canonical {
                return Err("receipt and verification event identities disagree".into());
            }
        }
        if class.is_some_and(|class| !oracle_classes(runtime_kind).contains(&class)) {
            return Err("receipt oracle class is unsupported for its runtime".into());
        }
        let legacy_python = runtime_kind == Runtime::Python
            && self.verification_event.is_none()
            && self.harness_sha256.is_none();
        let validate_phases = |phases: &[TargetPocPhase],
                               outcome,
                               reason: Option<&str>|
         -> Result<(), String> {
            if empty_refusal(phases, outcome, reason) {
                return Ok(());
            }
            if phases.len() != PHASE_NAMES.len()
                || phases
                    .iter()
                    .zip(PHASE_NAMES)
                    .any(|(phase, name)| phase.name != name)
            {
                return Err("receipt outcome disagrees with its phases: missing or misnamed phases are inconclusive".into());
            }
            let derived = if let Some(class) = class {
                derive_outcome(phases, class, self.runtime.as_ref())
            } else if legacy_python {
                // Older Python writers stored neither event nor harness hash.
                // Infer only an outcome, never a class from the claimed outcome.
                let mut candidates = oracle_classes(runtime_kind)
                    .iter()
                    .copied()
                    .filter(|class| match class {
                        OracleClass::Ssrf => false,
                        OracleClass::CommandInjection => phases[1].functional.is_none(),
                        OracleClass::PathTraversal | OracleClass::Sqli => {
                            phases[1].functional == Some(true)
                        }
                    })
                    .map(|class| derive_outcome(phases, class, None));
                let derived = candidates
                    .next()
                    .ok_or("receipt oracle class cannot be determined")?;
                if candidates.any(|candidate| candidate != derived) {
                    return Err("legacy receipt phases have ambiguous outcomes".into());
                }
                derived
            } else {
                return Err("receipt oracle class cannot be determined".into());
            };
            if derived != outcome {
                return Err("receipt outcome disagrees with its phases".into());
            }
            if let Some(runtime) = &self.runtime
                && outcome != TargetPocOutcome::Inconclusive
                && (runtime.lockfile_sha256.is_none()
                    || runtime.lockfile_summary_sha256.is_none()
                    || !self.image_id.as_deref().is_some_and(valid_image_id)
                    || !self.harness_sha256.as_deref().is_some_and(is_sha256))
            {
                return Err("Node outcome requires complete execution identities".into());
            }
            Ok(())
        };
        match (self.version, &self.replays) {
            (1, None) => {
                validate_phases(&self.phases, self.outcome, self.reason.as_deref())?;
            }
            (2 | 3, Some(summary)) => {
                validate_replays(summary.requested)?;
                if *summary != ReplaySummary::from_runs(summary.requested, summary.runs.clone())
                    || summary.completed > summary.requested
                    || summary
                        .runs
                        .iter()
                        .enumerate()
                        .any(|(i, run)| run.index != i as u32)
                    || summary
                        .runs
                        .first()
                        .map(|run| run.phases.as_slice())
                        .unwrap_or(&[])
                        != self.phases.as_slice()
                    || (self.phases.is_empty()
                        && !empty_refusal(&self.phases, self.outcome, self.reason.as_deref()))
                {
                    return Err("receipt replay summary is invalid".into());
                }
                for run in &summary.runs {
                    validate_phases(&run.phases, run.outcome, run.reason.as_deref())?;
                }
            }
            _ => return Err("unsupported receipt version and replays combination".into()),
        }
        let (outcome, reason) = self.derived_outcome();
        if outcome != self.outcome {
            return Err("receipt outcome disagrees with its replays".into());
        }
        Ok((outcome, reason, class))
    }

    pub(crate) fn validate_stored_with_finding(
        &self,
        expected_class: Option<OracleClass>,
        finding: Option<&Finding>,
    ) -> Result<(TargetPocOutcome, Option<String>), String> {
        let (outcome, reason, _) = self.validate_stored_with_class(expected_class)?;
        if let (Some(event), Some(finding)) = (&self.verification_event, finding)
            && (event.ir.binding.finding_id != finding.id || event.ir.subject.line != finding.line)
        {
            return Err("receipt and verification event identities disagree".into());
        }
        Ok((outcome, reason))
    }

    fn canonical_ir(
        &self,
        class: OracleClass,
        finding_id: &str,
        line: Option<u32>,
    ) -> Result<vettalon_contract::verification::VerificationIr, &'static str> {
        let adapter = self
            .adapter_sha256
            .as_deref()
            .filter(|hash| is_sha256(hash))
            .ok_or("receipt event requires an adapter digest")?;
        let cwe = match class {
            OracleClass::CommandInjection => "CWE-78",
            OracleClass::PathTraversal => "CWE-22",
            OracleClass::Sqli => "CWE-89",
            OracleClass::Ssrf => "CWE-918",
        };
        compile_ir(&CompileInput {
            runtime: self.runtime.as_ref().map(NodeRuntime::identity),
            finding_id: finding_id.into(),
            file: self.target_file.clone(),
            line,
            symbol: self.target_function.clone(),
            cwe: cwe.into(),
            source_sha256: self
                .source_sha256
                .clone()
                .ok_or("receipt source digest missing")?,
            target_file_sha256: self
                .target_file_sha256
                .clone()
                .ok_or("receipt target file digest missing")?,
            target_plan_sha256: self
                .target_plan_sha256
                .clone()
                .ok_or("receipt target plan digest missing")?,
            harness_sha256: match Runtime::for_file(&self.target_file)? {
                Runtime::Node => node_harness_sha256(class, adapter),
                Runtime::Python => target_harness_sha256(class, adapter),
            },
        })
    }

    /// Bind D9's host-selected runtime after adapter/image preflight. Neither
    /// fixture values nor the runner's executable flag are inputs here.
    #[allow(dead_code)]
    pub(crate) fn bind_node_runtime(
        &mut self,
        runtime: NodeRuntime,
        class: OracleClass,
    ) -> Result<(), &'static str> {
        if !runtime.matches_file(&self.target_file) {
            return Err("invalid_verification_runtime");
        }
        let adapter = self
            .adapter_sha256
            .as_deref()
            .filter(|hash| is_sha256(hash))
            .ok_or("invalid_target_hash")?;
        if !self.image_id.as_deref().is_some_and(valid_image_id) {
            return Err("invalid_image_identity");
        }
        self.version = TARGET_POC_RECEIPT_VERSION;
        self.harness_sha256 = Some(node_harness_sha256(class, adapter));
        self.runtime = Some(runtime);
        Ok(())
    }

    fn inconclusive(call: &TargetCall, reason: &str) -> Self {
        Self {
            runtime: None,
            harness_sha256: None,
            version: if call.runtime() == Ok(Runtime::Node) {
                TARGET_POC_RECEIPT_VERSION
            } else {
                PYTHON_RECEIPT_VERSION
            },
            outcome: TargetPocOutcome::Inconclusive,
            phases: Vec::new(),
            target_file: call.file.clone(),
            target_function: call.function.clone(),
            target_plan_sha256: serde_json::to_vec(call).ok().map(|v| sha256_hex(&v)),
            target_file_sha256: None,
            source_sha256: None,
            exclusions: None,
            adapter_sha256: None,
            image_id: None,
            reason: Some(reason.into()),
            verification_event: None,
            regression_test: None,
            replays: None,
        }
    }

    /// Replay record as stored, or the single implied replay of a version-1
    /// receipt (or of a receipt without the field).
    pub fn replay_summary(&self) -> ReplaySummary {
        match &self.replays {
            Some(summary) if self.version >= 2 => summary.clone(),
            _ => ReplaySummary::from_runs(
                1,
                vec![ReplayRun {
                    index: 0,
                    outcome: self.outcome,
                    reason: self.reason.clone(),
                    phases: self.phases.clone(),
                }],
            ),
        }
    }

    /// Outcome a stored receipt supports: the replay aggregate for version 2,
    /// the stored single-run outcome for version 1.
    pub fn derived_outcome(&self) -> (TargetPocOutcome, Option<String>) {
        match &self.replays {
            Some(summary) if self.version >= 2 => match summary.aggregate() {
                (TargetPocOutcome::Inconclusive, None) => {
                    (TargetPocOutcome::Inconclusive, self.reason.clone())
                }
                derived => derived,
            },
            _ => (self.outcome, self.reason.clone()),
        }
    }
}

#[async_trait::async_trait]
pub trait TargetSandbox: Send + Sync {
    fn image_id(&self) -> &str;
    async fn prepare_node(&self, _tree: &Path) -> Result<Arc<NodeExecution>, &'static str> {
        Err("node_runtime_unavailable")
    }
    #[allow(clippy::too_many_arguments)]
    async fn run_node(
        &self,
        _node: &NodeExecution,
        _tree: &Path,
        _runner: &str,
        _adapter: &str,
        _input: &str,
        _class: crate::audit::poc_oracle::OracleClass,
    ) -> Result<(i64, String), String> {
        Err("node_runtime_unavailable".into())
    }
    async fn run_node_regression(
        &self,
        _node: &NodeExecution,
        _tree: &Path,
        _runner: &str,
        _source: &str,
        _input: &str,
    ) -> Result<(i64, String), String> {
        Err("node_runtime_unavailable".into())
    }
    /// `input` goes to the runner's stdin (the oracle runner and the
    /// regression red runner both read their per-run marker from it). The
    /// runner runs as PID 1 of its container.
    async fn run(
        &self,
        tree: &Path,
        runner: &str,
        adapter: &str,
        input: &str,
    ) -> Result<(i64, String), String>;
}

pub(crate) struct DockerTargetSandbox {
    sandbox: crate::sandbox::DockerSandbox,
    budget: PocBudget,
    node_options: NodeOptions,
    node_session: NodeSession,
}

/// The same hardened Docker sandbox `reproduce` uses, with its own hard cap of
/// `max_runs` containers (used by `vettalon bisect`). The image is never pulled.
pub(crate) async fn docker_target_sandbox(
    image: &str,
    max_runs: usize,
) -> Result<DockerTargetSandbox, String> {
    let budget = PocBudget::with_image(max_runs, image);
    let sandbox = budget.sandbox().await?;
    Ok(DockerTargetSandbox {
        sandbox,
        budget,
        node_options: NodeOptions::default(),
        node_session: NodeSession::default(),
    })
}

#[async_trait::async_trait]
impl TargetSandbox for DockerTargetSandbox {
    async fn prepare_node(&self, tree: &Path) -> Result<Arc<NodeExecution>, &'static str> {
        self.node_session
            .prepare(tree, &self.sandbox, self.node_options.fixture.clone())
            .await
    }
    #[allow(clippy::too_many_arguments)]
    async fn run_node(
        &self,
        node: &NodeExecution,
        tree: &Path,
        runner: &str,
        adapter: &str,
        input: &str,
        class: crate::audit::poc_oracle::OracleClass,
    ) -> Result<(i64, String), String> {
        if !self.budget.try_claim() {
            return Err("target_poc_budget_exhausted".into());
        }
        node.run(&self.sandbox, tree, runner, adapter, input, class)
            .await
    }

    async fn run_node_regression(
        &self,
        node: &NodeExecution,
        tree: &Path,
        runner: &str,
        source: &str,
        input: &str,
    ) -> Result<(i64, String), String> {
        if !self.budget.try_claim() {
            return Err("target_poc_budget_exhausted".into());
        }
        node.run_regression(&self.sandbox, tree, runner, source, input)
            .await
    }

    fn image_id(&self) -> &str {
        &self.sandbox.image
    }

    async fn run(
        &self,
        tree: &Path,
        runner: &str,
        adapter: &str,
        input: &str,
    ) -> Result<(i64, String), String> {
        if !self.budget.try_claim() {
            return Err("target_poc_budget_exhausted".into());
        }
        self.sandbox
            .run_workspace_with_tree(
                &[("runner.py", runner), ("sink.py", adapter)],
                tree,
                &runner_command(),
                Some(input),
                POC_TIMEOUT,
            )
            .await
    }
}

/// Read-only source preflight shared by GUI transports. Does not execute source,
/// create containers, or claim that a function call will succeed at runtime.
pub fn preflight_source(repo_root: &Path, finding: &Finding) -> Result<String, &'static str> {
    TargetCall {
        file: finding.file.clone(),
        function: "target".into(),
        args: vec![TargetArgument::Payload],
    }
    .validate()?;
    if classify_finding_target(finding).is_none() {
        return Err("unsupported_oracle_class");
    }
    let expected = finding
        .file_hash
        .as_deref()
        .filter(|hash| is_sha256(hash))
        .ok_or("missing_finding_source_identity")?;
    let (_, live_hash) = read_target_source(repo_root, &finding.file)?;
    if expected != live_hash {
        return Err("stale_source");
    }
    Ok(live_hash)
}

/// Docker detection binds the selected mutable tag to an immutable image ID.
pub async fn run_target_poc(
    repo_root: &Path,
    finding: &Finding,
    call: &TargetCall,
    image: &str,
) -> TargetPocReceipt {
    run_docker(repo_root, finding, call, image, false, 1, None)
        .await
        .receipt
}

/// [`run_target_poc`], then generate a regression test and run it against
/// the same snapshot. Without an observed effect and a red run, the receipt
/// says why and there is no test.
pub async fn run_target_poc_with_test(
    repo_root: &Path,
    finding: &Finding,
    call: &TargetCall,
    image: &str,
) -> TargetPocWithTest {
    run_docker(repo_root, finding, call, image, true, 1, None).await
}

/// Run the full three-phase protocol `replays` times (1..=20), each replay in
/// fresh containers with fresh nonces, then the optional red check once.
pub async fn run_target_poc_replayed(
    repo_root: &Path,
    finding: &Finding,
    call: &TargetCall,
    image: &str,
    replays: u32,
    emit_test: bool,
) -> TargetPocWithTest {
    run_docker(repo_root, finding, call, image, emit_test, replays, None).await
}

/// [`run_target_poc_replayed`] without a regression test that starts no
/// further replay once `deadline` has passed. A run cut short carries reason
/// `deadline_exceeded` (inconclusive).
pub async fn run_target_poc_until(
    repo_root: &Path,
    finding: &Finding,
    call: &TargetCall,
    image: &str,
    replays: u32,
    deadline: Instant,
) -> TargetPocWithTest {
    run_docker(
        repo_root,
        finding,
        call,
        image,
        false,
        replays,
        Some(deadline),
    )
    .await
}

/// CLI entry point with explicit Node image and private fixture.
#[allow(clippy::too_many_arguments)]
pub async fn run_target_poc_with_node(
    repo: &Path,
    finding: &Finding,
    call: &TargetCall,
    python_image: &str,
    node: &NodeOptions,
    replays: u32,
    emit_test: bool,
) -> TargetPocWithTest {
    if call.runtime() != Ok(Runtime::Node) {
        return run_target_poc_replayed(repo, finding, call, python_image, replays, emit_test)
            .await;
    }
    if let Err(reason) = validate_replays(replays).and_then(|_| call.validate()) {
        return refused_with(call, reason, emit_test, replays);
    }
    let runner =
        match node_docker_sandbox(node, 3 * replays as usize + usize::from(emit_test)).await {
            Ok(runner) => runner,
            Err(_) => return refused_with(call, "node_runtime_unavailable", emit_test, replays),
        };
    run_replays_until(repo, finding, call, &runner, emit_test, replays, None).await
}

pub(crate) async fn node_docker_sandbox(
    node: &NodeOptions,
    max_runs: usize,
) -> Result<DockerTargetSandbox, String> {
    let mut runner = docker_target_sandbox(&node.image, max_runs).await?;
    runner.node_options = node.clone();
    Ok(runner)
}

pub(crate) fn refused_with(
    call: &TargetCall,
    reason: &str,
    emit_test: bool,
    replays: u32,
) -> TargetPocWithTest {
    let mut receipt = TargetPocReceipt::inconclusive(call, reason);
    receipt.replays = Some(ReplaySummary::from_runs(replays, Vec::new()));
    if emit_test {
        receipt.regression_test = Some(RegressionTestRecord::refused(reason));
    }
    TargetPocWithTest {
        receipt,
        test_source: None,
    }
}

async fn run_docker(
    repo_root: &Path,
    finding: &Finding,
    call: &TargetCall,
    image: &str,
    emit_test: bool,
    replays: u32,
    deadline: Option<Instant>,
) -> TargetPocWithTest {
    let refused = |reason| refused_with(call, reason, emit_test, replays);
    if let Err(reason) = validate_replays(replays) {
        return refused(reason);
    }
    if let Err(reason) = call.validate() {
        return refused(reason);
    }
    if finding.file != call.file {
        return refused("finding_target_mismatch");
    }
    if call
        .runtime()
        .ok()
        .and_then(|runtime| classify_target(finding, runtime))
        .is_none()
    {
        return refused("unsupported_oracle_class");
    }
    if call.runtime() == Ok(Runtime::Node) {
        let options = NodeOptions {
            image: crate::sandbox::default_node_poc_image().into(),
            fixture: None,
        };
        let runner = match node_docker_sandbox(
            &options,
            3 * replays as usize + usize::from(emit_test),
        )
        .await
        {
            Ok(runner) => runner,
            Err(_) => return refused("node_runtime_unavailable"),
        };
        return run_replays_until(
            repo_root, finding, call, &runner, emit_test, replays, deadline,
        )
        .await;
    }
    // Claimed per container: three per replay plus one for the red check,
    // so at most 3 * MAX_REPLAYS + 1 = 61 containers.
    let containers = 3 * replays as usize + usize::from(emit_test);
    let budget = PocBudget::with_image(containers, image);
    let sandbox = match budget.sandbox().await {
        Ok(sandbox) => sandbox,
        Err(_) => return refused("sandbox_unavailable"),
    };
    let runner = DockerTargetSandbox {
        sandbox,
        budget,
        node_options: NodeOptions::default(),
        node_session: NodeSession::default(),
    };
    run_replays_until(
        repo_root, finding, call, &runner, emit_test, replays, deadline,
    )
    .await
}

/// Testable core.  The host only validates and copies bytes; target Python is
/// executed exclusively by `TargetSandbox`.
#[cfg(test)]
pub(crate) async fn run_target_poc_with_sandbox<S: TargetSandbox>(
    repo_root: &Path,
    finding: &Finding,
    call: &TargetCall,
    sandbox: &S,
) -> TargetPocReceipt {
    run_with_sandbox(repo_root, finding, call, sandbox, false)
        .await
        .receipt
}

#[cfg(test)]
async fn run_with_sandbox<S: TargetSandbox>(
    repo_root: &Path,
    finding: &Finding,
    call: &TargetCall,
    sandbox: &S,
    emit_test: bool,
) -> TargetPocWithTest {
    run_replays_with_sandbox(repo_root, finding, call, sandbox, emit_test, 1).await
}

/// Phase reason for a container run that returned no capture. A run killed
/// at the hard timeout with confirmed cleanup is the target hanging
/// (`target_timeout`); anything else is the backend
/// (`incomplete_sandbox_capture`).
pub(crate) fn sandbox_error_reason(error: &str) -> &'static str {
    if error.starts_with(crate::sandbox::EXECUTION_TIMEOUT_PREFIX)
        && !error.contains("cleanup unconfirmed")
    {
        "target_timeout"
    } else {
        "incomplete_sandbox_capture"
    }
}

/// True when a replay was refused before or by the sandbox backend rather
/// than by the target's behaviour: nothing ran (stale source, snapshot or
/// image refusal), or a container did not return a complete capture
/// (backend failure, exhausted container budget), or the target hung until
/// the hard timeout (further replays would only burn the same timeout).
fn infrastructure_refusal(run: &TargetPocReceipt) -> bool {
    run.outcome == TargetPocOutcome::Inconclusive
        && (run.phases.is_empty()
            || run.phases.iter().any(|phase| {
                matches!(
                    phase.reason.as_deref(),
                    Some(
                        "incomplete_sandbox_capture"
                            | "target_timeout"
                            | "ssrf_listener_unavailable"
                    )
                )
            }))
}

/// Replays always run to the requested count, even once the aggregate can no
/// longer be anything but inconclusive, so the receipt shows the full spread.
/// The only early stop is an infrastructure refusal (see
/// [`infrastructure_refusal`]): further replays would charge containers for
/// a result the sandbox already cannot give. The stopping replay is recorded
/// (`completed` counts it) and the aggregate carries its reason.
#[cfg(test)]
pub(crate) async fn run_replays_with_sandbox<S: TargetSandbox>(
    repo_root: &Path,
    finding: &Finding,
    call: &TargetCall,
    sandbox: &S,
    emit_test: bool,
    replays: u32,
) -> TargetPocWithTest {
    run_replays_until(repo_root, finding, call, sandbox, emit_test, replays, None).await
}

/// The replay loop; with a `deadline` it starts no replay once it has
/// passed. A run stopped that way is inconclusive with reason
/// `deadline_exceeded` (also when no replay started at all).
pub(crate) async fn run_replays_until<S: TargetSandbox>(
    repo_root: &Path,
    finding: &Finding,
    call: &TargetCall,
    sandbox: &S,
    emit_test: bool,
    replays: u32,
    deadline: Option<Instant>,
) -> TargetPocWithTest {
    if let Err(reason) = validate_replays(replays) {
        return refused_with(call, reason, emit_test, replays);
    }
    let mut first: Option<TargetPocReceipt> = None;
    let mut runs = Vec::new();
    let mut snapshot = None;
    let mut deadline_hit = false;
    let mut node = None;
    for index in 0..replays {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            deadline_hit = true;
            break;
        }
        let mut kept = None;
        let run = phases(repo_root, finding, call, sandbox, &mut kept, &mut node).await;
        let mut record = ReplayRun {
            index,
            outcome: run.outcome,
            reason: run.reason.clone(),
            phases: run.phases.clone(),
        };
        // Every replay must execute the same bytes in the same image.
        if let Some(first) = &first
            && !run.phases.is_empty()
            && (run.source_sha256 != first.source_sha256
                || run.target_file_sha256 != first.target_file_sha256
                || run.adapter_sha256 != first.adapter_sha256
                || run.image_id != first.image_id)
        {
            record.outcome = TargetPocOutcome::Inconclusive;
            record.reason = Some("replay_identity_drift".into());
        }
        runs.push(record);
        let stop = infrastructure_refusal(&run);
        if kept.is_some() {
            snapshot = kept;
        }
        if first.is_none() {
            first = Some(run);
        }
        if stop {
            break;
        }
    }
    let Some(mut receipt) = first else {
        let reason = if deadline_hit {
            "deadline_exceeded"
        } else {
            "invalid_replay_count"
        };
        return refused_with(call, reason, emit_test, replays);
    };
    let first_outcome = receipt.outcome;
    let summary = ReplaySummary::from_runs(replays, runs);
    // At least one run exists, so the aggregate always states its own reason.
    (receipt.outcome, receipt.reason) = summary.aggregate();
    if deadline_hit
        && receipt.outcome == TargetPocOutcome::Inconclusive
        && receipt.reason.as_deref() == Some("replay_incomplete")
    {
        receipt.reason = Some("deadline_exceeded".into());
    }
    receipt.replays = Some(summary);
    if receipt.outcome != first_outcome {
        // The event mirrors the first replay's phases but must carry the
        // aggregate verdict; re-derive it so the two cannot disagree.
        receipt.verification_event = None;
        if let Some(class) = call
            .runtime()
            .ok()
            .and_then(|runtime| classify_target(finding, runtime))
        {
            attach_verification_event(&mut receipt, finding, call, class);
        }
    }
    if !emit_test {
        return TargetPocWithTest {
            receipt,
            test_source: None,
        };
    }
    if call
        .runtime()
        .ok()
        .and_then(|runtime| classify_target(finding, runtime))
        == Some(OracleClass::Ssrf)
    {
        receipt.regression_test = Some(RegressionTestRecord::refused("ssrf_emit_test_unsupported"));
        return TargetPocWithTest {
            receipt,
            test_source: None,
        };
    }
    let (record, test_source) = match (
        receipt.outcome,
        snapshot,
        call.runtime()
            .ok()
            .and_then(|runtime| classify_target(finding, runtime)),
    ) {
        (TargetPocOutcome::EffectObserved, Some(snapshot), Some(class)) => {
            red_check_with_node(finding, call, class, sandbox, &snapshot, node.as_deref()).await
        }
        _ => (RegressionTestRecord::refused("effect_not_observed"), None),
    };
    receipt.regression_test = Some(record);
    TargetPocWithTest {
        receipt,
        test_source,
    }
}

/// Run a freshly generated test on the unfixed snapshot. It must fail its
/// attack assertion and pass its benign control, or it is not released.
#[cfg(test)]
async fn red_check<S: TargetSandbox>(
    finding: &Finding,
    call: &TargetCall,
    class: OracleClass,
    sandbox: &S,
    snapshot: &fix_diff::SourceSnapshot,
) -> (RegressionTestRecord, Option<String>) {
    red_check_with_node(finding, call, class, sandbox, snapshot, None).await
}

async fn red_check_with_node<S: TargetSandbox>(
    finding: &Finding,
    call: &TargetCall,
    class: OracleClass,
    sandbox: &S,
    snapshot: &fix_diff::SourceSnapshot,
    node: Option<&NodeExecution>,
) -> (RegressionTestRecord, Option<String>) {
    let generated = if let Some(node) = node {
        regression_test::generate_node(finding, class, call, node.fixture_sha256())
    } else {
        regression_test::generate(finding, class, call)
    };
    let source = match generated {
        Ok(source) => source,
        Err(reason) => return (RegressionTestRecord::refused(reason), None),
    };
    let secrets = OracleSecrets::fresh();
    // The red runner holds no marker; it reads it from stdin, like the
    // oracle runner, and only a run that exits 0 counts.
    let result = if let Some(node) = node {
        let child = match regression_test::node_child(call) {
            Ok(child) => child,
            Err(reason) => return (RegressionTestRecord::refused(reason), None),
        };
        sandbox
            .run_node_regression(
                node,
                &snapshot.path,
                &regression_test::node_red_runner(class, &secrets, &child),
                &source,
                &runner_input(&secrets),
            )
            .await
    } else {
        sandbox
            .run(
                &snapshot.path,
                &regression_test::red_runner(),
                &source,
                &runner_input(&secrets),
            )
            .await
    };
    let verdict = match result {
        Ok((exit, output)) => regression_test::parse_red_verdict(exit, &output, &secrets.marker),
        Err(_) => Err("incomplete_sandbox_capture"),
    };
    let red_check = node.map(|_| "emitted_test_with_parent_canary".to_string());
    let sha256 = Some(sha256_hex(source.as_bytes()));
    match verdict {
        Ok((true, true)) => (
            RegressionTestRecord {
                sha256,
                red_check,
                red_observed: true,
                benign_passed: true,
                reason: None,
            },
            Some(source),
        ),
        Ok((red_observed, benign_passed)) => (
            RegressionTestRecord {
                sha256,
                red_check,
                red_observed,
                benign_passed,
                reason: Some("regression_test_not_red".into()),
            },
            None,
        ),
        Err(reason) => (
            RegressionTestRecord {
                sha256,
                red_check,
                ..RegressionTestRecord::refused(reason)
            },
            None,
        ),
    }
}

async fn phases<S: TargetSandbox>(
    repo_root: &Path,
    finding: &Finding,
    call: &TargetCall,
    sandbox: &S,
    kept: &mut Option<fix_diff::SourceSnapshot>,
    node: &mut Option<Arc<NodeExecution>>,
) -> TargetPocReceipt {
    let mut receipt = TargetPocReceipt::inconclusive(call, "target_poc_incomplete");
    if let Err(reason) = call.validate() {
        receipt.reason = Some(reason.into());
        return receipt;
    }
    if finding.file != call.file {
        receipt.reason = Some("finding_target_mismatch".into());
        return receipt;
    }
    let Some(class) = call
        .runtime()
        .ok()
        .and_then(|runtime| classify_target(finding, runtime))
    else {
        receipt.reason = Some("unsupported_oracle_class".into());
        return receipt;
    };
    if !valid_image_id(sandbox.image_id()) {
        receipt.reason = Some("invalid_image_identity".into());
        return receipt;
    }
    let (source, live_hash) = match read_target_source(repo_root, &call.file) {
        Ok(value) => value,
        Err(reason) => {
            receipt.reason = Some(reason.into());
            return receipt;
        }
    };
    if finding
        .file_hash
        .as_deref()
        .is_some_and(|expected| expected != live_hash)
    {
        receipt.reason = Some("stale_source".into());
        return receipt;
    }
    if finding.file_hash.is_none() {
        receipt.reason = Some("missing_finding_source_identity".into());
        return receipt;
    }
    let is_node = call.runtime() == Ok(Runtime::Node);
    if !is_node && declares_top_level_async_function(&source, &call.function) {
        receipt.reason = Some("async_target_unsupported".into());
        return receipt;
    }
    if !is_node && !declares_top_level_function(&source, &call.function) {
        receipt.reason = Some("function_not_declared".into());
        return receipt;
    }

    let snapshot = match if is_node {
        fix_diff::snapshot_with_mode(repo_root, fix_diff::SnapshotMode::Node)
    } else {
        fix_diff::snapshot(repo_root)
    } {
        Ok(snapshot) => snapshot,
        Err(reason) => {
            receipt.reason = Some(reason.into());
            return receipt;
        }
    };
    let tree_digest = match snapshot_digest(&snapshot.path) {
        Ok(value) => value,
        Err(reason) => {
            receipt.reason = Some(reason.into());
            return receipt;
        }
    };
    let copied_hash = match source_file_digest(&snapshot.path, &call.file) {
        Ok(value) => value,
        Err(_) => {
            receipt.reason = Some("unsafe_target_path".into());
            return receipt;
        }
    };
    if copied_hash != live_hash {
        receipt.reason = Some("source_changed_during_snapshot".into());
        return receipt;
    }
    if is_node {
        if node.is_none() {
            match sandbox.prepare_node(&snapshot.path).await {
                Ok(prepared) => *node = Some(prepared),
                Err(reason) => {
                    receipt.reason = Some(reason.into());
                    return receipt;
                }
            }
        }
        if let Some(prepared) = node.as_ref()
            && let Err(reason) = prepared.check_inputs(&snapshot.path)
        {
            receipt.reason = Some(reason.into());
            return receipt;
        }
    }
    let adapter = match if is_node {
        build_node_adapter(call, &copied_hash, class)
    } else {
        build_target_adapter(call, &copied_hash)
    } {
        Ok(adapter) => adapter,
        Err(reason) => {
            receipt.reason = Some(reason.into());
            return receipt;
        }
    };
    receipt.target_file_sha256 = Some(copied_hash);
    receipt.source_sha256 = Some(tree_digest.sha256.clone());
    receipt.exclusions = Some(snapshot.exclusions.clone());
    receipt.adapter_sha256 = Some(sha256_hex(adapter.as_bytes()));
    receipt.image_id = Some(sandbox.image_id().to_string());
    if let Some(node) = node.as_ref() {
        let runtime = node.runtime(&snapshot.path, call, &source, class);
        if let Err(reason) = receipt.bind_node_runtime(runtime, class) {
            receipt.reason = Some(reason.into());
            return receipt;
        }
    }

    let malicious = fixture_inputs(class)[0];
    let plans = [
        ("target", malicious),
        ("benign_control", benign_input(class)),
        ("fresh_nonce_rerun", malicious),
    ];
    for (name, payload) in plans {
        let secrets = OracleSecrets::fresh();
        let runner = match &receipt.runtime {
            Some(runtime) => super::poc_oracle::node_target_runner(
                class,
                &secrets,
                payload,
                runtime.plan_driver(),
            ),
            None => target_runner(class, &secrets, payload),
        };
        let started = Instant::now();
        let result = match node.as_ref() {
            Some(node) => {
                sandbox
                    .run_node(
                        node,
                        &snapshot.path,
                        &runner,
                        &adapter,
                        &runner_input(&secrets),
                        class,
                    )
                    .await
            }
            None => {
                sandbox
                    .run(&snapshot.path, &runner, &adapter, &runner_input(&secrets))
                    .await
            }
        };
        let elapsed_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        let mut phase = TargetPocPhase {
            surfaced: None,
            reached: None,
            reach_source: None,
            reach_sha256: None,
            reach: None,
            executable: None,
            name: name.into(),
            nonce_commitment: sha256_hex(secrets.marker.as_bytes()),
            effect: None,
            functional: None,
            exit_code: None,
            transcript_sha256: None,
            elapsed_ms,
            reason: None,
        };
        match result {
            Ok((exit, output)) => {
                phase.exit_code = Some(exit);
                phase.transcript_sha256 = Some(sha256_hex(output.as_bytes()));
                if class == OracleClass::Ssrf
                    && exit == 4
                    && !has_marked_verdict(&output, &secrets.marker)
                {
                    phase.reason = Some("ssrf_listener_unavailable".into());
                } else if let (Some(runtime), Some(node)) = (&receipt.runtime, node.as_ref()) {
                    match parse_node_verdict(&output, &secrets.marker, class) {
                        Ok(mut verdict) if exit == 0 => {
                            node.redact(&mut verdict);
                            phase.record_node_verdict(&verdict, runtime);
                        }
                        Ok(_) => phase.reason = Some("target_execution_error".into()),
                        Err(reason) => phase.reason = Some(reason.into()),
                    }
                } else {
                    match parse_verdict(&output, &secrets.marker) {
                        // A raising target call stays an execution error here,
                        // as before `raised=` existed.
                        Ok(v) if exit == 0 && !v.error && !v.raised => {
                            phase.effect = Some(v.effect);
                            phase.functional = v.functional;
                        }
                        Ok(_) => phase.reason = Some("target_execution_error".into()),
                        Err(reason) => phase.reason = Some(reason.into()),
                    }
                }
            }
            Err(error) => phase.reason = Some(sandbox_error_reason(&error).into()),
        }
        receipt.phases.push(phase);
    }

    if snapshot_digest(&snapshot.path).ok().as_ref() != Some(&tree_digest)
        || source_file_digest(&snapshot.path, &call.file)
            .ok()
            .as_deref()
            != receipt.target_file_sha256.as_deref()
    {
        receipt.reason = Some("snapshot_changed".into());
        attach_verification_event(&mut receipt, finding, call, class);
        return receipt;
    }
    if receipt
        .phases
        .iter()
        .any(|phase| phase.reason.is_some() || phase.effect.is_none())
    {
        receipt.reason = receipt
            .phases
            .iter()
            .find_map(|phase| phase.reason.clone())
            .or_else(|| Some("phase_incomplete".into()));
        attach_verification_event(&mut receipt, finding, call, class);
        return receipt;
    }
    match derive_outcome(&receipt.phases, class, receipt.runtime.as_ref()) {
        TargetPocOutcome::Inconclusive => {
            receipt.reason = Some("non_differential_result".into());
        }
        outcome => {
            receipt.outcome = outcome;
            receipt.reason = None;
        }
    }
    attach_verification_event(&mut receipt, finding, call, class);
    *kept = Some(snapshot);
    receipt
}

fn attach_verification_event(
    receipt: &mut TargetPocReceipt,
    finding: &Finding,
    call: &TargetCall,
    class: OracleClass,
) {
    if receipt.target_file != call.file || receipt.target_function != call.function {
        return;
    }
    let Some(image_id) = receipt.image_id.clone() else {
        return;
    };
    let ir = match receipt.canonical_ir(class, &finding.id, finding.line) {
        Ok(ir) => ir,
        Err(_) => return,
    };

    let reason = receipt.reason.as_deref();
    let mut tampering = Vec::new();
    if matches!(
        reason,
        Some("duplicate_target_verdict" | "invalid_target_verdict" | "target_verdict_missing")
    ) {
        tampering.push(TamperSignal::VerdictChannelForgery);
    }
    if reason == Some("snapshot_changed") {
        tampering.push(TamperSignal::SourceIdentityDrift);
    }
    let all_transcripts = !receipt.phases.is_empty()
        && receipt
            .phases
            .iter()
            .all(|phase| phase.transcript_sha256.is_some());
    let all_zero = !receipt.phases.is_empty()
        && receipt
            .phases
            .iter()
            .all(|phase| phase.exit_code == Some(0));
    let benign_healthy = receipt.phases.get(1).and_then(|phase| phase.effect) == Some(false)
        && match class {
            OracleClass::CommandInjection => true,
            OracleClass::PathTraversal | OracleClass::Sqli | OracleClass::Ssrf => {
                receipt.phases.get(1).and_then(|phase| phase.functional) == Some(true)
            }
        };
    let fresh_challenge = match (receipt.phases.first(), receipt.phases.get(2)) {
        (Some(first), Some(second)) => first
            .effect
            .zip(second.effect)
            .map(|(a, b)| a == b && first.nonce_commitment != second.nonce_commitment),
        _ => None,
    };
    let challenge_commitment = sha256_hex(
        serde_json::to_vec(
            &receipt
                .phases
                .iter()
                .map(|phase| &phase.nonce_commitment)
                .collect::<Vec<_>>(),
        )
        .unwrap_or_default()
        .as_slice(),
    );
    let transcript_sha256 = all_transcripts.then(|| {
        sha256_hex(
            serde_json::to_vec(
                &receipt
                    .phases
                    .iter()
                    .filter_map(|phase| phase.transcript_sha256.as_deref())
                    .collect::<Vec<_>>(),
            )
            .unwrap_or_default()
            .as_slice(),
        )
    });
    let effect_observed = match receipt.outcome {
        TargetPocOutcome::EffectObserved => Some(true),
        TargetPocOutcome::EffectAbsent => Some(false),
        TargetPocOutcome::Inconclusive => None,
    };
    let cleanup = if all_transcripts {
        // TargetSandbox returns Ok only after the backend has confirmed
        // cleanup. Err deliberately cannot distinguish capture from cleanup.
        CleanupState::Confirmed
    } else {
        CleanupState::Unknown
    };
    let observations = HostObservations {
        backend_kind: BackendKind::Docker,
        backend_identity: image_id,
        platform: "linux/container".into(),
        challenge_commitment,
        capture_complete: all_transcripts,
        cleanup,
        tampering,
        effect_observed,
        benign_control: all_transcripts.then_some(benign_healthy),
        fresh_challenge_control: fresh_challenge,
        exit_code: all_zero.then_some(0),
        transcript_sha256,
        replay_grade: ReplayGrade::Semantic,
    };
    if let Ok(event) = VerificationEvent::from_host_observations(ir, observations) {
        debug_assert_eq!(
            event.decision.verdict,
            match receipt.outcome {
                TargetPocOutcome::EffectObserved => DerivedVerdict::EffectObserved,
                TargetPocOutcome::EffectAbsent => DerivedVerdict::EffectAbsent,
                TargetPocOutcome::Inconclusive => DerivedVerdict::Inconclusive,
            }
        );
        receipt.verification_event = Some(event);
    }
}

fn valid_image_id(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(is_sha256)
}

/// Read the target inside `root` under the reproduce path rules: a safe
/// relative `.py`-style path, no symlinked component, a regular file within
/// the size cap, not a secret file, UTF-8. Returns `(source, sha256)`.
pub(crate) fn read_target_source(
    root: &Path,
    file: &str,
) -> Result<(String, String), &'static str> {
    let safe = vettalon_contract::safe_path::SafeRepoPath::parse(file)
        .map_err(|_| "unsafe_target_path")?;
    let root = std::fs::canonicalize(root).map_err(|_| "unsafe_target_path")?;
    let mut path = PathBuf::from(&root);
    let parts: Vec<&str> = safe.as_str().split('/').collect();
    for (index, part) in parts.iter().enumerate() {
        path.push(part);
        let meta = std::fs::symlink_metadata(&path).map_err(|_| "unsafe_target_path")?;
        if meta.file_type().is_symlink()
            || (index + 1 < parts.len() && !meta.is_dir())
            || (index + 1 == parts.len()
                && (!meta.is_file() || meta.len() > TARGET_SOURCE_MAX_BYTES))
        {
            return Err("unsafe_target_path");
        }
    }
    let basename = parts.last().copied().unwrap_or("");
    if crate::util::is_secret_file(basename) {
        return Err("unsafe_target_path");
    }
    let before = std::fs::symlink_metadata(&path).map_err(|_| "unsafe_target_path")?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut input = options.open(&path).map_err(|_| "unsafe_target_path")?;
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut input)
        .take(TARGET_SOURCE_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "unsafe_target_path")?;
    let after = input.metadata().map_err(|_| "unsafe_target_path")?;
    if bytes.len() as u64 > TARGET_SOURCE_MAX_BYTES
        || after.len() != before.len()
        || after.len() != bytes.len() as u64
    {
        return Err("source_changed_during_read");
    }
    let hash = sha256_hex(&bytes);
    let source = String::from_utf8(bytes).map_err(|_| "target_source_not_utf8")?;
    Ok((source, hash))
}

pub(crate) fn declares_top_level_function(source: &str, function: &str) -> bool {
    let direct = format!("def {function}(");
    source.lines().any(|line| line.starts_with(&direct))
}

pub(crate) fn declares_top_level_async_function(source: &str, function: &str) -> bool {
    let asynchronous = format!("async def {function}(");
    source.lines().any(|line| line.starts_with(&asynchronous))
}

pub(super) fn has_marked_verdict(output: &str, marker: &str) -> bool {
    output.lines().any(|line| {
        line.trim()
            .strip_prefix("__VTL_ORACLE__ ")
            .is_some_and(|rest| rest.split_whitespace().next() == Some(marker))
    })
}

/// The fields of a runner's marked verdict line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct HarnessVerdict {
    pub surfaced: Option<bool>,
    pub effect: bool,
    /// The benign input's known good result (`None` when the class has none).
    pub functional: Option<bool>,
    /// A harness-side failure: timeout, non-zero child exit, missing,
    /// oversized or invalid result, or evidence altered while the sink ran.
    pub error: bool,
    /// The adapter or the target code raised a Python exception.
    pub raised: bool,
    /// The child running the checked code hit the runner's time limit
    /// (reported together with `error`).
    pub timeout: bool,
}

/// The single line bearing `marker`. No such line, or one without
/// `effect=`, is `target_verdict_missing`; more than one marked line, whatever
/// fields the others carry, is `duplicate_target_verdict` (the runner writes
/// exactly one), as is a repeated `effect=` or `functional=`.
pub(super) fn parse_verdict(output: &str, marker: &str) -> Result<HarnessVerdict, &'static str> {
    let mut effect = None;
    let mut functional = None;
    let mut surfaced = None;
    let mut error = false;
    let mut raised = false;
    let mut timeout = false;
    let mut marked = 0usize;
    for line in output.lines().map(str::trim) {
        let Some(rest) = line.strip_prefix("__VTL_ORACLE__ ") else {
            continue;
        };
        let mut parts = rest.split_whitespace();
        if parts.next() != Some(marker) {
            continue;
        }
        marked += 1;
        if marked != 1 {
            return Err("duplicate_target_verdict");
        }
        for part in parts {
            let parse_bool = |raw: &str| match raw {
                "true" => Ok(true),
                "false" => Ok(false),
                _ => Err("invalid_target_verdict"),
            };
            if let Some(raw) = part.strip_prefix("effect=") {
                if effect.is_some() {
                    return Err("duplicate_target_verdict");
                }
                effect = Some(parse_bool(raw)?);
            } else if let Some(raw) = part.strip_prefix("functional=") {
                if functional.is_some() {
                    return Err("duplicate_target_verdict");
                }
                functional = Some(parse_bool(raw)?);
            } else if let Some(raw) = part.strip_prefix("surfaced=") {
                if surfaced.is_some() {
                    return Err("duplicate_target_verdict");
                }
                surfaced = Some(parse_bool(raw)?);
            } else if let Some(raw) = part.strip_prefix("error=") {
                error |= parse_bool(raw)?;
            } else if let Some(raw) = part.strip_prefix("raised=") {
                raised |= parse_bool(raw)?;
            } else if let Some(raw) = part.strip_prefix("timeout=") {
                timeout |= parse_bool(raw)?;
            } else {
                return Err("invalid_target_verdict");
            }
        }
    }
    let Some(effect) = effect.filter(|_| marked == 1) else {
        return Err("target_verdict_missing");
    };
    Ok(HarnessVerdict {
        surfaced,
        effect,
        functional,
        error,
        raised,
        timeout,
    })
}

#[cfg(test)]
#[path = "target_poc_tests.rs"]
pub(crate) mod tests;

#[cfg(test)]
#[path = "target_poc_node_tests.rs"]
mod node_tests;
