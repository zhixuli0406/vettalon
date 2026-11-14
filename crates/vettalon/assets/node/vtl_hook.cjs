'use strict';

// Cache eviction must not reopen initialization, even if the first load was
// inert. The permanent own property also survives replacement of Object APIs.
const ObjectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const initializationKey = '__vettalon_node_hook_initialized__';
const ReloadError = Error;
if (process[initializationKey] !== undefined || ObjectGetOwnPropertyDescriptor(process, initializationKey)) {
  module.exports = Object.freeze(Object.assign(Object.create(null), {
    configureTarget() { throw new ReloadError('node_hook_failed: hook already initialized'); }
  }));
  return;
}
Object.defineProperty(process, initializationKey, { value: Symbol('vtl hook initialized') });

// These records are attacker-controlled diagnostics, NEVER proof of an effect.
// Only the out-of-process runner may evaluate evidence or emit a verdict.
const fs = require('node:fs');
const path = require('node:path');
const util = require('node:util');
const modules = require('node:module');
const childProcess = require('node:child_process');
const compileFunction = require('node:vm').compileFunction;
const { fileURLToPath, pathToFileURL } = require('node:url');
const { createHash } = require('node:crypto');
const apply = Reflect.apply;
const stringify = JSON.stringify;
const stringSlice = Function.prototype.call.bind(String.prototype.slice);
const startsWith = Function.prototype.call.bind(String.prototype.startsWith);
const endsWith = Function.prototype.call.bind(String.prototype.endsWith);
const regexTest = Function.prototype.call.bind(RegExp.prototype.test);
const mapGet = Function.prototype.call.bind(Map.prototype.get);
const mapHas = Function.prototype.call.bind(Map.prototype.has);
const isArray = Array.isArray;
const arrayPush = Function.prototype.call.bind(Array.prototype.push);
const arraySplice = Function.prototype.call.bind(Array.prototype.splice);
const arrayJoin = Function.prototype.call.bind(Array.prototype.join);
const isProxy = util.types.isProxy;
const create = Object.create;
const ObjectSetPrototypeOf = Object.setPrototypeOf;
const freeze = Object.freeze;
const defineProperty = Object.defineProperty;
const getDescriptor = Object.getOwnPropertyDescriptor;
const getDescriptors = Object.getOwnPropertyDescriptors;
const defineProperties = Object.defineProperties;
const objectKeys = Object.keys;
const assign = Object.assign;
const hasOwn = Object.hasOwn;
const NativeError = Error;
const NativeURL = URL;
const urlHref = Function.prototype.call.bind(getDescriptor(URL.prototype, 'href').get);
const bufferUtf8Slice = Function.prototype.call.bind(Buffer.prototype.utf8Slice);
const typedArrayLength = Function.prototype.call.bind(
  getDescriptor(Object.getPrototypeOf(Uint8Array.prototype), 'length').get);
const hashPrototype = Object.getPrototypeOf(createHash('sha256'));
const hashUpdate = Function.prototype.call.bind(hashPrototype.update);
const hashDigest = Function.prototype.call.bind(hashPrototype.digest);
const isBuffer = Buffer.isBuffer;
const bufferFrom = Buffer.from;
const ceil = Math.ceil;
const isFinite = Number.isFinite;
const numberString = String;
const writeSync = fs.writeSync;
const fstatSync = fs.fstatSync;
const readFileSync = fs.readFileSync;
const statSync = fs.statSync;
const lstatSync = fs.lstatSync;
const realpathSync = fs.realpathSync;
const resolvePath = path.resolve;
const joinPath = path.join;
const pathSeparator = path.sep;
const processId = process.pid;
const byteLength = Buffer.byteLength;
const cwd = process.cwd.bind(process);
const defer = process.nextTick.bind(process);
const dbPath = process.env.VTL_DB;
const base = resolvePath(process.env.VTL_BASE || '/tmp/vtl_base');
const value = process.env.VTL_EVENT_FD;
delete process.env.VTL_EVENT_FD;
delete process.env.VTL_HOOK_ROOT;
module.exports = freeze(create(null));
// Descendants inherit --require but not the consumed configuration. Workers
// are always inert, even with explicitly supplied env. Missing events mean
// unknown reach, never evidence that a sink did not execute.
if (!require('node:worker_threads').isMainThread || !value) {
  return;
}
let eventFd;
try {
  if (!/^[0-9]+$/.test(value || '')) throw new Error('invalid fd');
  eventFd = Number(value);
  const stat = fstatSync(eventFd);
  // The runner opens separate read/write descriptions, then unlinks the file.
  // Requiring this shape avoids accidentally using stdout or a named log file.
  if (eventFd < 3 || !Number.isSafeInteger(eventFd) || !stat.isFile() ||
      stat.nlink !== 0 || stat.size !== 0 || typeof modules.registerHooks !== 'function') {
    throw new Error('invalid event channel');
  }
} catch {
  return;
}

let sequence = 0;
let totalBytes = 0;
let recordingFailed = false;
// Diagnostics never change process exit status. Missing or incomplete reach
// data must be treated as unknown by the out-of-process runner.
const fieldsAllowed = freeze(['class', 'api', 'raw', 'path', 'inside_base',
  'file', 'argv', 'shell', 'driver', 'query', 'params', 'executable',
  'filename', 'requested_api']);
function ownData(value, key) {
  if (value === null || (typeof value !== 'object' && typeof value !== 'function') || isProxy(value)) return undefined;
  const descriptor = getDescriptor(value, key);
  return descriptor && hasOwn(descriptor, 'value') ? descriptor.value : undefined;
}
function record(fields) {
  if (recordingFailed) return;
  try {
    let truncated = false;
    function copy(value, depth = 0) {
      if (typeof value === 'string') {
        if (value.length > 2048) { truncated = true; return stringSlice(value, 0, 2048); }
        return value;
      }
      if (value == null) return null;
      if (typeof value === 'boolean' || typeof value === 'number') return value;
      // Never inspect target objects, invoke accessors, or enter Proxy traps.
      if (!isProxy(value) && isArray(value) && depth < 3) {
        const length = ownData(value, 'length');
        if (length > 32) truncated = true;
        const result = [];
        ObjectSetPrototypeOf(result, null);
        for (let i = 0; i < length && i < 32; i++) {
          defineProperty(result, i, { value: copy(ownData(value, i), depth + 1), writable: true, enumerable: true });
        }
        return result;
      }
      truncated = true;
      return '[uninspected]';
    }
    const event = create(null);
    event.v = 1;
    event.seq = sequence + 1;
    for (let i = 0; i < fieldsAllowed.length; i++) {
      const key = fieldsAllowed[i];
      const value = ownData(fields, key);
      if (value !== undefined) event[key] = copy(value);
    }
    if (truncated) event.truncated = true;
    function encode(value) {
      // JSON.stringify only receives primitive strings, never event objects.
      if (typeof value === 'string') return stringify(value);
      if (typeof value === 'number') return isFinite(value) ? numberString(value) : 'null';
      if (typeof value === 'boolean') return value ? 'true' : 'false';
      if (value === null) return 'null';
      let text = '[';
      for (let i = 0; i < value.length; i++) text += (i ? ',' : '') + encode(value[i]);
      return text + ']';
    }
    const keys = objectKeys(event);
    function serialize() {
      let line = '{';
      for (let i = 0; i < keys.length; i++) {
        const key = keys[i];
        line += (i ? ',' : '') + stringify(key) + ':' + encode(event[key]);
      }
      if (event.truncated && !truncated) line += ',"truncated":true';
      return line + '}\n';
    }
    function shrink(value) {
      if (typeof value === 'string' && value.length > 32) return stringSlice(value, 0, ceil(value.length / 2));
      if (isArray(value)) for (let i = 0; i < value.length; i++) value[i] = shrink(value[i]);
      return value;
    }
    let line = serialize();
    while (byteLength(line) > 4096) {
      for (let i = 0; i < fieldsAllowed.length; i++) {
        const key = fieldsAllowed[i];
        if (event[key] !== undefined) event[key] = shrink(event[key]);
      }
      event.truncated = true;
      const smaller = serialize();
      if (smaller.length === line.length) throw new NativeError('event too large');
      line = smaller;
    }
    if (sequence >= 256 || totalBytes + byteLength(line) > 65536) throw new NativeError('event limit');
    const bytes = bufferFrom(line);
    const length = typedArrayLength(bytes);
    let offset = 0;
    while (offset < length) {
      const written = writeSync(eventFd, bytes, offset, length - offset);
      if (written <= 0) throw new NativeError('short event write');
      offset += written;
    }
    totalBytes += length;
    sequence++;
  } catch { recordingFailed = true; }
}

function wrap(original, before, copyCustom = true, guard) {
  function wrapped(...args) {
    if (guard) guard(args);
    try { before(args); } catch { recordingFailed = true; }
    return apply(original, this, args);
  }
  const descriptors = getDescriptors(original);
  const custom = util.promisify.custom;
  if (copyCustom && descriptors[custom]) {
    // Node's custom promisifier closes over the ORIGINAL function; copying it
    // verbatim would silently bypass reach recording for promisified exec.
    const promisified = wrap(original[custom], before, false, guard);
    descriptors[custom] = 'value' in descriptors[custom]
      ? { ...descriptors[custom], value: promisified }
      : { ...descriptors[custom], get: () => promisified };
  }
  defineProperties(wrapped, descriptors);
  return wrapped;
}

function normalise(value) {
  if (typeof value === 'number') return null; // fd overload, not a pathname
  try {
    if (value !== null && typeof value === 'object') {
      if (isProxy(value)) return null;
      if (isBuffer(value)) value = bufferUtf8Slice(value, 0, typedArrayLength(value));
      else { try { value = fileURLToPath(urlHref(value)); } catch { return null; } }
    }
    return typeof value === 'string' ? resolvePath(cwd(), value) : null;
  } catch { return null; } // Let the original API report invalid arguments.
}

function pathDiagnostic(value) {
  // Node's loader opens file URLs. These supported path types have safe,
  // captured conversions and must not mark an otherwise complete log truncated.
  if (value !== null && typeof value === 'object' && !isProxy(value)) {
    if (isBuffer(value)) return bufferUtf8Slice(value, 0, typedArrayLength(value));
    try { return urlHref(value); } catch { /* Keep other objects uninspected. */ }
  }
  return value;
}

function protectChannel(value) {
  const resolved = normalise(value);
  if (value === eventFd || resolved === `/dev/fd/${eventFd}` ||
      resolved === `/proc/self/fd/${eventFd}` || resolved === `/proc/${processId}/fd/${eventFd}`) {
    // This stops ordinary fs reads/closes, not inspector/native/internal API
    // attacks. The inherited fd is write-only; the runner owns its read fd.
    throw assign(new NativeError('node_hook_failed: protected event channel'), { code: 'EACCES' });
  }
}

for (const name of ['readFile', 'readFileSync', 'createReadStream', 'open', 'openSync']) {
  fs[name] = wrap(fs[name], args => {
    const resolved = normalise(args[0]);
    record({ class: 'CWE-22', api: `fs.${name}`, raw: pathDiagnostic(args[0]), path: resolved,
      inside_base: resolved !== null && (resolved === base || startsWith(resolved, base + pathSeparator)) });
  }, true, args => {
    protectChannel(args[0]);
    if (name === 'createReadStream') protectChannel(ownData(args[1], 'fd'));
  });
}
for (const name of ['readFile', 'open']) {
  fs.promises[name] = wrap(fs.promises[name], args => {
    const resolved = normalise(args[0]);
    record({ class: 'CWE-22', api: `fs.promises.${name}`, raw: pathDiagnostic(args[0]), path: resolved,
      inside_base: resolved !== null && (resolved === base || startsWith(resolved, base + pathSeparator)) });
  }, true, args => protectChannel(args[0]));
}
for (const name of ['read', 'readSync', 'readv', 'readvSync', 'close', 'closeSync']) {
  fs[name] = wrap(fs[name], () => {}, true, args => protectChannel(args[0]));
}
// Streams can close a supplied descriptor even without reading it.
fs.createWriteStream = wrap(fs.createWriteStream, () => {}, true, args => {
  protectChannel(args[0]);
  protectChannel(ownData(args[1], 'fd'));
});

function forkArguments(execArgv, file, argv) {
  const result = [];
  ObjectSetPrototypeOf(result, null);
  function append(value) { defineProperty(result, result.length, { value, enumerable: true }); }
  function appendArray(array) {
    if (isProxy(array) || !isArray(array)) return;
    const length = ownData(array, 'length');
    for (let i = 0; i < length && i < 32; i++) append(ownData(array, i));
  }
  appendArray(execArgv);
  append(file);
  appendArray(argv);
  return result;
}

// Keep unrelated preloads and options intact. Match this exact hook filename;
// arbitrary shell commands/native/internal APIs remain outside this boundary.
function stripHookPreload(tokens) {
  const result = [];
  for (let i = 0; i < tokens.length; i++) {
    const value = tokens[i].value;
    if ((value === '--require' || value === '-r') && tokens[i + 1]?.value === __filename) {
      i++;
    } else if (value !== '--require=' + __filename && value !== '-r' + __filename && value !== '-r=' + __filename) {
      arrayPush(result, tokens[i]);
    }
  }
  return result;
}
function cleanExecArgv(argv) {
  const tokens = [];
  for (let i = 0; i < argv.length; i++) arrayPush(tokens, { value: argv[i] });
  const kept = stripHookPreload(tokens);
  const result = [];
  for (let i = 0; i < kept.length; i++) arrayPush(result, kept[i].value);
  return result;
}
function cleanNodeOptions(text) {
  // Node accepts space-separated options, double quotes and escaped characters
  // inside quotes. Preserve original spelling of every retained option.
  const tokens = [];
  let start = -1;
  let value = '';
  let quoted = false;
  for (let i = 0; i <= text.length; i++) {
    const ch = text[i];
    if (i === text.length || (!quoted && ch === ' ')) {
      if (start !== -1) arrayPush(tokens, { value, raw: stringSlice(text, start, i) });
      start = -1;
      value = '';
    } else {
      if (start === -1) start = i;
      if (ch === '"') quoted = !quoted;
      else if (quoted && ch === '\\' && i + 1 < text.length) value += text[++i];
      else value += ch;
    }
  }
  const kept = stripHookPreload(tokens);
  const result = [];
  for (let i = 0; i < kept.length; i++) arrayPush(result, kept[i].raw);
  return arrayJoin(result, ' ');
}
function cleanChildOptions(name, args) {
  const command = name === 'exec' || name === 'execSync';
  const index = command ? 1 : (isArray(args[1]) || (args[1] == null && args[2] !== undefined) ? 2 : 1);
  const original = args[index];
  if (original != null && typeof original !== 'object' && typeof original !== 'function') return;
  // Match Node's own options copy: getters are evaluated once, then the
  // original API receives plain values. Never mutate caller-owned options.
  const options = assign(create(null), typeof original === 'object' ? original : null);
  const env = options.env == null ? process.env : options.env;
  const cleanEnv = create(null);
  for (const key in env) {
    if (startsWith(key, 'VTL_')) continue;
    const value = env[key];
    cleanEnv[key] = key === 'NODE_OPTIONS' && typeof value === 'string' ? cleanNodeOptions(value) : value;
  }
  options.env = cleanEnv;
  if (name === 'fork') options.execArgv = cleanExecArgv(options.execArgv || process.execArgv);
  else if (isArray(options.execArgv)) options.execArgv = cleanExecArgv(options.execArgv);
  if (!command && name !== 'fork' && isArray(args[1])) args[1] = cleanExecArgv(args[1]);
  if (typeof original === 'function') arraySplice(args, index, 0, options);
  else args[index] = options;
}

for (const name of ['exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync', 'fork']) {
  childProcess[name] = wrap(childProcess[name], args => {
    const command = name === 'exec' || name === 'execSync';
    const argv = command ? [] : (isArray(args[1]) ? args[1] : []);
    const options = args[command ? 1 : (isArray(args[1]) ? 2 : 1)] || {};
    // execFile defaults to shell:false despite its name; fork includes the
    // actual Node executable/execArgv, as these are executable arguments too.
    const shell = command ? (ownData(options, 'shell') || true) : (ownData(options, 'shell') || false);
    record({ class: 'CWE-78', api: `child_process.${name}`,
      file: name === 'fork' ? (ownData(options, 'execPath') || ownData(process, 'execPath')) : args[0],
      argv: name === 'fork' ? forkArguments(ownData(options, 'execArgv') || ownData(process, 'execArgv'), args[0], argv) : argv,
      shell });
  }, true, args => cleanChildOptions(name, args));
}
modules.syncBuiltinESMExports();

let identity;
function configureTarget({ target_url, target_file_sha256 }) {
  // D7 calls this once, from the trusted adapter, before importing the target.
  // It is a binding check, not an authenticity boundary within the JS process.
  if (identity || !regexTest(/^[a-f0-9]{64}$/, target_file_sha256 || '')) {
    throw new NativeError('node_hook_failed: invalid target identity');
  }
  const url = new NativeURL(target_url);
  if (url.protocol !== 'file:' || url.search || url.hash) throw new NativeError('node_hook_failed: invalid target URL');
  identity = create(null);
  identity.path = realpathSync(fileURLToPath(urlHref(url)));
  identity.hash = target_file_sha256;
}

const shims = new Map(['sqlite3', 'pg', 'mysql2'].map(driver =>
  [driver, pathToFileURL(joinPath(__dirname, `vtl_shim_${driver}.cjs`)).href]));
// CJS caches by filename, ignoring URL queries. Use a distinct virtual filename
// for the promise facade; load supplies its source without a fifth disk asset.
shims.set('mysql2/promise', pathToFileURL(joinPath(__dirname, 'vtl_mysql2_promise_bridge.cjs')).href);
function fileKind(filename, entry = false) {
  try { return ((entry ? lstatSync : statSync)(filename).mode & 0o170000) === 0o100000 ? 'file' : 'other'; } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'ENOTDIR') return 'absent';
    throw error;
  }
}
modules.registerHooks({
  resolve(specifier, context, nextResolve) {
    if (mapHas(shims, specifier)) return { url: mapGet(shims, specifier), shortCircuit: true };
    // Only relative emitted .js paths are mapped. Existing JS always wins;
    // bare packages, .mjs/.cjs, aliases and non-erasable TS are not emulated.
    if (regexTest(/^\.{1,2}\//, specifier) && endsWith(specifier, '.js') && (typeof context.parentURL === 'string' && startsWith(context.parentURL, 'file:'))) {
      const js = new NativeURL(specifier, context.parentURL);
      const ts = new NativeURL(stringSlice(urlHref(js), 0, -3) + '.ts');
      if (fileKind(fileURLToPath(urlHref(js)), true) === 'absent' && fileKind(fileURLToPath(urlHref(ts))) === 'file') return nextResolve(fileURLToPath(urlHref(ts)), context);
    }
    return nextResolve(specifier, context);
  },
  load(url, context, nextLoad) {
    if (url === mapGet(shims, 'mysql2/promise')) {
      return { format: 'commonjs', shortCircuit: true,
        source: `const driver = require(${stringify(joinPath(__dirname, 'vtl_shim_mysql2.cjs'))}).promiseDriver;
exports.createConnection = driver.createConnection; exports.createPool = driver.createPool; module.exports = driver;` };
    }
    if (identity && startsWith(url, 'file:') && realpathSync(fileURLToPath(url)) === identity.path) {
      const bytes = readFileSync(identity.path);
      if (hashDigest(hashUpdate(createHash('sha256'), bytes), 'hex') !== identity.hash) {
        throw new NativeError('node_hook_failed: target identity mismatch');
      }
      const loaded = nextLoad(url, context);
      // Execute the very bytes checked, including for CJS and TS; no second
      // filesystem read can swap in unchecked source between hash and execute.
      return { ...loaded, source: bytes };
    }
    return nextLoad(url, context);
  }
});

function sqlEvent(driver, api, query, params, executable, extra = {}) {
  record({ class: 'CWE-89', driver, api, query, params, executable, ...extra });
}
function unsupported(driver, api) {
  sqlEvent(driver, 'api_unsupported', '', [], driver === 'sqlite3', { requested_api: api });
  throw assign(new NativeError(`node_driver_api_unsupported: ${driver}.${api}`), { code: 'node_driver_api_unsupported' });
}
function guardApi(value, driver, unsupportedApis = []) {
  // Only concrete, documented driver APIs get stubs. Unknown names retain
  // normal feature-detection semantics, including optionalHook/then/toJSON.
  for (let i = 0; i < unsupportedApis.length; i++) {
    const key = unsupportedApis[i];
    defineProperty(value, key, { value: () => unsupported(driver, key), enumerable: false });
  }
  return value;
}

// Evaluate shim source privately: the capability never crosses a CommonJS
// export or Module._load call, even transiently. Only driver APIs enter cache.
// Direct shim loads after cache eviction are inert (no sixth wrapper argument).
const capability = freeze({ sqlEvent, guardApi, unsupported, dbPath, defer });
for (const driver of ['pg', 'mysql2', 'sqlite3']) {
  const filename = joinPath(__dirname, `vtl_shim_${driver}.cjs`);
  const shim = new modules.Module(filename, module);
  shim.filename = filename;
  const evaluate = compileFunction(readFileSync(filename, 'utf8'),
    ['exports', 'require', 'module', '__filename', '__dirname', 'capability'], { filename });
  evaluate(shim.exports, require, shim, filename, __dirname, capability);
  shim.loaded = true;
  require.cache[filename] = shim;
}
module.exports = freeze(assign(create(null), { configureTarget }));
