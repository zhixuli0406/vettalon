import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const hook = fileURLToPath(new URL('../../../crates/vettalon/assets/node/vtl_hook.cjs', import.meta.url));
const prefix = `
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const require = createRequire(process.cwd() + '/vtl-test.cjs');
const fs = require('node:fs');
const cp = require('node:child_process');
const util = require('node:util');
const hook = require(${JSON.stringify(hook)});
`;

function run(source, options = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'vtl-node-test-'));
  const eventPath = path.join(directory, 'events');
  fs.writeFileSync(eventPath, '', { mode: 0o600, flag: 'wx' });
  const writer = fs.openSync(eventPath, fs.constants.O_WRONLY | fs.constants.O_APPEND);
  const reader = fs.openSync(eventPath, fs.constants.O_RDONLY);
  fs.unlinkSync(eventPath);
  try {
    const env = { ...process.env, VTL_EVENT_FD: '3', VTL_HOOK_ROOT: '1', VTL_BASE: directory,
      VTL_DB: path.join(directory, 'fixture.db'), TEST_DIR: directory, ...options.env };
    delete env.NODE_OPTIONS;
    delete env.NODE_PATH;
    for (const [name, content] of Object.entries(options.files || {})) {
      fs.mkdirSync(path.dirname(path.join(directory, name)), { recursive: true });
      fs.writeFileSync(path.join(directory, name), content);
    }
    const main = path.join(directory, 'main.mjs');
    fs.writeFileSync(main, prefix + source);
    const preloads = [];
    if (options.before) {
      const before = path.join(directory, 'before.cjs');
      fs.writeFileSync(before, options.before);
      preloads.push('--require', before);
    }
    const result = spawnSync(process.execPath,
      [...preloads, '--require', hook, main],
      { env, stdio: ['ignore', 'pipe', 'pipe', writer], encoding: 'utf8', timeout: 15000 });
    assert.ifError(result.error);
    const text = fs.readFileSync(reader, 'utf8');
    const events = text.trim() ? text.trimEnd().split('\n').map(line => JSON.parse(line)) : [];
    return { ...result, text, events, directory };
  } finally {
    fs.closeSync(writer);
    fs.closeSync(reader);
    fs.rmSync(directory, { recursive: true });
  }
}
function success(result) {
  assert.equal(result.status, 0, result.stderr);
  result.events.forEach((event, index) => {
    assert.equal(event.v, 1);
    assert.equal(event.seq, index + 1);
  });
  return result.events;
}

test('all wrappers preserve name, length, symbols and working promisify.custom', () => {
  const result = run(`
    for (const [name, original] of Object.entries(globalThis.originals)) {
      const wrapped = cp[name];
      assert.notEqual(wrapped, original);
      assert.equal(wrapped.name, original.name);
      assert.equal(wrapped.length, original.length);
      assert.deepEqual(Reflect.ownKeys(wrapped), Reflect.ownKeys(original));
    }
    for (const name of ['exec', 'execFile']) {
      assert.equal(typeof cp[name][util.promisify.custom], 'function');
    }
    const a = await util.promisify(cp.exec)('printf vtlbenign');
    const b = await util.promisify(cp.execFile)(process.execPath, ['-e', 'process.stdout.write("vtlbenign")']);
    assert.equal(a.stdout, 'vtlbenign');
    assert.equal(b.stdout, 'vtlbenign');
  `, { before: `globalThis.originals = Object.fromEntries(['exec','execSync','execFile','execFileSync','spawn','spawnSync','fork'].map(name => [name, require('node:child_process')[name]]));` });
  const events = success(result).filter(event => event.class === 'CWE-78');
  assert.ok(events.some(event => event.api === 'child_process.exec' && event.file === 'printf vtlbenign'));
  assert.ok(events.some(event => event.api === 'child_process.execFile' && event.argv.includes('-e')));
});

test('ESM named builtin imports see fs, promises and child_process wrappers', () => {
  const result = run(`
    const { execSync } = await import('node:child_process');
    const { readFileSync } = await import('node:fs');
    const { readFile } = await import('node:fs/promises');
    assert.equal(execSync, cp.execSync);
    assert.equal(readFileSync, fs.readFileSync);
    assert.equal(readFile, fs.promises.readFile);
    assert.equal(execSync('printf vtlbenign').toString(), 'vtlbenign');
    readFileSync(process.env.TEST_DIR + '/safe.txt');
    await readFile(process.env.TEST_DIR + '/safe.txt');
  `, { files: { 'safe.txt': 'safe' } });
  const events = success(result);
  assert.ok(events.some(event => event.api === 'child_process.execSync'));
  assert.ok(events.some(event => event.api === 'fs.promises.readFile'));
});

test('fs sync, callback, stream and promise paths normalise strings, Buffers and URLs', () => {
  const result = run(`
    const { pathToFileURL } = require('node:url');
    const file = process.env.TEST_DIR + '/sub/../safe.txt';
    fs.readFileSync(Buffer.from(file));
    await new Promise((resolve, reject) => fs.readFile(file, error => error ? reject(error) : resolve()));
    const fd = fs.openSync(pathToFileURL(file), 'r'); fs.closeSync(fd);
    await new Promise((resolve, reject) => fs.open(file, 'r', (error, fd) => {
      if (error) reject(error); else { fs.closeSync(fd); resolve(); }
    }));
    await fs.promises.readFile(pathToFileURL(file));
    const handle = await fs.promises.open(file, 'r'); await handle.close();
    for await (const chunk of fs.createReadStream(file)) {}
    try { fs.readFileSync(process.env.TEST_DIR + '-sibling/missing'); } catch {}
    try { fs.readFileSync('./vtl-definitely-missing'); } catch {}
  `, { files: { 'safe.txt': 'vtl_safe_content' }, before: `require('node:fs').mkdirSync(process.env.TEST_DIR + '/sub');` });
  const events = success(result);
  for (const api of ['readFileSync', 'readFile', 'openSync', 'open', 'promises.readFile', 'promises.open', 'createReadStream']) {
    assert.ok(events.some(event => event.api === 'fs.' + api && event.path === result.directory + '/safe.txt' && event.inside_base));
  }
  assert.ok(events.some(event => event.path === result.directory + '-sibling/missing' && !event.inside_base));
  assert.ok(events.some(event => event.path === path.resolve('./vtl-definitely-missing')));
});

test('process sinks record argv, shell options and fork executable', () => {
  const result = run(`
    cp.execFileSync(process.execPath, ['-e', ''], { shell: false });
    cp.spawnSync(process.execPath, ['-e', ''], { shell: false });
    await new Promise(resolve => cp.spawn(process.execPath, ['-e', '']).on('exit', resolve));
    await new Promise((resolve, reject) => cp.exec('printf vtlbenign', error => error ? reject(error) : resolve()));
    await new Promise((resolve, reject) => cp.execFile(process.execPath, ['-e', ''], error => error ? reject(error) : resolve()));
    await new Promise(resolve => cp.fork(process.env.TEST_DIR + '/child.cjs', ['vtlbenign'], { execArgv: [], stdio: 'ignore' }).on('exit', resolve));
  `, { files: { 'child.cjs': '' } });
  const events = success(result).filter(event => event.class === 'CWE-78');
  for (const name of ['execFileSync', 'spawnSync', 'spawn', 'exec', 'execFile', 'fork']) {
    assert.ok(events.some(event => event.api === 'child_process.' + name), name);
  }
  assert.ok(events.some(event => event.api === 'child_process.execFileSync' && event.shell === false && event.argv[0] === '-e'));
  assert.ok(events.some(event => event.api === 'child_process.fork' && event.file === process.execPath && event.argv.at(-1) === 'vtlbenign'));
});

test('relative .js maps to .ts for ESM and CJS; existing .js wins', () => {
  const result = run(`
    const { pathToFileURL } = require('node:url');
    const result = await import(pathToFileURL(process.env.TEST_DIR + '/entry.mjs'));
    assert.equal(result.mapped, 42); assert.equal(result.existing, 7);
    assert.equal(require(process.env.TEST_DIR + '/entry.cjs'), 42);
  `, { files: {
    'entry.mjs': `export { value as mapped } from './only.js'; export { value as existing } from './existing.js';`,
    'only.ts': 'export const value: number = 42;',
    'existing.js': 'export const value = 7;',
    'existing.ts': 'export const value: number = 99;',
    'entry.cjs': `module.exports = require('./only.js').value;`
  } });
  success(result);
});

for (const extension of ['mjs', 'cjs', 'ts']) {
  test(`identity checks bind executed ${extension} bytes and reject mismatches`, () => {
    const source = extension === 'cjs' ? 'exports.answer = 42;' :
      extension === 'ts' ? 'export const answer: number = 42;' : 'export const answer = 42;';
    const sha = createHash('sha256').update(source).digest('hex');
    const program = hash => `
      const { pathToFileURL } = require('node:url');
      const target = pathToFileURL(process.env.TEST_DIR + '/target.${extension}');
      hook.configureTarget({ target_url: target.href, target_file_sha256: '${hash}' });
      const ns = await import(target);
      assert.equal(ns.answer, 42);
      assert.throws(() => hook.configureTarget({ target_url: target.href, target_file_sha256: '${sha}' }), /invalid target identity/);
    `;
    success(run(program(sha), { files: { [`target.${extension}`]: source } }));
    const bad = run(program('0'.repeat(64)), { files: { [`target.${extension}`]: source } });
    assert.notEqual(bad.status, 0);
    assert.match(bad.stderr, /target identity mismatch/);
  });
}

test('pg and mysql2 callback/promise entry points record reach-only queries', () => {
  const result = run(`
    const { Client, Pool } = await import('pg');
    const client = new Client(); await client.connect();
    await assert.rejects(client.query({ text: 'SELECT vtl_secret WHERE x=$1', values: ['apple'] }), { code: 'sql_dialect_not_executable' });
    const pooled = await new Pool().connect();
    await new Promise(resolve => pooled.query('SELECT $1', ['apple'], error => { assert.equal(error.code, 'sql_dialect_not_executable'); resolve(); }));
    pooled.release(); await client.end();
    const mysql = require('mysql2');
    const connection = mysql.createConnection({});
    await new Promise(resolve => connection.query({ sql: 'SELECT vtl_secret', values: ['apple'] }, error => { assert.equal(error.code, 'sql_dialect_not_executable'); resolve(); }));
    await assert.rejects(connection.promise().execute('SELECT ?', ['apple']), { code: 'sql_dialect_not_executable' });
    const promiseDriver = (await import('mysql2/promise')).default;
    const promiseConnection = await promiseDriver.createConnection({});
    await assert.rejects(promiseConnection.query('SELECT vtl_secret'), { code: 'sql_dialect_not_executable' });
    const pool = promiseDriver.createPool({});
    await assert.rejects((await pool.getConnection()).execute('SELECT ?', ['apple']), { code: 'sql_dialect_not_executable' });
    const requirePromise = require('mysql2/promise');
    await assert.rejects((await requirePromise.createConnection({})).query('SELECT 1'), { code: 'sql_dialect_not_executable' });
  `);
  const events = success(result).filter(event => event.class === 'CWE-89');
  assert.equal(events.length, 7);
  assert.ok(events.every(event => event.executable === false));
  assert.ok(events.some(event => event.driver === 'pg' && event.params[0] === 'apple'));
  assert.ok(events.some(event => event.driver === 'mysql2' && event.query === 'SELECT vtl_secret'));
});

let hasSQLite = true;
try { await import('node:sqlite'); } catch { hasSQLite = false; }
test('sqlite3 Database and Statement use node:sqlite fixture with real query results', { skip: !hasSQLite }, () => {
  const result = run(`
    const sqlite = require('sqlite3').verbose();
    const { Database } = await import('sqlite3');
    assert.equal(Database, sqlite.Database);
    const db = new sqlite.Database('/must/not/be/opened.db');
    const call = (receiver, method, ...args) => new Promise((resolve, reject) => receiver[method](...args, function(error, rows) {
      if (error) reject(error); else resolve(method === 'run' ? { lastID: this.lastID, changes: this.changes } : rows);
    }));
    await call(db, 'exec', "CREATE TABLE fruit (id INTEGER PRIMARY KEY, name TEXT); CREATE TABLE vtl_secret (value TEXT); INSERT INTO vtl_secret VALUES ('fixture-secret');");
    const inserted = await call(db, 'run', 'INSERT INTO fruit(name) VALUES (?)', ['apple']);
    assert.deepEqual(inserted, { lastID: 1, changes: 1 });
    assert.equal((await call(db, 'get', 'SELECT name FROM fruit WHERE name = ?', 'apple')).name, 'apple');
    assert.equal((await call(db, 'all', "SELECT name FROM fruit UNION SELECT value FROM vtl_secret")).length, 2);
    const stmt = db.prepare('SELECT name FROM fruit WHERE name = $name', { $name: 'apple' });
    assert.equal((await call(stmt, 'get')).name, 'apple');
    await call(stmt, 'bind', { $name: 'pear' });
    assert.equal((await call(stmt, 'all')).length, 0);
    await call(stmt, 'reset'); await call(stmt, 'finalize');
    let count = 0;
    await new Promise((resolve, reject) => db.each('SELECT name FROM fruit', (error, row) => {
      assert.ifError(error); assert.equal(row.name, 'apple'); count++;
    }, (error, total) => { if (error) reject(error); else { assert.equal(total, 1); resolve(); } }));
    assert.equal(count, 1);
    await assert.rejects(call(db, 'get', 'SELECT FROM broken'));
    await call(db, 'close');
    assert.equal(fs.existsSync('/must/not/be/opened.db'), false);
  `);
  const events = success(result).filter(event => event.class === 'CWE-89');
  assert.ok(events.every(event => event.driver === 'sqlite3' && event.executable));
  assert.ok(events.some(event => event.api === 'Database' && event.filename === '/must/not/be/opened.db'));
  assert.ok(events.some(event => event.api === 'all' && event.query.includes('vtl_secret')));
});

test('unsupported driver APIs leave an explicit diagnostic event', () => {
  const result = run(`
    assert.throws(() => new (require('pg').Client)().cancel(), { code: 'node_driver_api_unsupported' });
    assert.throws(() => require('mysql2').createPoolCluster(), { code: 'node_driver_api_unsupported' });
  `);
  const events = success(result).filter(event => event.api === 'api_unsupported');
  assert.equal(events.length, 2);
  assert.ok(events.every(event => event.executable === false));
});

test('events are bounded by UTF-8 JSON bytes and marked when truncated', () => {
  const result = run(`
    await assert.rejects(new (require('pg').Client)().query('界\\n'.repeat(10000), ['x'.repeat(20000)]));
  `);
  const events = success(result);
  assert.ok(events.some(event => event.driver === 'pg' && event.truncated));
  for (const line of result.text.trimEnd().split('\n')) assert.ok(Buffer.byteLength(line + '\n') <= 4096);
});

test('event count and total size caps stop recording without changing exit status', () => {
  for (const query of ['x', '界'.repeat(2000)]) {
    const result = run(`
      const client = new (require('pg').Client)();
      for (let index = 0; index < 300; index++) { try { await client.query(${JSON.stringify(query)}); } catch {} }
    `);
    assert.equal(result.status, 0, result.stderr);
    assert.ok(result.events.length <= 256);
    assert.ok(Buffer.byteLength(result.text) <= 65536);
    result.events.forEach((event, index) => assert.equal(event.seq, index + 1));
    if (query === 'x') assert.equal(result.events.length, 256);
    else assert.ok(result.events.length < 256);
  }
});

test('event descriptor is hidden and ordinary fs read/close paths are protected', () => {
  const result = run(`
    assert.equal(process.env.VTL_EVENT_FD, undefined);
    assert.equal(hook.eventFd, undefined);
    for (const attempt of [
      () => fs.readSync(3, Buffer.alloc(1), 0, 1, 0),
      () => fs.read(3, Buffer.alloc(1), 0, 1, 0, () => {}),
      () => fs.readFileSync(3), () => fs.readFile(3, () => {}),
      () => fs.closeSync(3), () => fs.close(3, () => {}),
      () => fs.createReadStream(null, { fd: 3 }),
      () => fs.createWriteStream(null, { fd: 3 }),
      () => fs.openSync('/dev/fd/3', 'r'),
      () => fs.openSync('/proc/self/fd/3', 'r'),
      () => fs.promises.open('/dev/fd/3', 'r')
    ]) assert.throws(attempt, { code: 'EACCES' });
    cp.execSync('printf still-recording');
  `);
  assert.ok(success(result).some(event => event.file === 'printf still-recording'));
});

test('root misconfiguration is inert and never changes exit status', () => {
  for (const options of [
    { env: { VTL_EVENT_FD: '' } }, { env: { VTL_EVENT_FD: '1' } },
    { env: { VTL_EVENT_FD: '999999' } },
    { before: `require('node:module').registerHooks = undefined;` },
    { before: `process.env.VTL_EVENT_FD = String(require('node:fs').openSync(process.env.TEST_DIR + '/named', 'w'));` }
  ]) {
    const result = run(`fs.writeFileSync(process.env.TEST_DIR + '/marker', 'ran'); process.stdout.write('ran');`, options);
    assert.equal(result.stdout, 'ran');
    assert.deepEqual(success(result), []);
  }
});


test('hook and shims expose no diagnostic writers or leftover capabilities', () => {
  const result = run(`
    assert.equal(Object.isFrozen(hook), true);
    assert.deepEqual(Reflect.ownKeys(hook), ['configureTarget']);
    const directory = ${JSON.stringify(path.dirname(hook))};
    for (const name of ['pg', 'mysql2', 'sqlite3']) {
      const shim = require(directory + '/vtl_shim_' + name + '.cjs');
      for (const key of ['sqlEvent', 'record', 'unsupported', 'guardApi', 'takeShimCapability', 'defer']) {
        assert.equal(shim[key], undefined);
        assert.equal(hook[key], undefined);
      }
      assert.equal(shim, require(name));
    }
    assert.deepEqual(Reflect.ownKeys(require(directory + '/vtl_shim_pg.cjs')), ['Client', 'Pool']);
    assert.deepEqual(Reflect.ownKeys(require(directory + '/vtl_shim_sqlite3.cjs')),
      ['Database', 'Statement', 'OPEN_READONLY', 'OPEN_READWRITE', 'OPEN_CREATE', 'verbose']);
  `);
  assert.equal(success(result).filter(event => event.class === 'CWE-89').length, 0);
});

test('fork and Worker inherit preload and still execute; clean spawn executes too', () => {
  const markerSource = `
    const fs = require('node:fs');
    const assert = require('node:assert/strict');
    assert.equal(process.env.VTL_EVENT_FD, undefined);
    assert.equal(process.env.VTL_HOOK_ROOT, undefined);
    const hook = require(${JSON.stringify(hook)});
    assert.deepEqual(Reflect.ownKeys(hook), []);
    assert.equal(Object.isFrozen(hook), true);
    assert.equal(fs.readFileSync.name, 'readFileSync');
    fs.writeFileSync(process.env.TEST_DIR + '/' + process.env.MARKER, 'ran');
  `;
  const result = run(`
    const { Worker } = require('node:worker_threads');
    const childPath = process.env.TEST_DIR + '/child.cjs';
    const wait = child => new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('exit', code => { if (code !== 0) reject(new Error('descendant exit: ' + code)); else resolve(); });
    });
    await wait(cp.fork(childPath, [], { env: { ...process.env, MARKER: 'fork-marker' }, stdio: 'ignore' }));
    await wait(new Worker(childPath, { env: { ...process.env, MARKER: 'worker-marker' } }));
    const spawned = cp.spawnSync(process.execPath, [childPath], {
      env: { ...process.env, MARKER: 'spawn-marker' }, encoding: 'utf8'
    });
    assert.equal(spawned.status, 0, spawned.stderr);
    for (const marker of ['fork-marker', 'worker-marker', 'spawn-marker']) {
      assert.equal(fs.readFileSync(process.env.TEST_DIR + '/' + marker, 'utf8'), 'ran');
    }
  `, { files: { 'child.cjs': markerSource } });
  success(result);
});

test('Worker stays inert even when supplied root configuration', () => {
  success(run(`
    const { Worker } = require('node:worker_threads');
    await new Promise((resolve, reject) => {
      const worker = new Worker(
        'require("node:fs").writeFileSync(process.env.TEST_DIR + "/worker-marker", "ran")',
        { eval: true, env: { ...process.env, VTL_EVENT_FD: '999999', VTL_HOOK_ROOT: '1' } }
      );
      worker.on('error', reject);
      worker.on('exit', code => code === 0 ? resolve() : reject(new Error('worker exit: ' + code)));
    });
    assert.equal(fs.readFileSync(process.env.TEST_DIR + '/worker-marker', 'utf8'), 'ran');
  `));
});

test('missing configuration without root token installs nothing and never exits 70', () => {
  const result = run(`
    assert.deepEqual(Reflect.ownKeys(hook), []);
    assert.equal(fs.readFileSync, globalThis.originalRead);
    assert.equal(cp.fork, globalThis.originalFork);
    const directory = ${JSON.stringify(path.dirname(hook))};
    for (const name of ['pg', 'mysql2', 'sqlite3']) {
      const shim = require(directory + '/vtl_shim_' + name + '.cjs');
      assert.deepEqual(Reflect.ownKeys(shim), []);
      assert.equal(Object.isFrozen(shim), true);
    }
  `, {
    env: { VTL_EVENT_FD: '', VTL_HOOK_ROOT: '' },
    before: `globalThis.originalRead = require('node:fs').readFileSync; globalThis.originalFork = require('node:child_process').fork;`
  });
  assert.deepEqual(success(result), []);
});

test('Object and Array toJSON pollution cannot replace event contents', () => {
  const result = run(`
    const client = new (require('pg').Client)();
    const forge = () => ({ v: 99, seq: 900, class: 'forged', query: 'forged' });
    Object.prototype.toJSON = forge;
    Array.prototype.toJSON = forge;
    String.prototype.toJSON = forge;
    try { await client.query('SELECT vtl_secret', ['apple']); } catch {}
    delete Object.prototype.toJSON;
    delete Array.prototype.toJSON;
    delete String.prototype.toJSON;
  `);
  const events = success(result).filter(event => event.class === 'CWE-89');
  assert.equal(events.length, 1);
  assert.equal(events[0].query, 'SELECT vtl_secret');
  assert.deepEqual(events[0].params, ['apple']);
});

test('throwing Array.slice and polluted primordials cannot prevent the real fs call', () => {
  const result = run(`
    const replacements = [
      [Array.prototype, 'slice'], [Array.prototype, 'map'],
      [String.prototype, 'slice'], [String.prototype, 'startsWith'],
      [Reflect, 'apply'], [Reflect, 'get'], [Reflect, 'has'],
      [Map.prototype, 'get'], [Map.prototype, 'has'], [JSON, 'stringify']
    ];
    const originals = replacements.map(([object, key]) => object[key]);
    const client = new (require('pg').Client)();
    let content;
    let recordedError;
    try {
      for (const [object, key] of replacements) object[key] = () => { throw new Error('polluted'); };
      content = fs.readFileSync(process.env.TEST_DIR + '/safe.txt', 'utf8');
      await client.query('SELECT vtl_secret', ['apple']).catch(() => {});
    } catch (error) { recordedError = error; }
    finally {
      for (let i = 0; i < replacements.length; i++) replacements[i][0][replacements[i][1]] = originals[i];
    }
    assert.ifError(recordedError);
    assert.equal(content, 'safe');
  `, { files: { 'safe.txt': 'safe' } });
  const events = success(result);
  assert.ok(events.some(event => event.api === 'fs.readFileSync' && event.path.endsWith('/safe.txt')));
  assert.ok(events.some(event => event.query === 'SELECT vtl_secret' && event.params[0] === 'apple'));
});

test('recording does not invoke target accessors or Proxy traps before a sink', () => {
  const result = run(`
    let touched = 0;
    const params = [];
    Object.defineProperty(params, '0', { get() { touched++; throw new Error('getter'); } });
    params.push(new Proxy({}, { get() { touched++; throw new Error('proxy'); } }));
    const client = new (require('pg').Client)();
    Object.defineProperty(Object.prototype, 'value', {
      configurable: true, get() { touched++; throw new Error('inherited descriptor getter'); }
    });
    let queryResult;
    try { queryResult = client.query('SELECT $1', params); }
    finally { delete Object.prototype.value; }
    await assert.rejects(queryResult, { code: 'sql_dialect_not_executable' });
    assert.equal(touched, 0);
    let optionsReads = 0;
    cp.execFileSync(process.execPath, ['-e', ''], {
      get shell() { optionsReads++; return false; }
    });
    assert.equal(optionsReads, 1);
  `);
  success(result);
});

test('recording write failure leaves the real sink running and preserves exit status', () => {
  const result = run(`
    assert.equal(fs.readFileSync(process.env.TEST_DIR + '/safe.txt', 'utf8'), 'safe');
    process.stdout.write('sink-ran');
  `, {
    files: { 'safe.txt': 'safe' },
    before: `require('node:fs').writeSync = () => { throw new Error('injected event write failure'); };`
  });
  assert.equal(result.stdout, 'sink-ran');
  assert.equal(result.status, 0);
  assert.deepEqual(result.events, []);
});

test('existing .js directory resolves index.js instead of a sibling .ts', () => {
  success(run(`
    assert.equal(require(process.env.TEST_DIR + '/entry.cjs'), 'directory');
  `, { files: {
    'entry.cjs': "module.exports = require('./x.js');",
    'x.js/index.js': "module.exports = 'directory';",
    'x.ts': "module.exports = 'typescript';"
  } }));
});

test('unknown shim APIs remain undefined for feature detection', () => {
  const result = run(`
    const pg = require('pg');
    const mysql = require('mysql2');
    const sqlite = require('sqlite3');
    const db = new sqlite.Database('ignored');
    assert.equal(new pg.Pool().cancel, undefined);
    assert.equal(mysql.createPool().beginTransaction, undefined);
    for (const object of [pg, new pg.Client(), new pg.Pool(), mysql,
      mysql.createConnection(), mysql.createPool(), mysql.promiseDriver,
      mysql.createConnection().promise(), sqlite, db, db.prepare('SELECT 1')]) {
      assert.equal(object.optionalHook, undefined);
      if (object.optionalHook) object.optionalHook();
    }
    assert.throws(() => db.loadExtension('ignored'), { code: 'node_driver_api_unsupported' });
    assert.throws(() => mysql.createConnection().beginTransaction(), { code: 'node_driver_api_unsupported' });
    db.close();
  `);
  const events = success(result).filter(event => event.api === 'api_unsupported');
  assert.deepEqual(events.map(event => event.requested_api), ['loadExtension', 'beginTransaction']);
});


test('cache eviction and Module._load interposition cannot reacquire initialization or writers', () => {
  const result = run(`
    const Module = require('node:module');
    const hookPath = ${JSON.stringify(hook)};
    const originalLoad = Module._load;
    const observed = [];
    const forbidden = ['takeShimCapability', 'record', 'sqlEvent', 'guardApi', 'unsupported', 'defer'];
    const inspect = value => {
      if (value && (typeof value === 'object' || typeof value === 'function')) {
        for (const key of forbidden) assert.equal(value[key], undefined, key);
      }
    };
    const descriptor = Object.getOwnPropertyDescriptor(process, '__vettalon_node_hook_initialized__');
    assert.equal(typeof descriptor.value, 'symbol');
    assert.equal(Symbol.keyFor(descriptor.value), undefined);
    assert.equal(descriptor.writable, false);
    assert.equal(descriptor.configurable, false);
    assert.equal(descriptor.enumerable, false);
    const target = process.env.TEST_DIR + '/target.cjs';
    hook.configureTarget({ target_url: require('node:url').pathToFileURL(target).href,
      target_file_sha256: require('node:crypto').createHash('sha256').update(fs.readFileSync(target)).digest('hex') });
    const channel = process.env.TEST_DIR + '/new-events';
    const fd = fs.openSync(channel, 'w+');
    fs.unlinkSync(channel);
    process.env.VTL_EVENT_FD = String(fd);
    process.env.VTL_HOOK_ROOT = '1';
    for (const name of ['pg', 'mysql2', 'sqlite3']) {
      delete require.cache[${JSON.stringify(path.dirname(hook))} + '/vtl_shim_' + name + '.cjs'];
    }
    delete require.cache[hookPath];
    Module._load = function(...args) {
      inspect(require.cache[hookPath]?.exports);
      const value = Reflect.apply(originalLoad, this, args);
      inspect(require.cache[hookPath]?.exports);
      if (args[0] === hookPath || String(args[0]).includes('vtl_shim_')) inspect(value);
      observed.push(args[0]);
      return value;
    };
    let reloaded;
    try { reloaded = require(hookPath); }
    finally { Module._load = originalLoad; }
    assert.ok(observed.includes(hookPath));
    assert.deepEqual(Reflect.ownKeys(reloaded), ['configureTarget']);
    assert.equal(Object.isFrozen(reloaded), true);
    assert.throws(() => reloaded.configureTarget({}), /already initialized/);
    assert.throws(() => hook.configureTarget({}), /invalid target identity/);
    assert.equal(fs.readFileSync(fd, 'utf8'), '');
    fs.closeSync(fd);
    for (const name of ['pg', 'mysql2', 'sqlite3']) {
      const shim = require(${JSON.stringify(path.dirname(hook))} + '/vtl_shim_' + name + '.cjs');
      assert.deepEqual(Reflect.ownKeys(shim), []);
    }
  `, { files: { 'target.cjs': 'exports.answer = 42;' } });
  success(result);
});

test('even an initially inert hook cannot be reactivated by cache eviction', () => {
  const result = run(`
    const hookPath = ${JSON.stringify(hook)};
    const channel = process.env.TEST_DIR + '/new-events';
    const fd = fs.openSync(channel, 'w+');
    fs.unlinkSync(channel);
    process.env.VTL_EVENT_FD = String(fd);
    delete require.cache[hookPath];
    assert.throws(() => require(hookPath).configureTarget({}), /already initialized/);
    assert.equal(fs.readFileSync(fd, 'utf8'), '');
    fs.closeSync(fd);
  `, { env: { VTL_EVENT_FD: '' } });
  assert.deepEqual(success(result), []);
});

test('polluted TypedArray length cannot suppress writes or create sequence gaps', () => {
  const result = run(`
    const client = new (require('pg').Client)();
    const prototype = Object.getPrototypeOf(Uint8Array.prototype);
    const descriptor = Object.getOwnPropertyDescriptor(prototype, 'length');
    let touched = 0;
    Object.defineProperty(prototype, 'length', { configurable: true, get() { touched++; return 0; } });
    try { await client.query('during-length-pollution').catch(() => {}); }
    finally { Object.defineProperty(prototype, 'length', descriptor); }
    await client.query('after-length-pollution').catch(() => {});
    assert.equal(touched, 0);
  `);
  const events = success(result).filter(event => event.class === 'CWE-89');
  assert.deepEqual(events.map(event => event.query), ['during-length-pollution', 'after-length-pollution']);
  assert.equal(events[1].seq, events[0].seq + 1);
});

test('dangling .js symlink prevents .ts fallback for both CJS and ESM', () => {
  success(run(`
    fs.symlinkSync('missing-target', process.env.TEST_DIR + '/x.js');
    assert.throws(() => require(process.env.TEST_DIR + '/entry.cjs'), { code: 'MODULE_NOT_FOUND' });
    await assert.rejects(import(require('node:url').pathToFileURL(process.env.TEST_DIR + '/entry.mjs')),
      { code: 'ERR_MODULE_NOT_FOUND' });
  `, { files: {
    'entry.cjs': "module.exports = require('./x.js');",
    'entry.mjs': "export { value } from './x.js';",
    'x.ts': 'export const value: number = 42;'
  } }));
});

test('hostile child env and preloads are stripped across process APIs without child events', () => {
  const child = `
    const assert = require('node:assert/strict');
    const fs = require('node:fs');
    assert.deepEqual(Object.keys(process.env).filter(key => key.startsWith('VTL_')), []);
    assert.equal(process.env.KEEP_ME, 'kept');
    assert.equal(globalThis.otherPreload, true);
    assert.ok(!process.execArgv.some(arg => arg.includes('vtl_hook.cjs')));
    assert.ok(!process.env.NODE_OPTIONS.includes('vtl_hook.cjs'));
    assert.deepEqual(Reflect.ownKeys(require(${JSON.stringify(hook)})), []);
    fs.readFileSync(process.env.TEST_DIR + '/safe.txt');
    fs.writeFileSync(process.env.TEST_DIR + '/' + process.env.MARKER, 'ran');
  `;
  const result = run(`
    const hookPath = ${JSON.stringify(hook)};
    const childPath = process.env.TEST_DIR + '/child.cjs';
    const otherPath = process.env.TEST_DIR + '/other.cjs';
    const channel = process.env.TEST_DIR + '/descendant-events';
    const fd = fs.openSync(channel, 'w+');
    fs.unlinkSync(channel);
    const wait = child => new Promise((resolve, reject) => {
      child.on('error', reject);
      child.on('exit', code => code === 0 ? resolve() : reject(new Error('child exit ' + code)));
    });
    const modes = ['fork', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'exec', 'execSync'];
    for (const mode of modes) {
      const env = { ...process.env, VTL_HOOK_ROOT: '1', VTL_EVENT_FD: '4',
        VTL_BASE: '/forged', VTL_DB: '/forged', VTL_EXTRA: 'forged',
        VTL_HOOK_TOKEN: 'forged', KEEP_ME: 'kept', MARKER: mode,
        NODE_OPTIONS: '--require="' + hookPath + '" -r "' + otherPath + '" --require "' + hookPath + '" -r' + hookPath };
      const execArgv = ['--require', hookPath, '-r', otherPath, '--require=' + hookPath, '-r' + hookPath];
      const options = { env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe', 'ignore', fd] };
      if (mode === 'fork') await wait(cp.fork(childPath, [], { ...options, stdio: [...options.stdio, 'ipc'], execArgv }));
      else if (mode === 'spawn') await wait(cp.spawn(process.execPath, [...execArgv, childPath], options));
      else if (mode === 'spawnSync') {
        const child = cp.spawnSync(process.execPath, [...execArgv, childPath], options);
        assert.equal(child.status, 0, child.stderr);
      } else if (mode === 'execFile') {
        await new Promise((resolve, reject) => cp.execFile(process.execPath, [...execArgv, childPath], options,
          error => error ? reject(error) : resolve()));
      } else if (mode === 'execFileSync') cp.execFileSync(process.execPath, [...execArgv, childPath], options);
      else if (mode === 'exec') {
        await new Promise((resolve, reject) => cp.exec('"' + process.execPath + '" "' + childPath + '"', options,
          error => error ? reject(error) : resolve()));
      } else cp.execSync('"' + process.execPath + '" "' + childPath + '"', options);
      assert.equal(env.VTL_EVENT_FD, '4');
      assert.ok(env.NODE_OPTIONS.includes(hookPath));
      assert.equal(execArgv[1], hookPath);
      assert.equal(fs.readFileSync(process.env.TEST_DIR + '/' + mode, 'utf8'), 'ran');
    }
    // Default env/execArgv are also sanitized when the target mutates them.
    process.env.VTL_EVENT_FD = '4';
    process.env.VTL_HOOK_ROOT = '1';
    process.env.KEEP_ME = 'kept';
    process.env.MARKER = 'default-fork';
    process.env.NODE_OPTIONS = '--require="' + hookPath + '" -r "' + otherPath + '"';
    process.execArgv = ['--require', hookPath];
    await wait(cp.fork(childPath));
    assert.equal(fs.readFileSync(process.env.TEST_DIR + '/default-fork', 'utf8'), 'ran');
    assert.equal(fs.readFileSync(fd, 'utf8'), '');
    fs.closeSync(fd);
  `, { files: { 'child.cjs': child, 'other.cjs': 'globalThis.otherPreload = true;', 'safe.txt': 'safe' } });
  success(result);
});
