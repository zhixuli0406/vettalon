import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const hook = fileURLToPath(new URL('../../../crates/vettalon/assets/node/vtl_hook_net.cjs', import.meta.url));
// Fake only the underlying transports, before loading the real hook. These
// contracts never need DNS, listening sockets or external network access.
const before = `
const http = require('node:http');
const https = require('node:https');
globalThis.calls = [];
globalThis.originals = [];
for (const [mod, prefix] of [[http, 'http'], [https, 'https']]) {
  for (const name of ['request', 'get']) {
    const fn = function transport(input, options, callback) {
      calls.push({ api: prefix + '.' + name, receiver: this, args: [...arguments] });
      return 'transport result';
    };
    fn[Symbol.for('test property')] = 42;
    mod[name] = fn;
    originals.push([mod, name, fn]);
  }
}
const fetch = function fetch(input, options) {
  calls.push({ api: 'fetch', receiver: this, args: [...arguments] });
  return Promise.resolve('fetch result');
};
globalThis.fetch = fetch;
originals.push([globalThis, 'fetch', fetch]);
require('node:module').syncBuiltinESMExports();
`;
const prefix = `
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const http = require('node:http');
const https = require('node:https');
const hookPath = ${JSON.stringify(hook)};
`;
function run(source, options = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'vtl-net-test-'));
  const eventPath = path.join(directory, 'events');
  fs.writeFileSync(eventPath, options.initial || '', { mode: 0o600, flag: 'wx' });
  const writer = fs.openSync(eventPath, fs.constants.O_WRONLY | fs.constants.O_APPEND);
  const reader = fs.openSync(eventPath, fs.constants.O_RDONLY);
  if (!options.linked) fs.unlinkSync(eventPath);
  try {
    const env = { ...process.env, VTL_NET_EVENT_FD: '3', ...options.env };
    delete env.NODE_OPTIONS;
    delete env.NODE_PATH;
    const setup = path.join(directory, 'before.cjs');
    const main = path.join(directory, 'main.mjs');
    fs.writeFileSync(setup, before + (options.before || ''));
    fs.writeFileSync(main, prefix + source);
    const result = spawnSync(process.execPath, ['--require', setup, '--require', hook, main], {
      env, stdio: ['ignore', 'pipe', 'pipe', writer], encoding: 'utf8', timeout: 15000,
    });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
    const text = fs.readFileSync(reader, 'utf8');
    const events = text.trim() ? text.trimEnd().split('\n').map(line => JSON.parse(line)) : [];
    events.forEach((event, index) => {
      if (event.truncated === true) {
        assert.deepEqual(event, { v: 1, seq: index + 1, truncated: true });
        assert.equal(index, events.length - 1);
        return;
      }
      assert.deepEqual(Object.keys(event).sort(), ['v', 'seq', 'class', 'api', 'truncated', 'url', 'href', 'method'].sort());
      assert.equal(event.v, 1);
      assert.equal(event.seq, index + 1);
      assert.equal(event.class, 'CWE-918');
      assert.equal(event.truncated, false);
      assert.ok(Buffer.byteLength(event.url) <= 2048);
      assert.ok(event.href === null || Buffer.byteLength(event.href) <= 2048);
      assert.ok(event.method === null || Buffer.byteLength(event.method) <= 16);
    });
    assert.ok(Buffer.byteLength(text) <= 65536);
    for (const line of text.trimEnd().split('\n')) assert.ok(Buffer.byteLength(line + '\n') <= 4096);
    return { events, text };
  } finally {
    fs.closeSync(writer);
    fs.closeSync(reader);
    fs.rmSync(directory, { recursive: true });
  }
}

test('net wrappers preserve descriptors, receiver, arguments and return values; ESM sees wrappers', () => {
  const { events } = run(`
    import { get } from 'node:http';
    import { request } from 'node:https';
    assert.equal(get, http.get);
    assert.equal(request, https.request);
    for (const [mod, name, original] of originals) {
      assert.notEqual(mod[name], original);
      assert.deepEqual(Object.getOwnPropertyDescriptors(mod[name]), Object.getOwnPropertyDescriptors(original));
    }
    const receiver = {};
    const options = { method: 'POST' };
    const callback = () => {};
    assert.equal(get.call(receiver, 'http://example.com/vtl_ssrf', options, callback), 'transport result');
    assert.equal(calls[0].receiver, receiver);
    assert.deepEqual(calls[0].args, ['http://example.com/vtl_ssrf', options, callback]);
    http.request(new URL('http://example.com/a'));
    request('https://example.com/b');
    https.get('https://example.com/c');
    assert.equal(await fetch('https://example.com/d'), 'fetch result');
    assert.equal(calls.length, 5);
  `);
  assert.deepEqual(events.map(e => e.api), ['http.get', 'http.request', 'https.request', 'https.get', 'fetch']);
  assert.equal(events[0].method, 'POST');
});

test('fetch supports strings, native URLs and Requests with method overrides', () => {
  const { events } = run(`
    await fetch('HTTP://EXAMPLE.COM:80/vtl_ssrf');
    await fetch(new URL('https://example.com/a'), { method: 'PATCH' });
    const request = new Request('https://example.com/b', { method: 'POST' });
    await fetch(request);
    await fetch(request, { method: 'PUT' });
  `);
  assert.equal(events[0].url, 'HTTP://EXAMPLE.COM:80/vtl_ssrf');
  assert.equal(events[0].href, 'http://example.com/vtl_ssrf');
  assert.deepEqual(events.map(e => e.method), ['GET', 'PATCH', 'POST', 'PUT']);
});

test('http options rebuild URLs with protocol, hostname/host, port and path', () => {
  const { events } = run(`
    http.request({ hostname: '127.0.0.1', port: 8080, path: '/vtl_ssrf?q=1', method: 'POST' });
    https.get({ host: 'example.com', path: '/a' });
    http.get({ hostname: '::1', port: '80', path: '/b' });
    http.request({ protocol: 'https:', hostname: 'example.com' });
    http.get({ host: 'localhost:8080' });
    http.get({});
    http.get('not a URL');
  `);
  assert.deepEqual(events.map(e => e.url), [
    'http://127.0.0.1:8080/vtl_ssrf?q=1', 'https://example.com/a', 'http://[::1]:80/b',
    'https://example.com/', 'http://localhost:8080/', 'http://localhost/', 'not a URL',
  ]);
  assert.equal(events.at(-1).href, null);
});

test('field byte caps emit a sentinel and stop permanently without skipping original calls', () => {
  for (const call of [
    `http.get('x'.repeat(2049))`,
    `http.get('é'.repeat(1025))`,
    `http.get('http://example.com/' + 'é'.repeat(400))`,
    `http.get('http://example.com/', { method: 'A'.repeat(17) })`,
  ]) {
    const { events } = run(`http.get('http://example.com/first'); ${call}; http.get('http://example.com/last'); assert.equal(calls.length, 3);`);
    assert.equal(events.length, 2);
    assert.equal(events[1].truncated, true);
  }
  const { events } = run(`http.get('x'.repeat(2048), { method: 'A'.repeat(16) });`);
  assert.equal(events.length, 1);
});

test('line, total-byte and event-count caps stop permanently', () => {
  assert.deepEqual(run(`http.get('http://example.com/' + 'a'.repeat(2000)); http.get('http://example.com/');`).events, [{ v: 1, seq: 1, truncated: true }]);
  const count = run(`for (let i = 0; i < 300; i++) http.get('http://example.com/'); assert.equal(calls.length, 300);`);
  assert.equal(count.events.length, 256);
  const total = run(`for (let i = 0; i < 100; i++) http.get('http://example.com/' + 'a'.repeat(1000)); http.get('x'); assert.equal(calls.length, 101);`);
  assert.ok(total.events.length > 0 && total.events.length < 100);
  assert.ok(Buffer.byteLength(total.text) > 65536 - 4096);
});

test('missing, invalid, linked and nonempty event fds leave all functions inert', () => {
  const inert = `for (const [mod, name, original] of originals) assert.equal(mod[name], original);
    assert.equal(process.env.VTL_NET_EVENT_FD, undefined);`;
  for (const value of ['', 'bad', '1', '-1', '999999', '3.0']) assert.equal(run(inert, { env: { VTL_NET_EVENT_FD: value } }).events.length, 0);
  assert.equal(run(inert, { linked: true }).events.length, 0);
  // Whitespace keeps the test channel parseable while checking nonzero size.
  assert.equal(run(inert, { initial: ' ' }).events.length, 0);
});

test('workers and descendants are inert and do not inherit the consumed fd setting', () => {
  const { events } = run(`
    const { Worker } = require('node:worker_threads');
    const worker = new Worker(\`
      const assert = require('node:assert/strict');
      const http = require('node:http');
      assert.equal(http.get, originals[1][2]);
      assert.equal(process.env.VTL_NET_EVENT_FD, undefined);
    \`, { eval: true, env: { ...process.env, VTL_NET_EVENT_FD: '3' } });
    await new Promise((resolve, reject) => { worker.on('error', reject); worker.on('exit', code => code ? reject(new Error('worker failed')) : resolve()); });
    const child = require('node:child_process').spawnSync(process.execPath,
      [...process.execArgv, '-e', "require('node:assert/strict').equal(require('node:http').get, originals[1][2])"],
      { encoding: 'utf8' });
    assert.equal(child.status, 0, child.stderr);
    http.get('http://example.com/root');
  `);
  assert.equal(events.length, 1);
});

test('cache eviction never reinitializes active or initially inert hooks; writer is not exported', () => {
  for (const env of [{}, { VTL_NET_EVENT_FD: '' }]) {
    const { events } = run(`
      const original = http.get;
      const exported = require(hookPath);
      assert.equal(Object.getPrototypeOf(exported), null);
      assert.ok(Object.isFrozen(exported));
      assert.deepEqual(Reflect.ownKeys(exported), []);
      delete require.cache[hookPath];
      process.env.VTL_NET_EVENT_FD = '3';
      require(hookPath);
      assert.equal(http.get, original);
      http.get('http://example.com/');
    `, { env });
    assert.equal(events.length, env.VTL_NET_EVENT_FD === '' ? 0 : 1);
  }
});

test('captured primordials ignore poisoned serializers, getters, URL methods and Buffer length', () => {
  const { events } = run(`
    const url = new URL('http://example.com/vtl_ssrf');
    Object.defineProperty(url, 'href', { get() { throw new Error('own href'); } });
    Object.defineProperty(URL.prototype, 'href', { get() { throw new Error('URL href'); } });
    Object.defineProperty(Buffer.prototype, 'length', { get() { throw new Error('buffer length'); } });
    JSON.stringify = () => { throw new Error('stringify'); };
    Object.prototype.toJSON = () => { throw new Error('toJSON'); };
    Reflect.apply = () => { throw new Error('apply'); };
    Object.getOwnPropertyDescriptor = () => { throw new Error('descriptor'); };
    http.get(url);
  `);
  assert.equal(events.length, 1);
  assert.equal(events[0].url, 'http://example.com/vtl_ssrf');
});

test('diagnostics never invoke option accessors, proxies or custom conversions', () => {
  const { events } = run(`
    const options = { hostname: 'example.com', get method() { throw new Error('getter'); } };
    http.get(options);
    http.get(new Proxy({}, { get() { throw new Error('proxy'); }, getOwnPropertyDescriptor() { throw new Error('proxy'); } }));
    http.get('http://example.com/after');
    assert.equal(calls.length, 3);
  `);
  assert.equal(events.length, 2);
  assert.equal(events[1].truncated, true);
});

test('uninspectable options end the event file with one truncation sentinel', () => {
  const { events, text } = run(`
    http.get('http://example.com/first');
    http.get({ host: {} });
    http.get({ host: {} });
    http.get('http://example.com/after');
    assert.equal(calls.length, 4);
  `);
  assert.equal(events.length, 2);
  assert.deepEqual(events[1], { v: 1, seq: 2, truncated: true });
  assert.ok(text.endsWith('{"v":1,"seq":2,"truncated":true}\n'));
});

test('write failure disables recording without changing the transport result', () => {
  assert.equal(run(`
    assert.equal(http.get('http://example.com/'), 'transport result');
    assert.equal(http.get('http://example.com/again'), 'transport result');
    assert.equal(globalThis.writes, 2);
  `, { before: `globalThis.writes = 0; require('node:fs').writeSync = () => { writes++; throw new Error('write failed'); };` }).events.length, 0);
});
