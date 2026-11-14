'use strict';

// Untrusted, in-process reach diagnostics only. The protected runner alone
// evaluates effects; target code can forge, suppress or replace these events.
const initializationKey = '__vettalon_node_net_hook_initialized__';
if (process[initializationKey] !== undefined || Object.getOwnPropertyDescriptor(process, initializationKey)) {
  module.exports = Object.freeze(Object.create(null));
  return;
}
Object.defineProperty(process, initializationKey, { value: Symbol('vtl net hook initialized') });

const fs = require('node:fs');
const modules = require('node:module');
const http = require('node:http');
const https = require('node:https');
const isProxy = require('node:util').types.isProxy;
const apply = Reflect.apply;
const create = Object.create;
const getDescriptor = Object.getOwnPropertyDescriptor;
const getDescriptors = Object.getOwnPropertyDescriptors;
const defineProperties = Object.defineProperties;
const hasOwn = Object.hasOwn;
const stringify = JSON.stringify;
const numberString = String;
const NativeError = Error;
const NativeURL = URL;
const urlHref = Function.prototype.call.bind(getDescriptor(URL.prototype, 'href').get);
const requestUrl = typeof Request === 'function'
  ? Function.prototype.call.bind(getDescriptor(Request.prototype, 'url').get) : null;
const requestMethod = typeof Request === 'function'
  ? Function.prototype.call.bind(getDescriptor(Request.prototype, 'method').get) : null;
const startsWith = Function.prototype.call.bind(String.prototype.startsWith);
const includes = Function.prototype.call.bind(String.prototype.includes);
const byteLength = Buffer.byteLength;
const bufferFrom = Buffer.from;
const typedArrayLength = Function.prototype.call.bind(
  getDescriptor(Object.getPrototypeOf(Uint8Array.prototype), 'length').get);
const writeSync = fs.writeSync;
const fstatSync = fs.fstatSync;
const value = process.env.VTL_NET_EVENT_FD;
delete process.env.VTL_NET_EVENT_FD;
module.exports = Object.freeze(create(null));
// The base hook also strips VTL_* from explicit child environments. Consumed
// configuration cannot be inherited; workers are inert even with explicit env.
if (!require('node:worker_threads').isMainThread || !value) return;
let eventFd;
try {
  if (!/^[0-9]+$/.test(value)) return;
  eventFd = Number(value);
  const stat = fstatSync(eventFd);
  if (eventFd < 3 || !Number.isSafeInteger(eventFd) || !stat.isFile() ||
      stat.nlink !== 0 || stat.size !== 0) return;
} catch { return; }

let sequence = 0;
let totalBytes = 0;
let recordingFailed = false;
function ownData(value, key) {
  if (value === null || (typeof value !== 'object' && typeof value !== 'function') || isProxy(value)) return undefined;
  const descriptor = getDescriptor(value, key);
  return descriptor && hasOwn(descriptor, 'value') ? descriptor.value : undefined;
}
function text(value, fallback) {
  if (value === undefined || value === null) return fallback;
  if (typeof value === 'string') return value;
  throw new NativeError('uninspected network option');
}
function optionsUrl(options, protocol) {
  protocol = text(ownData(options, 'protocol'), protocol);
  const hostname = ownData(options, 'hostname');
  let host = text(hostname, text(ownData(options, 'host'), 'localhost'));
  if (hostname !== undefined && includes(host, ':') && !startsWith(host, '[')) host = '[' + host + ']';
  const port = ownData(options, 'port');
  if (port !== undefined && port !== null && port !== '') {
    if (typeof port !== 'string' && typeof port !== 'number') throw new NativeError('uninspected port');
    host += ':' + numberString(port);
  }
  return protocol + '//' + host + text(ownData(options, 'path'), '/');
}
function record(api, args, protocol) {
  if (recordingFailed) return;
  try {
    const input = args[0];
    let url;
    let method = 'GET';
    let options = args[1];
    if (typeof input === 'string') url = input;
    else {
      if (input === null || typeof input !== 'object' || isProxy(input)) throw new NativeError('uninspected URL');
      try { url = urlHref(input); } catch {
        if (api === 'fetch') {
          if (!requestUrl) throw new NativeError('uninspected Request');
          url = requestUrl(input);
          method = requestMethod(input);
        } else {
          options = input;
          url = optionsUrl(input, protocol);
        }
      }
    }
    method = text(ownData(options, 'method'), method);
    let href = null;
    try { href = urlHref(new NativeURL(url)); } catch {}
    if (byteLength(url) > 2048 || (href !== null && byteLength(href) > 2048) || byteLength(method) > 16) {
      throw new NativeError('network field limit');
    }
    const event = create(null);
    event.v = 1;
    event.seq = sequence + 1;
    event.class = 'CWE-918';
    event.api = api;
    event.truncated = false;
    event.url = url;
    event.href = href;
    event.method = method;
    // Only primitive strings reach JSON.stringify: no target toJSON or
    // prototype accessors are invoked by the diagnostic serializer.
    const line = '{"v":1,"seq":' + numberString(event.seq) + ',"class":"CWE-918","api":' + stringify(event.api) +
      ',"truncated":false,"url":' + stringify(event.url) + ',"href":' + (event.href === null ? 'null' : stringify(event.href)) +
      ',"method":' + stringify(event.method) + '}\n';
    const bytes = bufferFrom(line);
    const length = typedArrayLength(bytes);
    if (length > 4096 || sequence >= 256 || totalBytes + length > 65536) throw new NativeError('network event limit');
    let offset = 0;
    while (offset < length) {
      const written = writeSync(eventFd, bytes, offset, length - offset);
      if (written <= 0) throw new NativeError('short network event write');
      offset += written;
      totalBytes += written;
    }
    sequence++;
  } catch {
    recordingFailed = true;
    // Mark incomplete diagnostics once, within the same event and byte caps.
    try {
      const sentinel = bufferFrom('{"v":1,"seq":' + numberString(sequence + 1) + ',"truncated":true}\n');
      const length = typedArrayLength(sentinel);
      if (sequence >= 256 || totalBytes + length > 65536) return;
      let offset = 0;
      while (offset < length) {
        const written = writeSync(eventFd, sentinel, offset, length - offset);
        if (written <= 0) return;
        offset += written;
        totalBytes += written;
      }
      sequence++;
    } catch {}
  }
}
function wrap(original, api, protocol) {
  function wrapped(...args) {
    record(api, args, protocol);
    return apply(original, this, args);
  }
  defineProperties(wrapped, getDescriptors(original));
  return wrapped;
}
http.request = wrap(http.request, 'http.request', 'http:');
http.get = wrap(http.get, 'http.get', 'http:');
https.request = wrap(https.request, 'https.request', 'https:');
https.get = wrap(https.get, 'https.get', 'https:');
if (typeof globalThis.fetch === 'function') globalThis.fetch = wrap(globalThis.fetch, 'fetch');
modules.syncBuiltinESMExports();
