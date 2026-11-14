'use strict';

const { EventEmitter } = require('node:events');
// The hook supplies this argument through private compileFunction evaluation.
// Ordinary CommonJS loading has only five arguments and stays inert.
const shimCapability = arguments[5];
if (!shimCapability) {
  module.exports = Object.freeze(Object.create(null));
  return;
}
const { sqlEvent, guardApi, unsupported, dbPath, defer } = shimCapability;
// Load lazily: preloading pg/mysql2 must not require SQLite support.
let DatabaseSync;

function argumentsFor(args) {
  const values = [...args];
  const callback = typeof values.at(-1) === 'function' ? values.pop() : undefined;
  const params = values.length === 1 && Array.isArray(values[0]) ? values[0] : values;
  return { callback, params };
}
function finish(receiver, callback, error, ...result) {
  if (callback) defer(() => callback.call(receiver, error, ...result));
  else if (error) defer(() => receiver.emit('error', error));
}
function bindings(params) {
  // sqlite3 accepts arrays and named dictionaries. Numeric dictionaries refer
  // to positional slots; do not silently translate ambiguous sparse bindings.
  if (params.length === 1 && params[0] && typeof params[0] === 'object' &&
      !Buffer.isBuffer(params[0]) && !ArrayBuffer.isView(params[0])) {
    const entries = Object.entries(params[0]);
    if (entries.some(([key]) => /^\d+$/.test(key))) unsupported('sqlite3', 'numeric_parameter_dictionary');
  }
  return params;
}

class Statement extends EventEmitter {
  constructor(database, query, params = [], callback) {
    super();
    this.database = database;
    this.query = query;
    this.params = params;
    this.statement = null;
    this.error = null;
    this.finalized = false;
    this.lastID = 0;
    this.changes = 0;
    sqlEvent('sqlite3', 'prepare', query, params, true);
    try { this.statement = database.connection.prepare(query); }
    catch (error) { this.error = error; }
    finish(this, callback, this.error);
    return guardApi(this, 'sqlite3');
  }
  _perform(api, args) {
    const { callback, params } = argumentsFor(args);
    const actual = params.length ? params : this.params;
    sqlEvent('sqlite3', api, this.query, actual, true);
    let error = null;
    let result;
    try {
      if (this.error) throw this.error;
      if (this.finalized) throw new Error('SQLITE_MISUSE: statement finalized');
      result = this.statement[api](...bindings(actual));
      if (api === 'run') {
        this.lastID = Number(result.lastInsertRowid);
        this.changes = Number(result.changes);
      }
    } catch (failure) { error = failure; }
    finish(this, callback, error, ...(api === 'run' ? [] : [result]));
    return this;
  }
  all(...args) { return this._perform('all', args); }
  get(...args) { return this._perform('get', args); }
  run(...args) { return this._perform('run', args); }
  each(...args) {
    const values = [...args];
    let complete;
    if (typeof values.at(-1) === 'function' && typeof values.at(-2) === 'function') complete = values.pop();
    const { callback, params } = argumentsFor(values);
    if (!callback) return unsupported('sqlite3', 'each_without_callback');
    const actual = params.length ? params : this.params;
    sqlEvent('sqlite3', 'each', this.query, actual, true);
    let rows;
    try {
      if (this.error) throw this.error;
      if (this.finalized) throw new Error('SQLITE_MISUSE: statement finalized');
      rows = this.statement.all(...bindings(actual));
    } catch (error) {
      finish(this, complete || callback, error);
      return this;
    }
    defer(() => {
      for (const row of rows) callback(null, row);
      if (complete) complete(null, rows.length);
    });
    return this;
  }
  bind(...args) {
    const { callback, params } = argumentsFor(args);
    this.params = params;
    finish(this, callback, this.error);
    return this;
  }
  reset(callback) { finish(this, callback, this.error); return this; }
  finalize(callback) {
    this.finalized = true;
    this.statement = null;
    finish(this, callback, null);
    return this.database;
  }
}

class Database extends EventEmitter {
  constructor(filename, mode, callback) {
    super();
    if (typeof mode === 'function') callback = mode;
    this.connection = null;
    this.error = null;
    // The caller's filename is diagnostic only. Never open an arbitrary DB in
    // place of the runner's seeded fixture, nor allow loading native extensions.
    sqlEvent('sqlite3', 'Database', '', [], true, { filename });
    try {
      if (!dbPath) throw new Error('node_hook_failed: VTL_DB missing');
      DatabaseSync ||= require('node:sqlite').DatabaseSync;
      this.connection = new DatabaseSync(dbPath, { allowExtension: false });
    } catch (error) { this.error = error; }
    finish(this, callback, this.error);
    return guardApi(this, 'sqlite3', ['configure', 'loadExtension', 'interrupt']);
  }
  prepare(query, ...args) {
    const { callback, params } = argumentsFor(args);
    return new Statement(this, query, params, callback);
  }
  _perform(api, query, args) {
    // A temporary Statement provides sqlite3's callback `this.lastID/changes`.
    // Preparation errors belong to the operation callback, not an extra event.
    const statement = new Statement(this, query, [], () => {});
    statement.on('error', error => this.emit('error', error));
    statement[api](...args);
    return this;
  }
  all(query, ...args) { return this._perform('all', query, args); }
  get(query, ...args) { return this._perform('get', query, args); }
  run(query, ...args) { return this._perform('run', query, args); }
  each(query, ...args) { return this._perform('each', query, args); }
  exec(query, callback) {
    sqlEvent('sqlite3', 'exec', query, [], true);
    let error = this.error;
    try { if (!error) this.connection.exec(query); } catch (failure) { error = failure; }
    finish(this, callback, error);
    return this;
  }
  serialize(callback) { if (callback) callback(); return this; }
  parallelize(callback) { if (callback) callback(); return this; }
  close(callback) {
    let error = null;
    try { this.connection.close(); } catch (failure) { error = failure; }
    finish(this, callback, error);
    return this;
  }
}
exports.Database = Database;
exports.Statement = Statement;
exports.OPEN_READONLY = 1;
exports.OPEN_READWRITE = 2;
exports.OPEN_CREATE = 4;
exports.verbose = () => module.exports;
module.exports = guardApi(module.exports, 'sqlite3');
