'use strict';

const { EventEmitter } = require('node:events');
// The hook supplies this argument through private compileFunction evaluation.
// Ordinary CommonJS loading has only five arguments and stays inert.
const shimCapability = arguments[5];
if (!shimCapability) {
  module.exports = Object.freeze(Object.create(null));
  return;
}
const { sqlEvent, guardApi, defer } = shimCapability;

class Connection extends EventEmitter {
  constructor(promiseMode = false) {
    super();
    this.promiseMode = promiseMode;
    return guardApi(this, 'mysql2', new.target === Connection
      ? ['beginTransaction', 'commit', 'rollback', 'changeUser', 'ping', 'prepare', 'unprepare'] : []);
  }
  connect(callback) {
    if (callback) { defer(() => callback(null)); return; }
    if (this.promiseMode) return Promise.resolve();
  }
  query(query, values, callback) { return this._query('query', query, values, callback); }
  execute(query, values, callback) { return this._query('execute', query, values, callback); }
  _query(api, query, values, callback) {
    if (typeof values === 'function') callback = values;
    const text = typeof query === 'string' ? query : query?.sql;
    const params = Array.isArray(values) ? values : (query?.values || []);
    // Dialect semantics must never be approximated using SQLite.
    sqlEvent('mysql2', api, text, params, false);
    const error = Object.assign(new Error('sql_dialect_not_executable: mysql2'), { code: 'sql_dialect_not_executable' });
    if (this.promiseMode) return Promise.reject(error);
    if (callback) { defer(() => callback(error)); return; }
    const command = new EventEmitter();
    defer(() => command.emit('error', error));
    return command;
  }
  promise() { return new Connection(true); }
  end(callback) {
    if (callback) { defer(() => callback(null)); return; }
    if (this.promiseMode) return Promise.resolve();
  }
  destroy() {}
  release() {}
}
class Pool extends Connection {
  getConnection(callback) {
    const connection = new Connection(this.promiseMode);
    if (this.promiseMode) return Promise.resolve(connection);
    defer(() => callback(null, connection));
  }
  promise() { return new Pool(true); }
}
exports.createConnection = () => new Connection();
exports.createPool = () => new Pool();
exports.promiseDriver = guardApi({
  createConnection: async () => new Connection(true),
  createPool: () => new Pool(true)
}, 'mysql2');
module.exports = guardApi(module.exports, 'mysql2', ['createPoolCluster', 'createServer', 'escape', 'escapeId', 'format', 'raw']);
