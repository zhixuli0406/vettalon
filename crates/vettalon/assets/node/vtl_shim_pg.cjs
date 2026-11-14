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

class Client extends EventEmitter {
  constructor() {
    super();
    return guardApi(this, 'pg', new.target === Client ? ['cancel'] : []);
  }
  connect(callback) {
    // Connection setup is inert, so ordinary code can reach query without a
    // server. No successful query/result is ever fabricated.
    if (callback) { defer(() => callback(null)); return; }
    return Promise.resolve();
  }
  query(query, values, callback) {
    if (typeof values === 'function') callback = values;
    const text = typeof query === 'string' ? query : query?.text;
    const params = Array.isArray(values) ? values : (query?.values || []);
    sqlEvent('pg', 'query', text, params, false);
    const error = Object.assign(new Error('sql_dialect_not_executable: pg'), { code: 'sql_dialect_not_executable' });
    if (callback) { defer(() => callback(error)); return; }
    return Promise.reject(error);
  }
  end(callback) {
    if (callback) { defer(() => callback(null)); return; }
    return Promise.resolve();
  }
}
class Pool extends Client {
  connect(callback) {
    const client = new Client();
    client.release = () => {};
    if (callback) { defer(() => callback(null, client, client.release)); return; }
    return Promise.resolve(client);
  }
}
// Explicit assignments support Node's CJS named-export detection.
exports.Client = Client;
exports.Pool = Pool;
module.exports = guardApi(module.exports, 'pg');
