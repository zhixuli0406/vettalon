const { execFile } = require('node:child_process');
exports.run = function (x, callback) {
  execFile('/bin/echo', [x], callback);
};
