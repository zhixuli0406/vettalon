const { exec } = require('node:child_process');
exports.run = function (x, callback) {
  exec('echo ' + x, callback);
};
