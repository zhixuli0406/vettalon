const http = require('node:http');
const https = require('node:https');

function getBody(url) {
  return new Promise((resolve, reject) => {
    const client = new URL(url).protocol === 'https:' ? https : http;
    client.get(url, res => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => resolve(body));
      res.on('error', reject);
    }).on('error', reject);
  });
}

exports.run = function (url, callback) {
  getBody(url).then(body => callback(null, body), callback);
};
