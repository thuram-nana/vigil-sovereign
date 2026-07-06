// Minimal harness exposing the REAL CVE-2014-3744 path traversal in st@0.2.4.
// st < 0.2.5 fails to sanitize URL-encoded "../" sequences, so an encoded traversal
// escapes the served root and reads arbitrary files. This is a published, historical
// npm vulnerability (GHSA-excj-6qcf-hmvv / CVE-2014-3744), not an invented bug.
'use strict';
const http = require('http');
const st = require('st');
const PORT = process.env.PORT || 8080;
const mount = st({ path: __dirname + '/public', url: '/', index: 'index.txt', passthrough: true });
http.createServer((req, res) => {
  if (req.url === '/' ) {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<!doctype html><html><body><h1>st file service</h1>' +
            '<a href="/index.txt">browse a file</a></body></html>');
    return;
  }
  mount(req, res, () => { res.writeHead(404); res.end('not found'); });
}).listen(PORT, '0.0.0.0', () => console.log('cve-st listening on ' + PORT));
