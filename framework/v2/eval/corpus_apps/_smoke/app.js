// Minimal deliberately-vulnerable app for the corpus DOCKER smoke test.
//
// Its only purpose is to prove the real DockerLauncher lifecycle end-to-end
// (docker run -> health poll -> scan through the gated client -> teardown) against
// a live daemon, using a bug CRUCIBLE confirms with an unforgeable oracle. It is
// built from a cached node base image so it needs no registry pull.
//
// Ground truth (see smoke-node.json):
//   * /search?q=...  reflects q into a raw HTML context  -> reflected XSS (planted)
//   * /safe?q=...    HTML-escapes q                        -> must NOT be flagged
//   * /health        liveness                              -> 200
'use strict';
const http = require('http');
const { URL } = require('url');

const PORT = process.env.PORT || 8080;

function escapeHtml(s) {
  return String(s)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

const server = http.createServer((req, res) => {
  const u = new URL(req.url, `http://localhost:${PORT}`);
  const q = u.searchParams.get('q') || '';

  if (u.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
    return;
  }
  if (u.pathname === '/search') {
    // VULNERABLE: q reflected into HTML without escaping.
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!doctype html><html><body><h1>Results</h1><div>${q}</div></body></html>`);
    return;
  }
  if (u.pathname === '/safe') {
    // SAFE control: q is escaped; a scanner must not flag this.
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!doctype html><html><body><div>${escapeHtml(q)}</div></body></html>`);
    return;
  }
  // Index links the crawler to the endpoints.
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end(
    '<!doctype html><html><body><h1>corpus smoke</h1>' +
    '<a href="/search?q=hello">search</a> <a href="/safe?q=hello">safe</a>' +
    '</body></html>'
  );
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`corpus-smoke listening on ${PORT}`);
});
