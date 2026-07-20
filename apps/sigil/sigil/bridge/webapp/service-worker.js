"use strict";
/* SIGIL Companion service worker — a cache-first OFFLINE SHELL for the static app only.
 *
 * Scope is /static/ (the only path the unmodified bridge server serves this file from — see
 * sigil/bridge/server.py :: _serve_static). The installed app's start_url therefore also lives under
 * /static/ (manifest.json) so the shell is genuinely reloadable offline.
 *
 * DOCTRINE: it caches ONLY the static shell (html/js/css/manifest). It NEVER caches an /api/*
 * response — bridge reads/actions must always be LIVE and freshly signed; a stale cached snapshot or
 * approval would be a lie over the tunnel. So /api/* and every POST fall straight through to the
 * network. The app can still SIGN approvals offline (WebCrypto + IndexedDB in app.js, no network) and
 * flush the queued, already-signed POSTs on reconnect — that offline capability lives in app.js, not
 * here; the SW's only job is to make the app itself load without a connection.
 */
var CACHE = "sigil-companion-v1";
var SHELL = [
  "/static/index.html",
  "/static/app.js",
  "/static/canonical.js",
  "/static/style.css",
  "/static/manifest.json"
];

self.addEventListener("install", function (e) {
  e.waitUntil(caches.open(CACHE).then(function (c) { return c.addAll(SHELL); }).then(function () { return self.skipWaiting(); }));
});

self.addEventListener("activate", function (e) {
  e.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(keys.map(function (k) { return k === CACHE ? null : caches.delete(k); }));
    }).then(function () { return self.clients.claim(); })
  );
});

self.addEventListener("fetch", function (e) {
  var req = e.request;
  if (req.method !== "GET") { return; }                 // never intercept POST actions
  var url = new URL(req.url);
  if (url.pathname.indexOf("/api/") === 0) { return; }  // never cache live bridge data — go to network
  // cache-first for the shell, with a network refresh in the background (stale-while-revalidate)
  e.respondWith(
    caches.match(req).then(function (hit) {
      var net = fetch(req).then(function (resp) {
        if (resp && resp.ok && (req.url.indexOf("/static/") !== -1 || url.pathname === "/")) {
          var copy = resp.clone();
          caches.open(CACHE).then(function (c) { c.put(req, copy); });
        }
        return resp;
      }).catch(function () { return hit; });
      return hit || net;
    })
  );
});
