"use strict";
/* SIGIL Companion service worker — the OFFLINE SHELL of one build of the static app.
 *
 * Scope is /static/ (the only path the unmodified bridge server serves this file from — see
 * sigil/bridge/server.py :: _serve_static). The installed app's start_url therefore also lives under
 * /static/ (manifest.webmanifest) so the shell is genuinely reloadable offline.
 *
 * DOCTRINE: it caches ONLY the static shell (html/js/css/manifest/icons), and only at install. It NEVER caches an
 * /api/* response — bridge reads/actions must always be LIVE and freshly signed; a stale cached snapshot or
 * approval would be a lie over the tunnel. So /api/* and every POST fall straight through to the network. The
 * app can still SIGN approvals offline (WebCrypto + IndexedDB in app.js, no network) and flush the queued,
 * already-signed POSTs on reconnect — that offline capability lives in app.js, not here; the SW's only job is to
 * make the app itself load without a connection.
 *
 * VERSIONED: the bridge writes the webapp's build (a content hash of its files) in place of __COMPANION_BUILD__
 * when it serves this file, so a changed app is a new worker with its own cache. The new worker installs and
 * WAITS; app.js offers "Reload", which sends {type: "SKIP_WAITING"}; activation then deletes the old build's cache.
 */
var BUILD = "__COMPANION_BUILD__";
var CACHE = "sigil-companion-" + BUILD;
var SHELL = [
  "/static/index.html",
  "/static/app.js",
  "/static/canonical.js",
  "/static/style.css",
  "/static/manifest.webmanifest",
  "/static/brand/favicon.svg",
  "/static/brand/icon-192.png"
];

self.addEventListener("install", function (e) {
  e.waitUntil(caches.open(CACHE).then(function (c) { return c.addAll(SHELL); }));
});

self.addEventListener("activate", function (e) {
  e.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(keys.map(function (k) { return k === CACHE ? null : caches.delete(k); }));
    }).then(function () { return self.clients.claim(); })
  );
});

self.addEventListener("message", function (e) {
  if (e.data && e.data.type === "SKIP_WAITING") { self.skipWaiting(); }
});

self.addEventListener("fetch", function (e) {
  var req = e.request;
  if (req.method !== "GET") { return; }                 // never intercept POST actions
  var url = new URL(req.url);
  if (url.origin !== self.location.origin) { return; }
  if (url.pathname.indexOf("/api/") === 0) { return; }  // never cache live bridge data — go to network
  if (url.search || SHELL.indexOf(url.pathname) === -1) { return; }   // only the shell, by its exact path
  // this build's shell, stored at install; the network only if the store lost it
  e.respondWith(
    caches.open(CACHE).then(function (c) { return c.match(url.pathname); })
      .then(function (hit) { return hit || fetch(req); })
  );
});
