/* VIGIL customer app — service worker: the app SHELL of one build, never an account's data.
 *
 * WHAT IT STORES: the shell of ONE build — the root page and the ?v=<digest> files that page names — in a cache
 * named after that build ("vigil-shell-<build>"), filled once at install. Activation deletes every other cache.
 * Nothing is ever stored while the app runs (there is no cache.put in this file).
 *
 * WHAT IT NEVER TOUCHES — the browser sends these exactly as if no worker existed (no respondWith):
 *   - every request that is not a GET (sign-in, sign-up, launches, checkout): no Background Sync, no replay;
 *   - api/*: every account read and action, the Google sign-in redirect and its callback included;
 *   - healthz, readyz, version.json;
 *   - anything outside this origin or this worker's scope, and every path that is not the shell.
 *
 * OFFLINE: a page load of the app root ("./" or "./index.html") goes to the network first and falls back to the
 * stored root page only when the network fails. Any other path still 404s as the edge answers it.
 *
 * UPDATES: a new worker installs its build's shell and WAITS. The page (pwa.js) shows "A new version of VIGIL is
 * available — Refresh"; Refresh posts {type: "SKIP_WAITING"}; the page reloads on controllerchange.
 *
 * The edge (custui) writes BUILD and SHELL into this file at startup, so each build is a new worker script. The
 * page registers it only at the customer origin's root — never under /customer/ on the console origin.
 */
"use strict";
var BUILD = "__VIGIL_BUILD__";
var SHELL = ["__VIGIL_SHELL__"];
var CACHE = "vigil-shell-" + BUILD;
// Paths (relative to the scope) that always go to the network, whatever SHELL says.
var NETWORK_ONLY = [/^api\//, /^api$/, /^healthz$/, /^readyz$/, /^version\.json$/];

function scopeUrl() { return self.registration.scope; }

// The request path relative to the scope ("" for the scope root), or null outside the scope.
function relPath(url) {
  var base = new URL(scopeUrl()).pathname;
  return url.pathname.indexOf(base) === 0 ? url.pathname.slice(base.length) : null;
}

function shellUrls() { return SHELL.map(function (u) { return new URL(u, scopeUrl()).href; }); }

// "network" (do not answer), "shell" (a stored file of this build) or "page" (the root: network first).
function route(req) {
  if (req.method !== "GET") return "network";
  var url = new URL(req.url);
  if (url.origin !== self.location.origin) return "network";
  var rel = relPath(url);
  if (rel === null) return "network";
  for (var i = 0; i < NETWORK_ONLY.length; i++) { if (NETWORK_ONLY[i].test(rel)) return "network"; }
  if (req.mode === "navigate") return (rel === "" || rel === "index.html") ? "page" : "network";
  return shellUrls().indexOf(url.href) !== -1 ? "shell" : "network";
}

self.addEventListener("install", function (e) {
  e.waitUntil(caches.open(CACHE).then(function (c) {
    return c.addAll(SHELL.map(function (u) { return new Request(u, { cache: "reload", credentials: "omit" }); }));
  }));
});

self.addEventListener("activate", function (e) {
  e.waitUntil(caches.keys().then(function (keys) {
    return Promise.all(keys.map(function (k) { return k === CACHE ? null : caches.delete(k); }));
  }));
});

self.addEventListener("message", function (e) {
  // only this app's own pages may ask the waiting worker to take over (a worker hears its own clients alone, but
  // the origin is checked explicitly)
  if (e.origin !== self.location.origin) return;
  if (e.data && e.data.type === "SKIP_WAITING") self.skipWaiting();
});

self.addEventListener("fetch", function (e) {
  var how = route(e.request);
  if (how === "network") return;
  if (how === "shell") {
    e.respondWith(caches.open(CACHE).then(function (c) { return c.match(e.request); })
      .then(function (hit) { return hit || fetch(e.request); }));
    return;
  }
  e.respondWith(fetch(e.request).catch(function () {
    return caches.open(CACHE).then(function (c) { return c.match(shellUrls()[0]); })
      .then(function (hit) { return hit || Response.error(); });
  }));
});
