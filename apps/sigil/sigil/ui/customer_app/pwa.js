/* VIGIL customer app — telling the person when a new version is out.
 *
 * The page carries the build it belongs to (body data-build, written by the edge). This file asks the edge which
 * build it serves now — GET version.json (no auth, no cookie sent, no-store) — on load, when the tab is looked at
 * again, every 10 minutes, and after an unexpected 404 (an asset of this page that failed to load, or a request
 * the app expected to exist). When the two builds differ it shows one notice, "A new version of VIGIL is
 * available — Refresh", and reloads only when the person taps Refresh. It never reloads by itself.
 *
 * CSP-native: no inline script or style, the DOM is built with createElement/textContent, same-origin only.
 * Exposes window.VIGIL_PWA for app.js.
 */
(function () {
  "use strict";
  var BUILD_RE = /^[0-9a-f]{12}$/;
  var CHECK_EVERY_MS = 10 * 60 * 1000;
  var MIN_GAP_MS = 5000;                 // a burst (focus + visibility + a 404) asks the edge once
  var ds = (document.body && document.body.dataset) || {};
  var MY_BUILD = BUILD_RE.test(ds.build || "") ? ds.build : "";   // "" when the edge did not stamp the page
  var latest = "";                       // the edge's build, from the last answer
  var lastAsked = 0;
  var noticeShown = false;

  function serverBuild(force) {
    var now = Date.now();
    if (!force && now - lastAsked < MIN_GAP_MS) return Promise.resolve(latest);
    lastAsked = now;
    return fetch("version.json", { cache: "no-store", credentials: "omit" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (d && typeof d.build === "string" && BUILD_RE.test(d.build)) latest = d.build;
        return latest;
      })
      .catch(function () { return latest; });   // offline / edge restarting: ask again next time
  }

  // Resolves true when the edge serves a different build than this page.
  function checkVersion(force) {
    if (!MY_BUILD) return Promise.resolve(false);
    return serverBuild(force).then(function (b) {
      if (b && b !== MY_BUILD) { showNotice(); return true; }
      return false;
    });
  }

  function applyUpdate() { location.reload(); }

  function showNotice() {
    if (noticeShown) return;
    noticeShown = true;
    var bar = document.createElement("div");
    bar.id = "vigil-update";
    bar.setAttribute("role", "status");
    var msg = document.createElement("span");
    msg.textContent = "A new version of VIGIL is available — ";
    var btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = "Refresh";
    btn.addEventListener("click", applyUpdate);
    bar.appendChild(msg);
    bar.appendChild(btn);
    document.body.appendChild(bar);
  }

  document.addEventListener("visibilitychange", function () { if (!document.hidden) checkVersion(false); });
  window.addEventListener("focus", function () { checkVersion(false); });
  setInterval(function () { checkVersion(true); }, CHECK_EVERY_MS);
  // A script, stylesheet or image of this page that fails to load may be a URL of a build the edge no longer
  // serves (its ?v= no longer matches: 404). Resource errors do not bubble, so listen in the capture phase.
  window.addEventListener("error", function (e) {
    var t = e && e.target;
    if (t && t !== window && /^(SCRIPT|LINK|IMG)$/.test(String(t.tagName || ""))) checkVersion(false);
  }, true);
  checkVersion(true);

  window.VIGIL_PWA = {
    build: MY_BUILD,
    checkVersion: function () { return checkVersion(true); },
    notFound: function () { return checkVersion(false); },   // app.js: a request answered 404
  };
})();
