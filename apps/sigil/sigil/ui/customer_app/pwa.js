/* VIGIL customer app — telling the person when a new version is out, and the installed-app worker.
 *
 * NEW VERSION. The page carries the build it belongs to (body data-build, written by the edge). This file asks the
 * edge which build it serves now — GET version.json (no auth, no cookie sent, no-store) — on load, when the tab is
 * looked at again, every 10 minutes, and after an unexpected 404 (an asset of this page that failed to load, or a
 * request the app expected to exist). When the two builds differ it shows one notice, "A new version of VIGIL is
 * available — Refresh", and reloads only when the person taps Refresh. It never reloads by itself.
 *
 * WORKER (sw.js, the shell of one build). Registered only when the app is served at its origin's root — the
 * dedicated customer origin — and never under /customer/ on the console origin. A new build's worker installs and
 * WAITS: if this page is older than the edge, the notice is shown and Refresh sends it {type: "SKIP_WAITING"}, then
 * the page reloads on controllerchange; if this page already is the edge's build (it came from the network), the
 * worker is switched quietly.
 *
 * INSTALL. Chromium offers installation through beforeinstallprompt: the event is kept and an "Install app" button
 * shown (root mount only); the browser's own dialog does the rest. Safari on iOS has no such event: when the edge
 * enables it (VIGIL_CUSTOMER_IOS_INSTALL_BANNER, off by default — pending the owner's sign-in test in the installed
 * app on a real iPhone) a dismissible "Share -> Add to Home Screen" banner is shown instead.
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
  var reg = null;                        // the worker registration (root mount only)
  var userAskedRefresh = false;
  var reloading = false;
  function noop() {}
  function reload() { if (!reloading) { reloading = true; location.reload(); } }

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
      if (b && b !== MY_BUILD) {
        if (reg) reg.update().catch(noop);   // start installing the new build's worker
        showNotice();
        return true;
      }
      return false;
    });
  }

  function applyUpdate() {
    userAskedRefresh = true;
    var w = reg && reg.waiting;
    if (!w) { reload(); return; }
    w.postMessage({ type: "SKIP_WAITING" });   // the reload follows on controllerchange
    setTimeout(reload, 3000);                  // ...or here, if the switch never comes
  }

  // A new worker finished installing and waits behind the one in control.
  function onWaiting(w) {
    if (!navigator.serviceWorker.controller) return;          // the first install: nothing to replace
    serverBuild(true).then(function (b) {
      if (b && b === MY_BUILD) w.postMessage({ type: "SKIP_WAITING" });   // this page is already that build
      else showNotice();
    });
  }

  function registerWorker() {
    // Only at the root of the customer origin: under /customer/ on the console origin no worker is registered.
    if (!("serviceWorker" in navigator) || location.pathname !== "/") return;
    var sw = navigator.serviceWorker;
    sw.addEventListener("controllerchange", function () { if (userAskedRefresh) reload(); });
    sw.register("sw.js", { scope: "./" }).then(function (r) {
      reg = r;
      if (r.waiting) onWaiting(r.waiting);
      r.addEventListener("updatefound", function () {
        var w = r.installing;
        if (!w) return;
        w.addEventListener("statechange", function () { if (w.state === "installed" && r.waiting === w) onWaiting(w); });
      });
    }).catch(noop);                              // no worker (private mode, policy): the app works without one
  }

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
  // ---- install: Chromium ---------------------------------------------------------------------------------------
  var installEvt = null;
  var installBtn = null;
  function hideInstall() { if (installBtn) { installBtn.remove(); installBtn = null; } }
  function showInstall() {
    if (installBtn) return;
    installBtn = document.createElement("button");
    installBtn.type = "button";
    installBtn.id = "vigil-install";
    installBtn.textContent = "Install app";
    installBtn.addEventListener("click", function () {
      var e = installEvt;
      installEvt = null;
      hideInstall();
      if (!e || typeof e.prompt !== "function") return;
      try {
        var shown = e.prompt();                          // the browser's own install dialog; it may be used once
        if (shown && typeof shown.catch === "function") shown.catch(noop);
        if (e.userChoice && typeof e.userChoice.catch === "function") e.userChoice.catch(noop);
      } catch (err) { /* already shown once: nothing to do */ }
    });
    document.body.appendChild(installBtn);
  }
  window.addEventListener("beforeinstallprompt", function (e) {
    e.preventDefault();                                  // never the browser's own banner: our button, or nothing
    if (location.pathname !== "/") return;              // not under /customer/ on the console origin
    installEvt = e;
    showInstall();
  });
  window.addEventListener("appinstalled", function () { installEvt = null; hideInstall(); });

  // ---- install: iOS (behind the edge's flag, off by default) -------------------------------------------------
  var IOS_DISMISSED = "vigil.ios_install.dismissed";
  function isIOS() {
    var ua = String(navigator.userAgent || "");
    return /iPad|iPhone|iPod/.test(ua) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
  }
  function standalone() {
    return navigator.standalone === true
      || !!(window.matchMedia && window.matchMedia("(display-mode: standalone)").matches);
  }
  function iosDismissed() { try { return localStorage.getItem(IOS_DISMISSED) === "1"; } catch (e) { return false; } }
  function showIosBanner() {
    var bar = document.createElement("div");
    bar.id = "vigil-ios-install";
    bar.setAttribute("role", "note");
    var msg = document.createElement("span");
    msg.textContent = "Install VIGIL: tap Share, then Add to Home Screen.";
    var close = document.createElement("button");
    close.type = "button";
    close.setAttribute("aria-label", "Dismiss");
    close.textContent = "×";
    close.addEventListener("click", function () {
      try { localStorage.setItem(IOS_DISMISSED, "1"); } catch (e) { /* storage off: hidden for this load only */ }
      bar.remove();
    });
    bar.appendChild(msg);
    bar.appendChild(close);
    document.body.appendChild(bar);
  }
  if (ds.iosInstall === "1" && location.pathname === "/" && isIOS() && !standalone() && !iosDismissed()) {
    showIosBanner();
  }

  checkVersion(true);
  registerWorker();

  // Sign-out: delete every CacheStorage cache of this origin (the worker's shell holds no account data, but a
  // shared device should keep nothing of the session). Clear-Site-Data "cache" would not reach CacheStorage.
  function clearCaches() {
    if (typeof caches === "undefined" || !caches || typeof caches.keys !== "function") return Promise.resolve(0);
    return caches.keys()
      .then(function (keys) { return Promise.all(keys.map(function (k) { return caches.delete(k); })); })
      .then(function (done) { return done.length; })
      .catch(function () { return 0; });
  }

  window.VIGIL_PWA = {
    build: MY_BUILD,
    checkVersion: function () { return checkVersion(true); },
    notFound: function () { return checkVersion(false); },   // app.js: a request answered 404
    clearCaches: clearCaches,                                // app.js: on sign-out
  };
})();
