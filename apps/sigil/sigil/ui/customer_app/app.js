/* VIGIL customer app (Slice I).
 *
 * A no-build, CSP-native SPA on window.VUI (the shared kit). It is served by the KEYLESS custui edge and
 * authenticates purely by the HttpOnly `vigil_customer_session` cookie — there is NO token in this page and
 * none in storage. Every call is same-origin (VUI.getJSON/postJSON send credentials:"same-origin" and the
 * X-Requested-With CSRF header), and every API path is RELATIVE ("api/customer/...") so it resolves against
 * the mount in dev (/customer/) and in prod (/ on the separate customer origin).
 *
 * Routing is HASH-based (#/login, #/signup, ...). The document path never changes after load, so assets and
 * API paths always resolve against the mount and no deep server route is needed (the proxy has no SPA history
 * fallback). The SERVER is the authority on identity + tenant scope; this UI never sends an org id the server
 * would trust — reads/launches are scoped to the session org by the edge + admit_customer.
 *
 * GOOGLE. When the edge has customer Google sign-in on, it writes data-google-signin="1" into the page at startup and
 * the sign-in and sign-up screens show "Continue with Google": a top-level GET of api/customer/oidc/login (relative),
 * which the edge answers with the redirect to Google. A Google sign-in that does not complete lands back on the app
 * as #oidc=err, shown as one generic message (the edge never says why).
 *
 * GOOGLE IN THE INSTALLED APP. An app added to a Home Screen runs standalone, and iOS finishes Google sign-in in a
 * separate browser with its own cookies, so a session set there never reaches the app. When the edge has the hand-off
 * on (data-oidc-handoff="1") and the app runs standalone, the button instead makes a random 32-byte verifier, keeps
 * it in this app (IndexedDB, else sessionStorage; never a cookie or a URL) and starts the login with
 * ?handoff=<base64url(sha256(verifier))>. The page where Google sign-in finished shows a 6-digit code; back in the
 * app, a code box asks for it and POSTs {verifier, code} to api/customer/oidc/handoff, which sets the session
 * cookie in the app's own cookie jar. Outside a standalone app the normal flow is used, unchanged.
 *
 * EMAIL CODES. When the deployment sends them (the request answers code: true), the sign-up and password-reset emails
 * carry a 6-digit code beside the token, and the screens ask for "the 6-digit code from your email" (with the token
 * one tap away). The code is sent with the email address it went to; it works once, for 10 minutes.
 *
 * ONBOARDING. When the edge has the onboarding guide on (data-onboarding="1", VIGIL_CUSTOMER_ONBOARDING), the app
 * (guide.js) opens a skippable click-through tour after a person's first sign-in — and at each sign-in after it, on
 * any device, until they finish or skip it: the SERVER keeps that answer per account (GET/POST api/customer/onboarding,
 * for the session's account only) and this browser remembers it too, for when the server cannot be asked. It also
 * adds a Guide screen (#/guide) covering the whole app to the top bar, and shows the VIGIL wordmark brightening and
 * dimming while a screen loads. Off, all of it is absent (no call is made) and every screen renders exactly as before.
 *
 * ACCOUNT SECURITY. When the edge has the security screens on (data-security="1", VIGIL_CUSTOMER_SECURITY_UI), the top
 * bar shows the account's name, which opens Account security (#/security, security.js: an authenticator app and
 * passkeys, read through GET api/customer/security for the session's account only), next to Sign out; the sign-in
 * screen offers "Sign in with a passkey" when the edge also serves passkeys (data-passkey="1"); and withStepUp() — the
 * one name every sensitive action goes through (buying credits today) — answers the server's request for a fresh
 * second factor with an inline code box, then sends the action ONCE more. Off, all of it is absent: withStepUp(action)
 * is action(), #/security is the home screen, and every screen renders exactly as before.
 * LAUNCHING. When the edge has launching from the app on (data-launch-ui="1", VIGIL_CUSTOMER_LAUNCH_UI), the
 * Assessments screen offers Launch on each verified host — one of the depths the server offers, never a price — and
 * lists the workspace's launches from api/customer/launches with the controls the server accepts (Start / Cancel
 * before a launch starts, Pause / Resume while it runs), refreshing while one runs and the screen is visible. Off, the
 * screen is read-only exactly as before and that read is never made.
 * MONITORING. When the edge has customer monitoring on (data-monitoring="1", VIGIL_CUSTOMER_MONITORING_ENABLED — the same
 * switch that serves the monitoring routes), the top bar has a Monitoring screen (#/monitoring): the workspace's hosts
 * and their AEGIS monitoring, Turn on / Turn off, and the events AEGIS reported, refreshed while the screen is in view.
 * The server decides who may change monitoring, which hosts are proven and what the plan includes; this page sends
 * only a host the server listed and a mode. Off, there is no tab, #/monitoring is the home screen exactly as any unknown
 * route, and no call or timer is made.
 * TEAM. When the edge has the Team screen on (data-team="1", VIGIL_CUSTOMER_TEAM_UI), #/team lists the workspace's
 * members (GET api/customer/members) and lets the founder or an admin add an existing VIGIL account by its email, change
 * a member's role and remove a member (confirmed in the page). Off, #/team is the "being wired" card it always was and
 * nothing is fetched.
 */
(function () {
  "use strict";
  var VUI = window.VUI;
  var root = document.getElementById("app");
  // Fail-to-DEGRADE before the first VUI.* dereference: if the shared kit (ui.js) did not load/parse, VUI is
  // undefined and the very next VUI call (store(), below) would throw at module init, aborting the whole IIFE
  // and leaving a blank page (noscript does not fire with JS enabled). Show the honest message and stop.
  if (!VUI) { if (root) { root.textContent = "VIGIL could not load its interface. Please reload."; } return; }
  // Cookie-auth plane: no embedded/sessionStorage token. VUI.postJSON still sends X-Requested-With + cookie.
  window.VIGIL_CFG = { token: "", api: {} };
  // A 404 may mean the edge now runs a newer build than this page (a route or file this build expected): let
  // pwa.js ask the edge — it shows the "new version" notice only when the build really changed.
  (function () {
    var P = window.VIGIL_PWA;
    if (!P || typeof P.notFound !== "function") return;
    ["getJSON", "postJSON"].forEach(function (k) {
      var f = VUI[k];
      VUI[k] = function () {
        return f.apply(VUI, arguments).catch(function (e) { if (e && e.status === 404) P.notFound(); throw e; });
      };
    });
  })();
  var API = "api/customer"; // relative to the mount
  var state = VUI.store({ who: null, booted: false });

  // ---- tiny helpers -------------------------------------------------------------------------------
  function h() { return VUI.h.apply(null, arguments); }
  function nav(hash) { if (location.hash === hash) render(); else location.hash = hash; }
  function authed() { var w = state.get().who; return !!(w && w.authenticated); }

  function pageFlag(name) {
    var ds = (document.body && document.body.dataset) || {};
    return ds[name] === "1";
  }

  // ---- onboarding (guide.js): the first-sign-in tour, the Guide screen, the branded loader ----------------------
  var GUIDE = window.VIGIL_GUIDE;
  var GUIDE_ON = !!(GUIDE && pageFlag("onboarding"));
  function guideStore() { try { return window.localStorage; } catch (e) { return null; } }
  // What a screen shows while it loads: the VIGIL wordmark brightening and dimming with the guide on, the plain text
  // otherwise (exactly the node every screen showed before).
  function loadingHolder(text) {
    return GUIDE_ON ? GUIDE.loader(h, text) : h("p.cust-muted", { text: text });
  }
  // The tour's outcome goes to the server, so it never opens again on any device (best effort: this browser remembers
  // it too, and the next sign-in sends it again if this send did not land).
  function recordTour(how) {
    VUI.postJSON(API + "/onboarding", { state: how }).catch(function () { /* remembered locally; re-sent later */ });
  }
  function openGuideTour() {
    var w = state.get().who || {};
    GUIDE.openTour({ h: h, doc: document, username: w.username, storage: guideStore(), nav: nav, onClose: recordTour });
  }
  // After a sign-in: the SERVER says whether this account still has the tour ahead of it ("pending" until it is
  // finished or skipped, on any device). Asked once per account per page load. If the server cannot be asked, this
  // browser's memory decides. A tour finished here whose record did not reach the server is sent again, not re-shown.
  var tourChecked = {};
  function maybeOpenTour() {
    if (!GUIDE_ON || !authed()) return;
    var u = String((state.get().who || {}).username || "");
    if (!u || tourChecked[u]) return;
    tourChecked[u] = true;
    (async function () {
      var server = null;
      try { var r = await VUI.getJSON(API + "/onboarding"); server = r && r.state; }
      catch (e) {
        if (e && e.status === 401) { tourChecked[u] = false; return; }   // the session ended: ask again after sign-in
        server = null;
      }
      if (!authed() || String((state.get().who || {}).username || "") !== u) return;   // signed out / switched since
      var store = guideStore();
      if (server === "done" || server === "skipped") { GUIDE.markDone(u, store, server); return; }
      var local = GUIDE.localState(u, store);
      if (server === "pending" && local) { recordTour(local); return; }
      if (server === "pending" || GUIDE.shouldOpen({ enabled: true, username: u, storage: store })) openGuideTour();
    })();
  }
  function viewGuideScreen() {
    var w = state.get().who || {};
    return shell(h("div", {}, [h("h2", { text: "Guide" }),
      GUIDE.viewGuide({ h: h, username: w.username, storage: guideStore(), nav: nav, replayTour: openGuideTour,
                        shown: routeShown })]),
    "#/guide");
  }
  // A screen the guide may send someone to that this deployment does not show: no "Go to" button leads there.
  function routeShown(route) { return route !== "#/monitoring" || MONITORING_ON; }

  // ---- account security (security.js): Account security, passkey sign-in, the step-up prompt -----------------------
  var SECURITY = window.VIGIL_SECURITY;
  var SECURITY_ON = !!(SECURITY && pageFlag("security"));
  // STEP-UP — the one name every screen uses for a sensitive action (buying credits, changing the team, turning
  // monitoring on, launching): withStepUp(action, where) runs action() — a function returning the promise of ONE
  // request — and settles with its answer. When the server refuses it with 401 {step_up_required: true}, a "Verify with
  // your authenticator" box opens inside `where` (an element; else at the top of the screen), and once the person's code
  // is verified, action() runs ONE more time: never a loop, a second refusal rejects like any error. Closing the box
  // rejects with e.stepUpCancelled === true (nothing was sent again). With the security screens off it is action().
  function withStepUp(action, where) {
    if (!SECURITY_ON) return action();
    return SECURITY.stepUp({ h: h, VUI: VUI, api: API, where: where, nav: nav }, action);
  }
  function viewSecurityScreen() {
    return shell(h("div", {}, [h("h2", { text: "Account security" }),
      SECURITY.viewSecurity({ h: h, VUI: VUI, api: API, who: state.get().who, passkeys: pageFlag("passkey"), nav: nav,
        here: here, loading: loadingHolder,
        onAuthLost: function () { refreshWho().then(function () { nav("#/login"); }); } })]),
    "#/security");
  }
  // "Sign in with a passkey" on the sign-in screen: only with the security screens on and passkeys served here.
  function passkeyBlock() {
    if (!SECURITY_ON || !pageFlag("passkey")) return null;
    if (SECURITY.webauthnSupport() === "none") {
      return h("p.muted.cust-passkey-none", { text: "Passkey sign-in needs a browser that supports passkeys." });
    }
    return h("div.cust-passkey-block", {}, [
      h("div.cust-or", {}, h("span", { text: "or" })),
      h("button.btn.cust-passkey", { type: "button", text: "Sign in with a passkey", onClick: doPasskeyLogin }),
    ]);
  }
  async function doPasskeyLogin() {
    clearErr();
    try {
      var r = await SECURITY.passkeySignIn({ VUI: VUI, api: API });
      if (r && r.username) { await refreshWho(); nav("#/"); VUI.toast("Signed in"); }
      else { err("Sign-in failed."); }
    } catch (e) { err(SECURITY.signInMessage(e)); }
  }

  function field(id, label, type) {
    return [h("label", { for: id, text: label }),
            h("input#" + id, { type: type || "text", autocomplete: "off", spellcheck: "false" })];
  }
  function val(id) { var el = VUI.$("#" + id); return el ? String(el.value || "").trim() : ""; }
  function err(msg) { VUI.errorBanner(msg); }   // kit API is errorBanner(msg, detail?) — a #error-banner body singleton
  function kv(k, v) {
    return h("div.cust-kv", {}, [h("span.k", { text: k }),
      h("span", { text: (v == null || v === "") ? "—" : String(v) })]);
  }
  function money(minor, cur) {
    var n = (typeof minor === "number") ? minor : parseInt(minor || 0, 10);
    if (isNaN(n)) n = 0;
    return (n / 100).toFixed(2) + " " + String(cur || "").toUpperCase();
  }
  function fmtDate(ts) {
    try { return new Date(Number(ts || 0) * 1000).toISOString().slice(0, 10); } catch (e) { return "—"; }
  }

  // ---- API ----------------------------------------------------------------------------------------
  function whoami() {
    // whoami answers 200 {authenticated:false} when logged out (never a 401), so this never throws for that.
    return VUI.getJSON(API + "/whoami").catch(function () { return { authenticated: false }; });
  }
  async function refreshWho() {
    var w = await whoami();
    state.set({ who: w, booted: true });
    return w;
  }

  // ---- views: logged out --------------------------------------------------------------------------
  function viewLogin() {
    var form = h("div.card.cust-auth", {}, [
      h("h2", { text: "Sign in" }),
      googleBlock(),
      field("login-email", "Email", "email"),
      field("login-password", "Password", "password"),
      h("div.row", {}, [
        h("button.btn.btn-primary", { type: "button", text: "Sign in", onClick: doLogin }),
        h("button.cust-nav-link", { type: "button", text: "Create an account", onClick: function () { nav("#/signup"); } }),
      ]),
      passkeyBlock(),
      h("div.row", {}, [
        h("button.cust-nav-link", { type: "button", text: "Forgot your password?", onClick: function () { nav("#/recover"); } }),
      ]),
    ]);
    return shell(form, "#/login");
  }

  // ---- Continue with Google -------------------------------------------------------------------------
  // Shown only while the edge has customer Google sign-in on (data-google-signin="1", written at startup). The
  // button is a top-level navigation to the edge's login route, which redirects to Google; the session cookie is
  // set by the edge when Google sends the person back. This page never sees a Google token.
  function googleOn() { return pageFlag("googleSignin"); }
  var SVG_NS = "http://www.w3.org/2000/svg";
  function googleMark() {
    // Google's four-colour "G" (the mark Google's sign-in button guidelines ask for), built as DOM: no inline markup
    var svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("viewBox", "0 0 48 48");
    svg.setAttribute("width", "18");
    svg.setAttribute("height", "18");
    svg.setAttribute("aria-hidden", "true");
    [["#EA4335", "M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"],
     ["#4285F4", "M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"],
     ["#FBBC05", "M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"],
     ["#34A853", "M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"]
    ].forEach(function (p) {
      var path = document.createElementNS(SVG_NS, "path");
      path.setAttribute("fill", p[0]);
      path.setAttribute("d", p[1]);
      svg.appendChild(path);
    });
    return svg;
  }
  function googleBlock() {
    if (!googleOn()) return null;
    var btn = h("button.btn.cust-google", { type: "button", onClick: startGoogle },
      [googleMark(), h("span", { text: "Continue with Google" })]);
    return h("div.cust-google-block", {}, [btn, h("div.cust-or", {}, h("span", { text: "or use your email" }))]);
  }
  function startGoogle() {
    clearErr();
    if (handoffOn()) { startHandoff(); return; }
    location.assign(API + "/oidc/login");          // relative: the edge answers with the redirect to Google
  }

  // ---- Google sign-in inside the installed app: the hand-off ----------------------------------------------
  var HANDOFF_KEY = "vigil.oidc.handoff";
  var HANDOFF_MAX_AGE_MS = 10 * 60 * 1000;         // the edge keeps a finished sign-in ~2 min; the login ~10 min
  function standaloneApp() {
    return navigator.standalone === true
      || !!(window.matchMedia && window.matchMedia("(display-mode: standalone)").matches);
  }
  function handoffOn() { return googleOn() && pageFlag("oidcHandoff") && standaloneApp(); }
  function b64u(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  // The pending verifier lives in this app only: IndexedDB (survives iOS ending the app in the background), else
  // sessionStorage. Every access is guarded; nothing here ever goes into a cookie or a URL.
  function idbRun(mode, fn) {
    return new Promise(function (resolve, reject) {
      if (typeof indexedDB === "undefined" || !indexedDB) { reject(new Error("no IndexedDB")); return; }
      var open = indexedDB.open("vigil-app", 1);
      open.onupgradeneeded = function () { open.result.createObjectStore("kv"); };
      open.onerror = function () { reject(open.error || new Error("IndexedDB")); };
      open.onsuccess = function () {
        var db = open.result, tx, req;
        try { tx = db.transaction("kv", mode); req = fn(tx.objectStore("kv")); }
        catch (e) { db.close(); reject(e); return; }
        tx.oncomplete = function () { db.close(); resolve(req ? req.result : undefined); };
        tx.onerror = tx.onabort = function () { db.close(); reject(tx.error || new Error("IndexedDB")); };
      };
    });
  }
  function ssGet() { try { return JSON.parse(sessionStorage.getItem(HANDOFF_KEY) || "null"); } catch (e) { return null; } }
  function pendingSave(rec) {
    return idbRun("readwrite", function (st) { return st.put(rec, HANDOFF_KEY); })
      .catch(function () { sessionStorage.setItem(HANDOFF_KEY, JSON.stringify(rec)); });   // throws if neither works
  }
  function pendingLoad() {
    return idbRun("readonly", function (st) { return st.get(HANDOFF_KEY); })
      .catch(function () { return null; })
      .then(function (rec) {
        rec = rec || ssGet();
        var fresh = rec && typeof rec.verifier === "string" && /^[A-Za-z0-9_-]{43}$/.test(rec.verifier)
          && typeof rec.at === "number" && Date.now() - rec.at < HANDOFF_MAX_AGE_MS;
        return fresh ? rec : null;
      });
  }
  function pendingClear() {
    try { sessionStorage.removeItem(HANDOFF_KEY); } catch (e) { /* storage off */ }
    return idbRun("readwrite", function (st) { return st.delete(HANDOFF_KEY); }).catch(function () {});
  }
  async function startHandoff() {
    try {
      var raw = new Uint8Array(32);
      crypto.getRandomValues(raw);
      var verifier = b64u(raw);
      var digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
      var challenge = b64u(new Uint8Array(digest));
      await pendingSave({ verifier: verifier, at: Date.now() });
      nav("#/google-code");                          // the code box is waiting when the person comes back
      location.assign(API + "/oidc/login?handoff=" + challenge);
    } catch (e) {
      err("Google sign-in could not start in this app. Sign in with your email, or try again.");
    }
  }
  // Coming back to the app (from the browser where Google sign-in finished): a sign-in in progress shows the box.
  async function resumeHandoff() {
    if (authed() || !pageFlag("oidcHandoff") || here() === "#/google-code") return;
    if (await pendingLoad()) nav("#/google-code");
  }
  function viewGoogleCode() {
    var holder = h("div#gc-body", {}, h("p.cust-muted", { text: "Checking for a Google sign-in on this device…" }));
    pendingLoad().then(function (rec) {
      if (here() !== "#/google-code") return;
      if (!rec) {
        VUI.mount(holder, [
          h("p", { text: "No Google sign-in is waiting in this app. Open VIGIL from your Home Screen and start "
            + "with Continue with Google there." }),
          h("div.row", {}, [h("button.btn", { type: "button", text: "Back to sign in",
            onClick: function () { nav("#/login"); } })]),
        ]);
        return;
      }
      var input = h("input#gc-code.cust-code-input", { type: "text", inputmode: "numeric", pattern: "[0-9 ]*",
        autocomplete: "one-time-code", maxlength: "7", "aria-label": "6-digit code", spellcheck: "false" });
      input.addEventListener("keydown", function (e) { if (e.key === "Enter") doHandoff(); });
      VUI.mount(holder, [
        h("p", { text: "Enter the 6-digit code shown after you signed in with Google." }),
        h("label", { for: "gc-code", text: "Code" }), input,
        h("div.row", {}, [
          h("button.btn.btn-primary", { type: "button", text: "Continue", onClick: doHandoff }),
          h("button.cust-nav-link", { type: "button", text: "Start again", onClick: function () {
            pendingClear().then(startGoogle); } }),
        ]),
        h("p.muted", { text: "Only enter a code that VIGIL showed you after you signed in with Google on this phone. "
          + "Stay on the same Wi-Fi or mobile network until you are signed in." }),
      ]);
      try { input.focus(); } catch (e) { /* no focus outside a gesture */ }
    });
    return shell(h("div.card.cust-auth", {}, [h("h2", { text: "Finish signing in with Google" }), holder]),
      "#/google-code");
  }
  async function doHandoff() {
    clearErr();
    var code = val("gc-code").replace(/\s+/g, "");
    if (!/^[0-9]{6}$/.test(code)) { return err("Enter the 6 digits of the code."); }
    var rec = await pendingLoad();
    if (!rec) { render(); return err("This sign-in has expired. Start again with Continue with Google."); }
    try {
      var r = await VUI.postJSON(API + "/oidc/handoff", { verifier: rec.verifier, code: code });
      await pendingClear();
      if (r && r.ok) { await refreshWho(); nav("#/"); VUI.toast("Signed in"); }
      else { err("Sign-in failed."); }
    } catch (e) {
      var d = (e && e.data) || {};
      if (e && e.status === 401 && d.retry) { return err(d.error || "That code does not match."); }
      if (e && e.status === 429) { return err("Too many attempts — wait a moment and try again."); }
      if (e && e.status === 401) {
        await pendingClear();
        nav("#/login");
        return err(d.error || "This sign-in is no longer valid. Start again with Continue with Google.");
      }
      err(authMsg(e, "Sign-in could not finish. Try again."));
    }
  }

  async function doLogin() {
    clearErr();
    var email = val("login-email"), password = val("login-password");
    if (!email || !password) { return err("Enter your email and password."); }
    try {
      var r = await VUI.postJSON(API + "/login", { email: email, password: password });
      if (r && r.username) { await refreshWho(); nav("#/"); VUI.toast("Signed in"); }
      else { err("Sign-in failed."); }
    } catch (e) { err(authMsg(e, "Sign-in failed.")); }
  }

  function viewSignup() {
    var form = h("div.card.cust-auth", {}, [
      h("h2", { text: "Create your account" }),
      googleBlock(),
      h("p.muted", { text: "We email you a single-use verification token (and, where enabled, a 6-digit code). "
        + "Your account and workspace are owner-signed on confirmation — this page never grants access by itself." }),
      field("su-email", "Work email", "email"),
      h("div.row", {}, [
        h("button.btn.btn-primary", { type: "button", text: "Send verification", onClick: doSignupRequest }),
      ]),
      h("div.row", {}, [
        h("button.cust-nav-link", { type: "button", text: "I already have a code",
          onClick: function () { VUI.mount(VUI.$("#su-confirm"), confirmBlock(true, true, "", "")); } }),
        h("button.cust-nav-link", { type: "button", text: "Back to sign in", onClick: function () { nav("#/login"); } }),
      ]),
      h("div#su-confirm"),
    ]);
    return shell(form, "#/signup");
  }

  // The mailbox proof of a sign-up or reset email: its 6-digit code (with the email address it went to), or its
  // token. `byCode` = the deployment sends codes; `offer` = show the other way too.
  function codeField(id) {
    return [h("label", { for: id, text: "6-digit code" }),
            h("input#" + id + ".cust-code-input", { type: "text", inputmode: "numeric", pattern: "[0-9 ]*",
              autocomplete: "one-time-code", maxlength: "7", spellcheck: "false" })];
  }
  function proofSwitch(holder, prefix, tokenLabel, byCode, offer) {
    function draw(useCode) {
      holder.dataset.mode = useCode ? "code" : "token";
      VUI.mount(holder, [
        h("p.muted", { text: useCode ? "Enter the 6-digit code from your email."
                                     : "Paste the token from the email." }),
        useCode ? codeField(prefix + "-code") : field(prefix + "-token", tokenLabel, "text"),
        offer ? h("button.cust-nav-link", { type: "button",
          text: useCode ? "Use the token from the email instead" : "Use the 6-digit code instead",
          onClick: function () { draw(!useCode); } }) : null,
      ]);
    }
    draw(byCode);
    return holder;
  }
  // {code, email} or {token} from the proof block; null (with the message shown) when it is not filled in.
  function proofBody(prefix, emailId) {
    var holder = VUI.$("#" + prefix + "-proof");
    if (holder && holder.dataset.mode === "code") {
      var code = val(prefix + "-code").replace(/\s+/g, ""), email = val(emailId);
      if (!email) { err("Enter the email address the code was sent to."); return null; }
      if (!/^[0-9]{6}$/.test(code)) { err("Enter the 6-digit code from your email."); return null; }
      return { email: email, code: code };
    }
    var token = val(prefix + "-token");
    if (!token) { err("Paste the token from the email."); return null; }
    return { token: token };
  }

  async function doSignupRequest() {
    clearErr();
    var email = val("su-email");
    if (!email) { return err("Enter your email."); }
    try {
      var r = await VUI.postJSON(API + "/signup/request", { email: email });
      // The token (and, where enabled, a 6-digit code) is delivered by email. A dev edge MAY echo them (explicit,
      // governed flag) to speed local testing; if present we prefill.
      var byCode = !!(r && r.code);
      var devToken = (r && (r.token || r.dev_token)) || "";
      VUI.mount(VUI.$("#su-confirm"), confirmBlock(byCode, byCode, devToken, (r && r.dev_code) || ""));
      VUI.toast(byCode ? "Check your email for your 6-digit code." : "Check your email for the verification token.");
    } catch (e) { err(authMsg(e, "Could not start signup.")); }
  }

  function confirmBlock(byCode, offer, devToken, devCode) {
    var box = h("div", {}, [
      h("hr"),
      proofSwitch(h("div#su-proof"), "su", "Verification token", byCode, offer),
      h("p.muted", { text: "Pick a password and name your workspace." }),
      field("su-password", "Choose a password", "password"),
      field("su-org", "Workspace name", "text"),
      h("div.row", {}, [
        h("button.btn.btn-primary", { type: "button", text: "Create account", onClick: doSignupConfirm }),
      ]),
    ]);
    setTimeout(function () {
      var t = VUI.$("#su-token"), c = VUI.$("#su-code");
      if (t && devToken) t.value = devToken;
      if (c && devCode) c.value = devCode;
    }, 0);
    return box;
  }

  async function doSignupConfirm() {
    clearErr();
    var password = val("su-password"), org = val("su-org");
    var proof = proofBody("su", "su-email");
    if (!proof) return;
    if (!password || !org) { return err("Choose a password and name your workspace."); }
    proof.password = password;
    proof.org_name = org;
    try {
      var r = await VUI.postJSON(API + "/signup/confirm", proof);
      if (r && r.username) { await refreshWho(); nav("#/"); VUI.toast("Welcome to VIGIL"); }
      else { err("Could not complete signup."); }
    } catch (e) { err(authMsg(e, "Could not complete signup.")); }
  }

  // ---- password reset ---------------------------------------------------------------------------------
  function viewRecover() {
    var form = h("div.card.cust-auth", {}, [
      h("h2", { text: "Reset your password" }),
      h("p.muted", { text: "We email a single-use token (and, where enabled, a 6-digit code) to the address of your "
        + "account. Setting a new password signs you out everywhere." }),
      field("rc-email", "Email", "email"),
      h("div.row", {}, [
        h("button.btn.btn-primary", { type: "button", text: "Send reset email", onClick: doRecoverRequest }),
      ]),
      h("div.row", {}, [
        h("button.cust-nav-link", { type: "button", text: "I already have a code",
          onClick: function () { VUI.mount(VUI.$("#rc-confirm"), recoverBlock(true, true, "", "")); } }),
        h("button.cust-nav-link", { type: "button", text: "Back to sign in", onClick: function () { nav("#/login"); } }),
      ]),
      h("div#rc-confirm"),
    ]);
    return shell(form, "#/recover");
  }

  async function doRecoverRequest() {
    clearErr();
    var email = val("rc-email");
    if (!email) { return err("Enter your email."); }
    try {
      var r = await VUI.postJSON(API + "/recover/request", { email: email });
      var byCode = !!(r && r.code);
      VUI.mount(VUI.$("#rc-confirm"), recoverBlock(byCode, byCode, (r && r.dev_token) || "", (r && r.dev_code) || ""));
      // the same answer whether or not the address has an account
      VUI.toast(byCode ? "If that address has an account, a 6-digit code is on its way."
                       : "If that address has an account, a reset token is on its way.");
    } catch (e) { err(authMsg(e, "Could not send the reset email.")); }
  }

  function recoverBlock(byCode, offer, devToken, devCode) {
    var box = h("div", {}, [
      h("hr"),
      proofSwitch(h("div#rc-proof"), "rc", "Reset token", byCode, offer),
      field("rc-password", "New password", "password"),
      h("div.row", {}, [
        h("button.btn.btn-primary", { type: "button", text: "Set new password", onClick: doRecoverConfirm }),
      ]),
    ]);
    setTimeout(function () {
      var t = VUI.$("#rc-token"), c = VUI.$("#rc-code");
      if (t && devToken) t.value = devToken;
      if (c && devCode) c.value = devCode;
    }, 0);
    return box;
  }

  async function doRecoverConfirm() {
    clearErr();
    var password = val("rc-password");
    var proof = proofBody("rc", "rc-email");
    if (!proof) return;
    if (!password) { return err("Choose a new password."); }
    proof.new_password = password;
    try {
      var r = await VUI.postJSON(API + "/recover/confirm", proof);
      if (r && r.username) { nav("#/login"); VUI.toast("Password changed. Sign in with your new password."); }
      else { err("Could not reset the password."); }
    } catch (e) { err(authMsg(e, "Could not reset the password.")); }
  }

  // ---- views: logged in ---------------------------------------------------------------------------
  function viewDashboard() {
    var w = state.get().who || {};
    var body = h("div", {}, [
      h("h2", { text: "Overview" }),
      h("div.cust-grid", {}, [
        VUI.card("Account", null, [kv("Signed in as", w.username), kv("Workspace", w.org_id)]),
      ]),
      h("p.cust-muted", { text: "Billing, invoices, authorized assets and assessments appear here as those "
        + "panels come online. Every panel is scoped to this workspace by the server." }),
    ]);
    return shell(body, "#/");
  }

  function viewSoon(title) {
    return shell(h("div", {}, [h("h2", { text: title }),
      h("div.card.cust-soon", { text: title + " is being wired to this workspace and will appear here shortly." })]),
      "#/" + title.toLowerCase());
  }

  // An async data view: render the shell + a "Loading…" holder NOW, then fetch and fill it. The server
  // scopes every read to the session org (admit_customer) — this UI never sends an org id. Guards against a
  // route change mid-flight, routes a 401 to login, and renders an honest card on 403 (role) or any error.
  function dataView(current, title, path, renderOk) {
    var holder = h("div#cust-data", {}, loadingHolder("Loading…"));
    (async function () {
      var data;
      try { data = await VUI.getJSON(path); }
      catch (e) {
        if (here() !== current) return;
        if (e && e.status === 401) { await refreshWho(); nav("#/login"); return; }
        if (e && e.status === 403) {
          return VUI.mount(holder, h("div.card.cust-soon", { text: "Your role does not have access to " + title
            + ". Billing roles cannot view assessments, and testing roles are granted separately by the owner." }));
        }
        return VUI.mount(holder, h("div.card.cust-soon", { text: "Could not load " + title
          + ((e && e.data && e.data.error) ? ": " + e.data.error : ".") }));
      }
      if (here() !== current) return;                 // the customer navigated away before the load resolved
      VUI.mount(holder, renderOk(data));
    })();
    return shell(h("div", {}, [h("h2", { text: title }), holder]), current);
  }
  function here() { return (location.hash || "#/").split("?")[0]; }

  function viewBilling() {
    return dataView("#/billing", "Billing", API + "/billing", function (d) {
      var c = d.credits || {}, w = d.wallet || {}, s = d.subscription;
      return h("div.cust-grid", {}, [
        VUI.card("Credits", null, [
          kv("Available", c.available), kv("Persistent (wallet)", c.persistent), kv("Plan (this period)", c.plan_live),
        ]),
        VUI.card("Wallet", null, [
          kv("Granted", w.granted), kv("Debited", w.debited), kv("Available", w.available),
        ]),
        VUI.card("Subscription", null, s
          ? [kv("Plan", s.plan_id), kv("Status", s.status), kv("Allotment", s.allotment),
             kv("Active now", d.active ? "yes" : "no")]
          : [h("p.cust-muted", { text: "No active subscription." })]),
        buySection(),
      ]);
    });
  }

  // ---- CHK-2: buy (hosted checkout) -----------------------------------------------------------------
  // This page NEVER grants anything. It asks the edge for a hosted-checkout link for a CATALOG price_id (the
  // amount is the owner catalog's, server side — the page sends no amount) and sends the browser there. Credit
  // arrives ONLY when the server verifies the payment (signed webhook + processor re-verify), never from here.
  var TOPUP = "topup_purchased";
  function isCheckoutUrl(u) {
    // Only ever navigate to an absolute https link with a host and no embedded credentials.
    try { var p = new URL(String(u)); return p.protocol === "https:" && !!p.hostname && !p.username && !p.password; }
    catch (e) { return false; }
  }
  // An AEGIS monitoring plan buys protected-host slots (monitor_hosts), never credits.
  function isMonitoringOffer(o) { return !!o && o.kind !== TOPUP && (parseInt(o.monitor_hosts, 10) || 0) > 0; }
  function aegisPlanName(hosts, respond) {
    var n = parseInt(hosts, 10) || 0;
    return "AEGIS " + (respond ? "Respond" : "Observe") + ", " + n + (n === 1 ? " host" : " hosts");
  }
  function offerLine(o) {
    if (o.kind === TOPUP) return (o.credits != null ? String(o.credits) + " credits" : "Credit top-up");
    var per = o.period_days ? " every " + String(o.period_days) + " days" : "";
    if (isMonitoringOffer(o)) {
      var days = Number(o.period_days) || 0;
      return aegisPlanName(o.monitor_hosts, !!o.monitor_respond) + (days >= 28 && days <= 31 ? " — monthly" : per ? " —" + per : "")
        + (o.monitor_respond ? ": watches traffic, reports attacks and can block them" : ": watches traffic and reports attacks");
    }
    return "Plan: " + String(o.allotment != null ? o.allotment : "") + " credits" + per;
  }
  // Checkout refuses a second plan OF THE SAME KIND, so the buy list hides a plan exactly then: a credit plan while the
  // workspace's credit plan is live or a credit-plan checkout is in progress; an AEGIS plan while its AEGIS plan is live
  // or an AEGIS checkout is in progress. One kind never hides the other, and top-ups are always offered. (Checkout sells
  // no AEGIS plan yet; the read that offers one must also report has_monitoring_plan and monitoring_checkout_pending.)
  function offerShown(d, o) {
    if (o.kind === TOPUP) return true;
    if (isMonitoringOffer(o)) return !(d.has_monitoring_plan || d.monitoring_checkout_pending);
    return !(d.has_active_plan || d.plan_checkout_pending);
  }
  async function startCheckout(o, btn) {
    btn.disabled = true;
    try {
      // when the server asks for a fresh second factor, withStepUp checks one inline and sends the purchase ONCE more
      var r = await withStepUp(function () { return VUI.postJSON(API + "/billing/checkout", { price_id: o.price_id }); },
        btn.parentNode);
      if (!r || !isCheckoutUrl(r.checkout_url)) {
        err("The payment link we received was not a secure https link, so we did not open it. Nothing was charged.");
        btn.disabled = false; return;
      }
      location.assign(r.checkout_url);            // leave for the processor's hosted page
    } catch (e) {
      btn.disabled = false;
      if (e && e.stepUpCancelled) return;          // the person closed the check: nothing was sent again or charged
      if (e && e.status === 401 && e.data && e.data.step_up_required) {
        return err("For your security, this purchase needs a fresh second-factor check. Verify with your "
          + "authenticator, then try again. Nothing was charged.");
      }
      if (e && e.status === 401) { await refreshWho(); nav("#/login"); return; }
      err("Checkout could not start" + ((e && e.data && e.data.error) ? ": " + e.data.error : ".")
        + " Nothing was charged.");
    }
  }
  function buySection() {
    var holder = h("div#cust-buy", {});
    (async function () {
      var d;
      // Absent while checkout is off (404) and hidden for a role that cannot spend money (403): no buy section.
      try { d = await VUI.getJSON(API + "/billing/offers"); } catch (e) { return; }
      if (here() !== "#/billing") return;
      // a live plan, or a plan checkout still in progress (not yet drained): checkout refuses a second plan of its kind.
      var offers = ((d && d.offers) || []).filter(function (o) { return offerShown(d, o); });
      if (!offers.length) return;
      var rows = offers.map(function (o) {
        var btn = h("button.btn", { type: "button", text: "Buy " + money(o.amount_minor, o.currency) });
        btn.addEventListener("click", function () { startCheckout(o, btn); });
        return h("div.cust-offer", {}, [h("div", {}, [h("strong", { text: String(o.name || o.price_id) }),
          h("p.cust-muted", { text: offerLine(o) })]), btn]);
      });
      var note = d.has_active_plan
        ? "Your workspace already has a plan, so top-ups are shown. Changing plans is not self-serve yet."
        : d.plan_checkout_pending
          ? "A plan checkout for your workspace is in progress, so top-ups are shown until it is confirmed or expires."
          : "You pay on the payment processor's secure page. Credits appear here once the payment is verified.";
      VUI.mount(holder, VUI.card("Buy credits", null, [h("p.cust-muted", { text: note })].concat(rows)));
    })();
    return holder;
  }

  // #/billing/return — where the processor sends the customer back. Its status is DISPLAY-ONLY: nothing here
  // grants credit (only the server's verified webhook drain does). We show the live balance while it confirms.
  function returnParams() {
    var hq = (location.hash || "").split("?")[1] || "";
    return new URLSearchParams(hq || (location.search || "").replace(/^\?/, ""));
  }
  function viewBillingReturn() {
    var status = String(returnParams().get("status") || "").toLowerCase();
    var failed = status === "cancelled" || status === "canceled" || status === "failed";
    var holder = h("div#cust-return-status", {}, h("p.cust-muted", { text: failed ? "" : "Checking your balance…" }));
    var lead = failed
      ? "The payment was not completed, so nothing was charged. You can try again from Billing."
      : "Thank you. Your payment is being confirmed with the payment processor. Credits appear as soon as it is "
        + "verified — usually within a minute. You can leave this page; nothing else is needed.";
    if (!failed) {
      (async function () {
        for (var i = 0; i < 20; i++) {
          if (here() !== "#/billing/return") return;
          try {
            var d = await VUI.getJSON(API + "/billing");
            var c = (d && d.credits) || {}, s = d && d.subscription;
            VUI.mount(holder, h("div", {}, [kv("Available credits", c.available),
              kv("Plan", s ? (s.plan_id + " (" + s.status + ")") : "none"),
              h("p.cust-muted", { text: "Last checked " + new Date().toLocaleTimeString() + "." })]));
          } catch (e) {
            if (e && e.status === 401) { await refreshWho(); nav("#/login"); return; }
          }
          await new Promise(function (res) { setTimeout(res, 3000); });
        }
        if (here() === "#/billing/return") {
          VUI.append(holder, h("p.cust-muted", { text: "Still confirming? It can take a few minutes; your "
            + "balance on the Billing page updates by itself. Nothing is lost." }));
        }
      })();
    }
    var back = h("button.cust-nav-link", { type: "button", text: "Back to Billing" });
    back.addEventListener("click", function () { nav("#/billing"); });
    return shell(h("div", {}, [h("h2", { text: failed ? "Payment not completed" : "Payment received" }),
      h("p", { text: lead }), holder, back]), "#/billing");
  }

  function viewInvoices() {
    return dataView("#/invoices", "Invoices", API + "/invoices", function (d) {
      var invs = (d && d.invoices) || [];
      if (!invs.length) { return h("div.card.cust-soon", { text: "No invoices yet." }); }
      var head = h("tr", {}, ["Date", "Type", "Plan", "Amount", "Credits"].map(function (t) { return h("th", { text: t }); }));
      var rows = invs.map(function (i) {
        return h("tr", {}, [
          h("td", { text: fmtDate(i.issued_at) }), h("td", { text: i.kind || "—" }),
          h("td", { text: i.price_id || "—" }), h("td", { text: money(i.amount_minor, i.currency) }),
          h("td", { text: (i.credits != null ? String(i.credits) : "—") }),
        ]);
      });
      return h("div.card", {}, [
        h("table.cust-table", {}, [h("thead", {}, head), h("tbody", {}, rows)]),
        h("p.cust-muted", { text: (d.count || invs.length) + " invoice(s)." }),
      ]);
    });
  }

  // ---- Assets / Domains: the status surface (verified / pending / expired) + prove ownership
  //      (challenge -> verify). The server scopes the list to THIS workspace (admit_customer, never a
  //      client-sent org id) and gates it on the testing (operator) role — a billing role gets the honest
  //      403 card from dataView. Proving control lets the owner authorize the target; it never runs a test. --
  function viewAssets() {
    return dataView("#/assets", "Authorized assets", API + "/assets", function (d) {
      var assets = (d && d.assets) || [];
      return h("div", {}, [
        h("p.cust-muted", { text: "Prove you control a host before any assessment can target it. Proving control "
          + "lets the owner authorize the target; it never runs a test by itself (billing is separate from testing)." }),
        assetsList(assets),
        h("div.card.cust-register", {}, [
          h("h3", { text: "Register a new host" }),
          field("asset-host", "Host (e.g. app.example.com)", "text"),
          h("div.row", {}, [h("button.btn.btn-primary", { type: "button", text: "Request ownership challenge",
            onClick: function () { doChallenge(); } })]),
          h("div#asset-flow"),
        ]),
      ]);
    });
  }
  function statusBadge(st) {
    var label = st === "verified" ? "✓ Verified" : st === "expired" ? "⚠ Expired" : "… Pending";
    return h("span.cust-badge.cust-badge-" + (st === "verified" || st === "expired" ? st : "pending"),
      { text: label });
  }
  function assetsList(assets) {
    if (!assets.length) {
      return h("div.card.cust-soon", { text: "No hosts registered yet — register one below, publish the token, "
        + "then verify to prove control." });
    }
    var cards = assets.map(function (a) {
      var rows = [h("div.cust-asset-head", {}, [h("span.host", { text: a.host }), statusBadge(a.status)])];
      if (a.method) {
        rows.push(kv("Method", a.method));
        rows.push(kv("Verified", fmtDate(a.verified_at)));
        rows.push(kv(a.status === "expired" ? "Expired" : "Expires", fmtDate(a.expires_at)));
      }
      if (a.status === "expired") {
        rows.push(h("p.cust-muted", { text: "This proof has lapsed — re-check or re-issue a challenge to renew it." }));
      } else if (a.status === "pending") {
        rows.push(h("p.cust-muted", { text: "Not yet verified — publish the token, then re-check." }));
      }
      var actions = [];
      if (a.challenge) {
        actions.push(h("button.btn", { type: "button", text: "Re-check now",
          onClick: function () { showChallenge(assign(a.challenge, { host: a.host })); } }));
      }
      actions.push(h("button.btn", { type: "button", text: "Re-issue challenge",
        onClick: function () { doChallenge(a.host); } }));
      rows.push(h("div.row", {}, actions));
      return h("div.card", {}, rows);
    });
    return h("div", {}, [h("h3", { text: "Your hosts" }), h("div.cust-grid", {}, cards)]);
  }
  function assign(base, extra) {                       // ES5-safe shallow merge (no Object.assign assumption)
    var o = {}, k;
    for (k in base) { if (Object.prototype.hasOwnProperty.call(base, k)) o[k] = base[k]; }
    for (k in extra) { if (Object.prototype.hasOwnProperty.call(extra, k)) o[k] = extra[k]; }
    return o;
  }
  function flowCard(sel, msg) { var e = VUI.$(sel); if (e) { VUI.mount(e, h("div.card.cust-soon", { text: msg })); } }
  function flowMsg(e, fallback) {
    if (e && e.status === 403) return "Asset registration requires the testing (operator) role, granted by the "
      + "owner. Billing roles cannot register or test assets.";
    if (e && e.data && e.data.error) return String(e.data.error);
    return fallback;
  }
  function showChallenge(r) {
    var holder = VUI.$("#asset-flow");
    if (holder) { VUI.mount(holder, challengeBlock(r)); try { holder.scrollIntoView({ block: "nearest" }); } catch (e) {} }
  }
  async function doChallenge(hostArg) {
    clearErr();
    var host = hostArg || val("asset-host");
    if (!host) { return err("Enter a host."); }
    try {
      var r = await VUI.postJSON(API + "/target/challenge", { host: host });
      showChallenge(r);
    } catch (e) { flowCard("#asset-flow", flowMsg(e, "Could not start the ownership challenge.")); }
  }
  function challengeBlock(r) {
    return h("div", {}, [
      h("hr"),
      h("p", { text: "Publish ONE of these for " + (r.host || "") + ", then verify:" }),
      h("label.cust-authz", { style: "display:flex;gap:.5rem;align-items:flex-start;margin:.5rem 0" }, [
        h("input", { type: "checkbox", id: "cust-authz-confirm" }),
        h("span.cust-muted", { text: "I confirm I am authorized to test this asset. Controlling a domain is not "
          + "the same as being allowed to test it — only check this if you have authorization." }),
      ]),
      VUI.card("DNS TXT record", "dns-txt", [kv("Name", r.dns_name), kv("Value", r.dns_value),
        h("div.row", {}, [h("button.btn", { type: "button", text: "Verify via DNS",
          onClick: function () { doVerify(r.host, "dns-txt"); } })])]),
      VUI.card(".well-known file", "https", [kv("URL", r.well_known_url), kv("Body", r.well_known_body),
        h("div.row", {}, [h("button.btn", { type: "button", text: "Verify via .well-known",
          onClick: function () { doVerify(r.host, "well-known"); } })])]),
      VUI.card("HTML meta tag", "meta-tag", [kv("In your homepage <head>", r.meta_tag),
        h("div.row", {}, [h("button.btn", { type: "button", text: "Verify via meta tag",
          onClick: function () { doVerify(r.host, "meta-tag"); } })])]),
      h("div#asset-verify"),
    ]);
  }
  async function doVerify(host, method) {
    var box = document.getElementById("cust-authz-confirm");
    if (!box || !box.checked) {                        // one inline step: confirm authorization, then verify
      flowCard("#asset-verify", h("p.cust-muted", { text: "Please confirm you are authorized to test this "
        + "asset (the checkbox above) before verifying." }));
      return;
    }
    try {
      var r = await VUI.postJSON(API + "/target/verify", { host: host, method: method, authorized: true });
      VUI.toast("Ownership verified for " + (r.host || host));
      if (here() === "#/assets") render();           // refresh the status list -> the host now shows "Verified"
    } catch (e) { flowCard("#asset-verify", flowMsg(e, "Verification did not pass — publish the token and retry.")); }
  }

  // ---- Assessments: results (operator-role only; org_admin sees the honest 403 card). Launching and controlling
  //      an assessment from here is the C1a block below, shown only while the edge has VIGIL_CUSTOMER_LAUNCH_UI on;
  //      off, this screen is read-only exactly as before. ------------------------------------------------------
  function viewAssessments() {
    return dataView("#/assessments", "Assessments", API + "/assessments", function (d) {
      var items = (d && d.assessments) || [];
      if (LAUNCH_ON) return assessmentsLaunchView(items);
      var note = h("p.cust-muted", { text: "Your authorized assessments and their oracle-confirmed findings. "
        + "Launching a new assessment arrives with the run driver." });
      if (!items.length) {
        return h("div", {}, [note, h("div.card.cust-soon", { text: "No authorized assessments yet — register and "
          + "verify an asset, then the owner authorizes the target." })]);
      }
      var rows = items.map(function (a) {
        return h("div.card", {}, [
          h("div.cust-kv", {}, [h("span.k", { text: a.host }), h("span", { text: (a.findings || 0) + " finding(s)" })]),
          h("div.row", {}, [h("button.btn", { type: "button", text: "View findings",
            onClick: function () { loadFindings(a.slug, a.host); } })]),
        ]);
      });
      return h("div", {}, [note, h("div.cust-grid", {}, rows), h("div#assess-findings")]);
    });
  }
  async function loadFindings(slug, host) {
    var holder = VUI.$("#assess-findings");
    if (!holder) { return; }
    VUI.mount(holder, loadingHolder("Loading findings for " + host + "…"));
    try {
      var d = await VUI.getJSON(API + "/assessments/findings");
      if (here() !== "#/assessments") { return; }
      var fs = ((d && d.findings) || []).filter(function (f) { return f.engagement_slug === slug; });
      VUI.mount(holder, findingsBlock(host, fs));
    } catch (e) {
      VUI.mount(holder, h("div.card.cust-soon", { text: "Could not load findings"
        + ((e && e.data && e.data.error) ? ": " + e.data.error : ".") }));
    }
  }
  function findingsBlock(host, fs) {
    if (!fs.length) { return h("div.card.cust-soon", { text: "No findings for " + host + "." }); }
    var cards = fs.map(function (f) {
      return VUI.card(f.title || f.finding_ref || "Finding", f.severity || null, h("div", {}, [
        kv("Severity", f.severity), kv("Class", f.bug_class), kv("Surface", f.surface), kv("Confidence", f.confidence),
        f.summary ? h("p", { text: f.summary }) : null,
        f.how_to_verify ? h("p.cust-muted", { text: "Verify offline: " + f.how_to_verify }) : null,
      ]));
    });
    return h("div", {}, [h("h3", { text: "Findings — " + host }), h("div.cust-grid", {}, cards)]);
  }

  // ---- Assessments: launch and control them (C1a) ----------------------------------------------------------------
  // Shown only while the edge writes data-launch-ui="1" (VIGIL_CUSTOMER_LAUNCH_UI). Each verified host gets Launch:
  // one of the depths the SERVER offers this workspace (api/customer/launches lists them — never a price, credits or
  // units: VIGIL never estimates what an assessment costs), then the app reserves (launch/reserve) and starts
  // (launch/start) it. The same read lists the workspace's launches with the actions the server would accept and, for a
  // member who may run them, the signed lease each action presents — so no control depends on a lease kept in this
  // page. Cancel asks first, in the page. While a launch runs or is paused and this screen is visible, the list
  // refreshes; it stops when the screen is left or hidden. A refusal is told in fixed words chosen from what the
  // server refused, never the server's own text (it can name amounts and internals). Off: nothing here runs.
  var LAUNCH_ON = pageFlag("launchUi");
  var LAUNCH_POLL_MS = 15000;
  var DEPTH_LABELS = { quick: "Quick", deep: "Deep" };
  var DEPTH_HINTS = { quick: "a focused first pass", deep: "broader and more thorough" };
  var STATE_LABELS = { reserved: "Not started", running: "Running", paused: "Paused" };
  var FINISHED_LABELS = { completed: "Completed", canceled: "Cancelled", failed: "Did not complete" };
  // The controls, in the order they show; a launch offers only the ones the server listed for it.
  var LAUNCH_ACTIONS = [
    { id: "start", label: "Start", path: "/launch/start", done: "Assessment started" },
    { id: "pause", label: "Pause", path: "/launch/pause", done: "Assessment paused" },
    { id: "resume", label: "Resume", path: "/launch/resume", done: "Assessment resumed" },
    { id: "cancel", label: "Cancel", path: "/launch/cancel", done: "Launch cancelled" },
  ];
  var launchUi = { data: null, hosts: [], slots: Object.create(null), other: null, done: null, timer: null, gen: 0,
                   notes: Object.create(null), busy: Object.create(null), used: Object.create(null),
                   picker: null, confirm: null };

  // a label for a value the server sent, from OUR table only (never an inherited member of the object)
  function own(table, key) {
    return Object.prototype.hasOwnProperty.call(table, key) ? table[key] : "";
  }
  function launchesFor(slug) {
    return ((launchUi.data && launchUi.data.launches) || []).filter(function (l) { return l && l.slug === slug; });
  }
  // What Launch offers: the depths the server lists (Quick / Deep; any other depth is never shown), else its one
  // default launch (no depth to choose).
  function launchChoices() {
    var cs = ((launchUi.data && launchUi.data.choices) || []).filter(function (c) { return !!c; });
    var depths = cs.filter(function (c) { return c.product_id && own(DEPTH_LABELS, c.depth); });
    if (depths.length) return depths;
    return cs.filter(function (c) { return c.product_id === ""; }).slice(0, 1);
  }

  function assessmentsLaunchView(items) {
    launchUi.hosts = items.map(function (a) { return { slug: a.slug, host: a.host }; });
    launchUi.slots = Object.create(null);
    launchUi.notes = Object.create(null);
    launchUi.data = null; launchUi.picker = null; launchUi.confirm = null;
    var note = h("p.cust-muted", { text: "Your authorized assessments and their oracle-confirmed findings. "
      + "Launch an assessment of a verified host, then follow it here while it runs." });
    var cards = items.map(function (a) {
      var slot = h("div.cust-launch", {});
      launchUi.slots[a.slug] = slot;
      return h("div.card", {}, [
        h("div.cust-kv", {}, [h("span.k", { text: a.host }), h("span", { text: (a.findings || 0) + " finding(s)" })]),
        slot,
        h("div.row", {}, [h("button.btn", { type: "button", text: "View findings",
          onClick: function () { loadFindings(a.slug, a.host); } })]),
      ]);
    });
    launchUi.other = h("div#cust-launch-other", {});
    launchUi.done = h("div#cust-launch-done", {});
    var body = [note, items.length ? h("div.cust-grid", {}, cards)
      : h("div.card.cust-soon", { text: "No verified hosts yet — prove you control a host in Assets, then launch an "
          + "assessment of it here." })];
    loadLaunches();
    return h("div", {}, body.concat([launchUi.other, launchUi.done, h("div#assess-findings")]));
  }

  // Draw every launch area of the screen from what the server last said (and what this page is doing right now).
  function renderLaunches() {
    if (here() !== "#/assessments") return;
    launchUi.hosts.forEach(function (a) {
      var slot = launchUi.slots[a.slug];
      if (slot) VUI.mount(slot, launchSlot(a));
    });
    if (launchUi.other) VUI.mount(launchUi.other, otherLaunches());
    if (launchUi.done) VUI.mount(launchUi.done, finishedLaunches());
  }
  function launchSlot(a) {
    if (!launchUi.data) return null;                       // still loading
    var mine = launchesFor(a.slug);
    var note = launchUi.notes[a.slug];
    return mine.map(launchRow).concat([note ? launchNote(note) : null, mine.length ? null : launchPicker(a)]);
  }
  function launchRow(l) {
    var key = l.slug + ":" + l.launch;
    var depth = own(DEPTH_LABELS, l.depth);
    var rows = [h("p.cust-launch-status", { text: own(STATE_LABELS, l.state) + (depth ? " · " + depth : "") })];
    if (l.expired) {
      rows.push(h("p.cust-muted", { text: "This launch can no longer start. Cancel it to release its credits." }));
    }
    if (launchUi.confirm === key) {
      rows.push(h("div.cust-launch-confirm", {}, [
        h("p", { text: "Cancel this launch? It has not started, so nothing is charged." }),
        h("div.row", {}, [
          h("button.btn.btn-primary", { type: "button", text: "Yes, cancel",
            onClick: function () { launchAction(l, "cancel"); } }),
          h("button.btn", { type: "button", text: "Keep it",
            onClick: function () { launchUi.confirm = null; renderLaunches(); } }),
        ]),
      ]));
      return h("div.cust-launch-item", {}, rows);
    }
    var allowed = l.actions || [];
    var busy = !!launchUi.busy[l.slug];
    var buttons = LAUNCH_ACTIONS.filter(function (x) { return allowed.indexOf(x.id) >= 0; }).map(function (x) {
      var go = x.id === "cancel" ? function () { launchUi.confirm = key; renderLaunches(); }
                                 : function () { launchAction(l, x.id); };
      return h("button.btn", { type: "button", text: x.label, disabled: busy, onClick: go });
    });
    if (buttons.length) rows.push(h("div.row", {}, buttons));
    return h("div.cust-launch-item", {}, rows);
  }
  function launchPicker(a) {
    var offered = launchChoices();
    if (!offered.length) return null;                    // nothing this member may launch here
    var busy = !!launchUi.busy[a.slug];
    if (launchUi.picker !== a.slug) {
      return h("div.row", {}, [h("button.btn.btn-primary", { type: "button", text: "Launch", disabled: busy,
        onClick: function () { launchUi.picker = a.slug; delete launchUi.notes[a.slug]; renderLaunches(); } })]);
    }
    var depths = offered.filter(function (c) { return c.product_id; });
    var rows = [h("p", { text: depths.length ? "Choose a depth to start an assessment of " + a.host + ":"
                                             : "Start an assessment of " + a.host + "?" })];
    offered.forEach(function (c) {
      var label = c.product_id ? own(DEPTH_LABELS, c.depth) : "Start";
      rows.push(h("div.cust-launch-choice", {}, [
        h("button.btn.btn-primary", { type: "button", text: label, disabled: busy,
          onClick: function () { doLaunch(a, c); } }),
        c.product_id ? h("span.cust-muted", { text: own(DEPTH_HINTS, c.depth) }) : null,
      ]));
    });
    rows.push(h("p.cust-muted", { text: "No price is shown: VIGIL never estimates what an assessment costs." }));
    rows.push(h("div.row", {}, [h("button.btn", { type: "button", text: "Not now",
      onClick: function () { launchUi.picker = null; renderLaunches(); } })]));
    return h("div.cust-launch-picker", {}, rows);
  }
  function launchNote(note) {
    return h("div.cust-launch-note", { role: "status" }, [
      h("p", { text: note.text }),
      note.go ? h("button.btn", { type: "button", text: note.goText, onClick: function () { nav(note.go); } }) : null,
    ]);
  }
  // Launches on hosts that are not on the verified list any more (a proof can lapse while an assessment runs): they
  // keep their controls here.
  function otherLaunches() {
    var d = launchUi.data;
    if (d && d.unavailable) {
      return h("p.cust-muted", { text: "Launching and following assessments is not available right now." });
    }
    var listed = Object.create(null);
    launchUi.hosts.forEach(function (a) { listed[a.slug] = true; });
    var rest = ((d && d.launches) || []).filter(function (l) { return l && !listed[l.slug]; });
    if (!rest.length) return null;
    return h("div", {}, [h("h3", { text: "Other launches" }), h("div.cust-grid", {}, rest.map(function (l) {
      var note = launchUi.notes[l.slug];
      return h("div.card", {}, [h("div.cust-asset-head", {}, [h("span.host", { text: l.host })]), launchRow(l),
        note ? launchNote(note) : null]);
    }))]);
  }
  function finishedLaunches() {
    var fs = ((launchUi.data && launchUi.data.finished) || []).filter(function (f) { return !!f; });
    if (!fs.length) return null;
    return VUI.card("Finished assessments", null, fs.map(function (f) {
      var used = f.state === "completed" ? launchUi.used[f.slug + ":" + f.launch] : "";
      return h("div.cust-kv", {}, [h("span.k", { text: f.host }), h("span", { text: (own(FINISHED_LABELS, f.state)
        || "Ended") + (f.ended_at ? " · " + fmtDate(f.ended_at) : "") + (used ? " · used " + used + " credits" : "") })]);
    }));
  }

  // The server's answer to the launches read; while a launch runs or is paused, asked again every LAUNCH_POLL_MS.
  async function loadLaunches() {
    if (here() !== "#/assessments") return;
    var gen = ++launchUi.gen;                              // only the newest answer is drawn
    var d;
    try { d = await VUI.getJSON(API + "/launches"); }
    catch (e) {
      if (gen !== launchUi.gen || here() !== "#/assessments") return;
      if (e && e.status === 401) { await refreshWho(); nav("#/login"); return; }
      if (!launchUi.data) {                                // never loaded on this visit: no controls
        launchUi.data = { unavailable: true, choices: [], launches: [], finished: [] };
        renderLaunches();
        return;
      }
      scheduleLaunchPoll();                                // a refresh that failed: keep what is shown, ask again
      return;
    }
    if (gen !== launchUi.gen || here() !== "#/assessments") return;
    launchUi.data = d || {};
    renderLaunches();
    loadUsage();
    scheduleLaunchPoll();
  }
  function scheduleLaunchPoll() {
    if (launchUi.timer || here() !== "#/assessments" || document.hidden) return;
    var live = ((launchUi.data && launchUi.data.launches) || []).some(function (l) {
      return l && (l.state === "running" || l.state === "paused");
    });
    if (!live) return;
    launchUi.timer = setTimeout(function () { launchUi.timer = null; loadLaunches(); }, LAUNCH_POLL_MS);
  }
  function stopLaunchPoll() {
    if (launchUi.timer) { clearTimeout(launchUi.timer); launchUi.timer = null; }
    launchUi.gen++;                                        // an answer already on its way is dropped
  }
  function onLaunchRoute() {
    if (here() !== "#/assessments") stopLaunchPoll();
  }
  function onLaunchVisibility() {
    if (document.hidden) stopLaunchPoll();
    else if (here() === "#/assessments" && launchUi.data) loadLaunches();
  }

  // After a run: what it used, only as the server's statement already records it (billing/usage: one figure per
  // launch, in credits) — never computed here. Shown for a COMPLETED launch whose statement has usage; asked once
  // per newly finished launch.
  async function loadUsage() {
    var want = ((launchUi.data && launchUi.data.finished) || []).filter(function (f) {
      return f && f.state === "completed" && !Object.prototype.hasOwnProperty.call(launchUi.used, f.slug + ":" + f.launch);
    });
    if (!want.length) return;
    var u = null;
    try { u = await VUI.getJSON(API + "/billing/usage"); } catch (e) { u = null; }
    var byLaunch = Object.create(null);
    ((u && u.scans) || []).forEach(function (s) {
      if (s && s.status === "ok" && s.requests > 0 && typeof s.credits === "string") {
        byLaunch[s.scan + ":" + s.launch] = s.credits;
      }
    });
    want.forEach(function (f) { var k = f.slug + ":" + f.launch; launchUi.used[k] = byLaunch[k] || ""; });
    renderLaunches();
  }

  // Launch: reserve, then start. A refusal of either is told in the host's card; a reservation whose start was
  // refused stays listed (Start / Cancel) — the server kept it.
  async function doLaunch(a, choice) {
    clearErr();
    var slug = a.slug;
    launchUi.picker = null; launchUi.busy[slug] = true; delete launchUi.notes[slug];
    renderLaunches();
    var body = { host: a.host };
    if (choice.product_id) body.product_id = choice.product_id;
    var r;
    try { r = await VUI.postJSON(API + "/launch/reserve", body); }
    catch (e) { delete launchUi.busy[slug]; return launchRefused(slug, "reserve", e); }
    try { await VUI.postJSON(API + "/launch/start", { lease: r && r.lease }); }
    catch (e) { delete launchUi.busy[slug]; await launchRefused(slug, "start", e); return loadLaunches(); }
    delete launchUi.busy[slug];
    VUI.toast("Assessment started");
    return loadLaunches();
  }
  async function launchAction(l, which) {
    clearErr();
    var act = LAUNCH_ACTIONS.filter(function (x) { return x.id === which; })[0];
    if (!act) return;
    var slug = l.slug;
    launchUi.confirm = null; launchUi.busy[slug] = true; delete launchUi.notes[slug];
    renderLaunches();
    var r;
    try { r = await VUI.postJSON(API + act.path, { lease: l.lease }); }
    catch (e) { delete launchUi.busy[slug]; await launchRefused(slug, which, e); return loadLaunches(); }
    delete launchUi.busy[slug];
    if (which === "resume" && r && r.expired) {
      launchUi.notes[slug] = { text: "Resumed. This launch's time window has closed: an assessment still running "
        + "carries on, but one that had not started, or had stopped for the pause, will not start again." };
    }
    VUI.toast(which === "cancel" && r && r.already_settled ? "This launch had already ended" : act.done);
    return loadLaunches();
  }
  async function launchRefused(slug, which, e) {
    if (e && e.status === 401 && !(e.data && e.data.step_up_required)) { await refreshWho(); nav("#/login"); return; }
    launchUi.notes[slug] = launchMessage(which, e);
    renderLaunches();
  }
  // Fixed words for each refusal the server gives a launch control (matched on what it refused), and where to fix
  // it: Billing for credits, Assets for a host's proof or authorization. The step-up answer asks for the
  // authenticator, as a purchase does. The refusals that name a host are matched first and every phrase matched has
  // a space in it, so no host name can be mistaken for another refusal.
  function launchMessage(which, e) {
    var status = e && e.status, data = (e && e.data) || {};
    var why = String(data.error || "").toLowerCase();
    var after = which === "reserve" ? " Nothing was charged." : which === "start" ? "" : " Nothing changed.";
    var billing = { go: "#/billing", goText: "Go to Billing" }, assets = { go: "#/assets", goText: "Go to Assets" };
    function has(s) { return why.indexOf(s) >= 0; }
    function msg(text, where) { return { text: text, go: where ? where.go : null, goText: where ? where.goText : null }; }
    if (status === 401 && data.step_up_required) {
      return msg("For your security, this needs a fresh second-factor check. Verify with your authenticator, then "
        + "try again." + after);
    }
    if (status === 503) return msg("VIGIL is updating. Try again in a few seconds." + after);
    if (status === 429) return msg("Too many attempts — wait a moment and try again." + after);
    if (status === 404 || has("pause/resume is not enabled")) return msg("This is not available right now." + after);
    if (has("insufficient credits")) return msg("Not enough credits to start an assessment. Add credits in Billing.", billing);
    if (has("ownership proof")) {
      return msg("This host's proof of control is missing or has expired. Verify it again in Assets, then launch.", assets);
    }
    if (has("engagement authority")) {
      return msg("Testing is not authorized for this host right now. Verify it again in Assets, confirming you are "
        + "authorized to test it, then launch.", assets);
    }
    if (has("not settled yet")) {
      return msg("An assessment of this host is already in progress. Let it finish, or cancel it if it has not "
        + "started, before launching another.");
    }
    if (has("still finishing")) return msg("An earlier assessment of this host is still finishing. Try again shortly.");
    if (has("may not launch") || has("may not manage launches")) {
      return msg("Your role cannot launch or control assessments. The founder can, and so can a teammate VIGIL has "
        + "made an Operator.");
    }
    if (has("new assessment launches are paused") || has("global cost pool")) {
      return msg("New assessments cannot start right now. Please try again later." + after);
    }
    if (has("line is overdue")) return msg("Your workspace has an invoice past its due date. Settle it before launching "
      + "new assessments.");
    if (has("postpaid credit line")) return msg("Your workspace's credit line has no room for another assessment right now.");
    if (has("trial scans are not available")) return msg("Trial scans are not available yet. Buy credits in Billing to "
      + "run an assessment.", billing);
    if (has("trial covers the trial scan only")) return msg("Your trial covers the trial scan only. Buy credits in "
      + "Billing for other assessments.", billing);
    if (has("registered domain")) return msg("Trial scans need your own registered domain. Buy credits in Billing to "
      + "test this host.", billing);
    if (has("one workspace per domain")) return msg("Trial scans are limited to one workspace per domain. Buy credits "
      + "in Billing to test this host.", billing);
    if (has("trial covers one domain")) return msg("Your trial covers one domain. Buy credits in Billing to test "
      + "another.", billing);
    if (has("paused for today")) return msg("Trial scans are paused for today. Try again later, or buy credits in "
      + "Billing.", billing);
    if (has("has been started")) return msg("This assessment has already started, so it can no longer be cancelled.");
    if (has("cannot be released automatically")) {
      return msg("This launch is cancelled, but its credits cannot be returned automatically right now: they stay "
        + "reserved, not spent, until VIGIL returns them. VIGIL has been alerted.");
    }
    if (has("was cancelled and cannot be started")) {
      return msg("This launch was cancelled, so it cannot start. Its credits stay reserved, not spent, until VIGIL "
        + "returns them.");
    }
    if (has("already been settled")) return msg("This launch has already ended.");
    if (has("billing changed")) {
      return msg("Billing changed after this launch was reserved, so it cannot start. Cancel it (nothing is charged) "
        + "and launch again.");
    }
    if (has("launch product")) return msg("That depth is not available right now. Reload the page and choose again.");
    if (has("is busy")) return msg("VIGIL is busy right now. Try again in a moment." + after);
    if (which === "reserve") return msg("The assessment could not be launched. Nothing was charged. Try again in a moment.");
    if (which === "start") {
      return msg("The assessment could not start. It stays reserved: select Start to try again, or Cancel it.");
    }
    return msg("That did not go through. Nothing changed. Try again in a moment.");
  }
  // ---- end of launching and controlling assessments (C1a) -------------------------------------------------------

  // ---- Monitoring (AEGIS) -------------------------------------------------------------------------------------------
  // #/monitoring, only while the edge has customer monitoring on. GET api/customer/monitoring answers for the SESSION
  // workspace: the hosts with monitoring (grants) and can_manage (the founder or an admin — the server decides); only to
  // such a person also the hosts whose proof of control is current (hosts) and the AEGIS plan (plan: host slots, whether
  // it includes Respond, its period end). Turning monitoring on or changing its mode may need a fresh second factor (the
  // server answers 401 step_up_required); turning it off never does, and is confirmed here first. The page shows only
  // what the server sent, and nothing internal of an event (no record number, report id, certificate hash or org id).
  var MONITORING_ON = pageFlag("monitoring");
  var MON_POLL_MS = 30000;                                // the events refresh this often while the screen is in view
  var mon = { timer: null, gen: 0, loaded: false };
  var MON_MODE = { observe: "Observe", block: "Respond" };
  var MON_ACTION = { block: "Blocked", observe: "Observed", challenge: "Challenged", throttle: "Slowed down",
                     allow: "Allowed" };
  function own(table, key) {                              // the label for a server value; never an inherited member
    var k = String(key == null ? "" : key);
    return Object.prototype.hasOwnProperty.call(table, k) ? table[k] : "";
  }
  function fmtWhen(ts) {
    try { return new Date(Number(ts || 0) * 1000).toISOString().slice(0, 16).replace("T", " ") + " UTC"; }
    catch (e) { return "—"; }
  }

  function viewMonitoring() {
    var holder = h("div#mon-body", {}, loadingHolder("Loading…"));
    mon.loaded = false;
    (async function () {
      var d;
      try { d = await VUI.getJSON(API + "/monitoring"); }
      catch (e) {
        if (here() !== "#/monitoring") return;
        if (e && e.status === 401) { await refreshWho(); nav("#/login"); return; }
        return VUI.mount(holder, h("div.card.cust-soon", { text: "Could not load Monitoring"
          + ((e && e.data && e.data.error) ? ": " + e.data.error : ".") }));
      }
      if (here() !== "#/monitoring") return;              // the customer navigated away before the load resolved
      VUI.mount(holder, monitoringBody(d || {}));
      pollMonEvents();                                    // the events fill in now, then every MON_POLL_MS
    })();
    return shell(h("div", {}, [h("h2", { text: "Monitoring" }),
      h("p.cust-muted", { text: "AEGIS watches live traffic to the hosts your workspace proved and reports attacks as "
        + "they happen. Only this workspace sees its hosts and events." }),
      holder]), "#/monitoring");
  }

  function monitoringBody(d) {
    var rows = monHostRows(d);
    var top = d.can_manage ? monPlanCard(d)
      : h("div.card.cust-soon", { text: "Only the founder or an admin of this workspace can turn monitoring on or "
          + "off. You can see which hosts are monitored and what AEGIS reported." });
    var hosts = rows.length ? h("div.cust-grid", {}, rows.map(function (r) { return monHostCard(r, d); }))
      : h("div.card.cust-soon", { text: d.can_manage
          ? "No host of this workspace has a current proof of control. Monitoring needs a host that shows Verified in Assets."
          : "No host of this workspace is monitored." });
    return h("div", {}, [top, h("h3", { text: "Hosts" }), hosts, h("h3", { text: "Events" }),
      h("div#mon-events", {}, loadingHolder("Loading events…"))]);
  }

  // One row per host: each host with a current proof (sent to a manager only) and each host with monitoring.
  function monHostRows(d) {
    var by = Object.create(null), out = [];
    function row(host) { if (!by[host]) { by[host] = { host: host }; out.push(by[host]); } return by[host]; }
    (d.hosts || []).forEach(function (x) {
      if (x && x.host) { var r = row(String(x.host)); r.verified = true; r.expires_at = x.expires_at; }
    });
    (d.grants || []).forEach(function (g) { if (g && g.host) { row(String(g.host)).grant = g; } });
    return out.sort(function (a, b) { return a.host < b.host ? -1 : (a.host > b.host ? 1 : 0); });
  }
  function monActive(d) { return (d.grants || []).filter(function (g) { return g && g.active; }).length; }

  function monPlanCard(d) {
    var p = d.plan;
    if (!p) {
      var help = h("div#mon-plan-help", {}, h("p.cust-muted", { text: "Checking where to get one…" }));
      monPlanHelp(help);
      return h("div.card", {}, [h("h3", { text: "AEGIS plan" }),
        h("p", { text: "This workspace has no active AEGIS plan, so monitoring cannot be turned on yet." }), help]);
    }
    return h("div.card", {}, [h("h3", { text: "AEGIS plan" }),
      kv("Plan", aegisPlanName(p.host_slots, !!p.respond)),
      kv("Hosts monitored", monActive(d) + " of " + (parseInt(p.host_slots, 10) || 0)),
      kv("Current period ends", fmtDate(p.period_end)),
      h("p.cust-muted", { text: p.respond ? "Observe watches traffic and reports attacks. Respond also blocks them."
        : "Observe watches traffic and reports attacks. Blocking attacks needs an AEGIS Respond plan." })]);
  }
  // Where a workspace without a plan gets one: Billing, but only while Billing really offers an AEGIS plan.
  function monPlanHelp(holder) {
    (async function () {
      var d = null;
      try { d = await VUI.getJSON(API + "/billing/offers"); } catch (e) { d = null; }
      if (here() !== "#/monitoring") return;
      var sold = ((d && d.offers) || []).some(isMonitoringOffer);
      VUI.mount(holder, sold
        ? [h("p.cust-muted", { text: "Choose an AEGIS plan on Billing, then turn monitoring on here." }),
           h("div.cust-mon-actions", {}, monButton("Go to Billing", function () { nav("#/billing"); }))]
        : h("p.cust-muted", { text: "AEGIS plans are not sold in the app yet. To add one to this workspace, "
            + "contact VIGIL." }));
    })();
  }

  function monHostCard(r, d) {
    var g = r.grant, on = !!(g && g.active);
    var badge = on ? h("span.cust-badge.cust-badge-on", { text: "Monitoring · " + (own(MON_MODE, g.mode) || "On") })
      : h("span.cust-badge.cust-badge-off", { text: "Not monitored" });
    var body = [h("div.cust-asset-head", {}, [h("span.host", { text: r.host }), badge])];
    if (on) { body.push(kv("Until", fmtDate(g.not_after))); }
    else if (g) { body.push(h("p.cust-muted", { text: "Monitoring of this host has ended." })); }
    if (r.verified) { body.push(kv("Proof expires", fmtDate(r.expires_at))); }
    else if (d.can_manage) {
      body.push(h("p.cust-muted", { text: "Its proof of control is not current: verify it again in Assets before "
        + "monitoring can be turned on." }));
    }
    if (d.can_manage) {
      var actions = h("div.cust-mon-actions", {});
      VUI.mount(actions, monActions(r, d, actions));
      body.push(actions);
    }
    return h("div.card", {}, body);
  }
  // A manager's choices for one host. Turn on needs a plan, a current proof and a free host on the plan; Respond only
  // when the plan includes it. A monitored host can switch mode (it keeps its place) or be turned off, after a confirm.
  function monActions(r, d, holder) {
    var p = d.plan, g = r.grant, on = !!(g && g.active), out = [];
    if (on) {
      if (p && p.respond && g.mode === "observe") {
        out.push(monButton("Switch to Respond", function (b) { monTurnOn(r.host, "block", b); }));
      }
      if (p && g.mode === "block") {
        out.push(monButton("Switch to Observe", function (b) { monTurnOn(r.host, "observe", b); }));
      }
      out.push(monButton("Turn off", function () { monConfirmOff(r, d, holder); }, "danger"));
    } else if (p && r.verified) {
      if (monActive(d) >= (parseInt(p.host_slots, 10) || 0)) {
        out.push(h("p.cust-muted", { text: "Every host your plan covers is monitored. Turn off another host to "
          + "monitor this one." }));
      } else {
        out.push(monButton("Turn on Observe", function (b) { monTurnOn(r.host, "observe", b); }, "primary"));
        if (p.respond) { out.push(monButton("Turn on Respond", function (b) { monTurnOn(r.host, "block", b); }, "primary")); }
      }
    }
    return out;
  }
  function monButton(label, act, kind) {
    var b = h("button.btn" + (kind ? "." + kind : ""), { type: "button", text: label });
    b.addEventListener("click", function () { act(b); });
    return b;
  }
  // Turning monitoring off is asked here first, in place of the host's buttons; nothing is sent until it is confirmed.
  function monConfirmOff(r, d, holder) {
    VUI.mount(holder, h("div.cust-mon-confirm", { role: "group", "aria-label": "Turn off monitoring" }, [
      h("p", { text: "Stop monitoring " + r.host + "? Its traffic then passes through AEGIS uninspected, and attacks on "
        + "it are no longer reported." }),
      h("div.cust-mon-actions", {}, [
        monButton("Yes, turn off", function (b) { monTurnOff(r.host, b); }, "danger"),
        monButton("Keep monitoring", function () { VUI.mount(holder, monActions(r, d, holder)); }),
      ]),
    ]));
  }
  async function monTurnOn(host, mode, btn) {
    clearErr();
    btn.disabled = true;
    try {
      await VUI.postJSON(API + "/monitoring/authorize", { host: host, mode: mode });
      VUI.toast("Monitoring is on for " + host + " (" + own(MON_MODE, mode) + ").");
      if (here() === "#/monitoring") render();            // show the host's new state
    } catch (e) { btn.disabled = false; await monFailed(e); }
  }
  async function monTurnOff(host, btn) {
    clearErr();
    btn.disabled = true;
    try {
      await VUI.postJSON(API + "/monitoring/revoke", { host: host });
      VUI.toast("Monitoring is off for " + host + ".");
      if (here() === "#/monitoring") render();
    } catch (e) { btn.disabled = false; await monFailed(e); }
  }
  async function monFailed(e) {
    if (e && e.status === 401 && e.data && e.data.step_up_required) {
      return err("For your security, this change to monitoring needs a fresh second-factor check. Verify with your "
        + "authenticator, then try again. Nothing was changed.");
    }
    if (e && e.status === 401) { await refreshWho(); nav("#/login"); return; }
    err("Monitoring was not changed" + ((e && e.data && e.data.error) ? ": " + e.data.error : "."));
  }

  function monEventsList(events) {
    var list = (Array.isArray(events) ? events : []).filter(function (ev) { return ev && typeof ev === "object"; });
    list.sort(function (a, b) { return (Number(b.ts) || 0) - (Number(a.ts) || 0); });     // newest first
    if (!list.length) {
      return h("div.card.cust-soon", { text: "No events yet. When AEGIS reports an attack on a monitored host, it "
        + "appears here." });
    }
    var head = h("tr", {}, ["When", "Host", "Attack", "Result", "AEGIS action"].map(function (t) {
      return h("th", { text: t });
    }));
    var rows = list.map(function (ev) {
      var confirmed = ev.decision === "confirmed";
      return h("tr", {}, [
        h("td", { text: fmtWhen(ev.ts) }), h("td", { text: String(ev.host || "—") }),
        h("td", { text: String(ev.attack_class || "—").replace(/_/g, " ") }),
        h("td", {}, h("span.cust-badge.cust-badge-" + (confirmed ? "attack" : "signal"),
          { text: confirmed ? "Confirmed" : "Not confirmed" })),
        h("td", { text: own(MON_ACTION, ev.action) || "—" }),
      ]);
    });
    return h("div.card.cust-mon-events", {}, h("table.cust-table", {}, [h("thead", {}, head), h("tbody", {}, rows)]));
  }

  // The events refresh politely: every MON_POLL_MS, and only while the Monitoring screen is shown to someone signed in
  // and the page is visible. render() and the page's visibility changes re-decide, so leaving the screen, hiding the
  // page or signing out stops it; an answer that comes back after any of those is dropped (the generation moved on).
  function monVisible() { return MONITORING_ON && authed() && here() === "#/monitoring" && !document.hidden; }
  function startMonPoll() { if (!mon.timer) { mon.timer = setInterval(function () { pollMonEvents(); }, MON_POLL_MS); } }
  function stopMonPoll() { if (mon.timer) { clearInterval(mon.timer); mon.timer = null; } mon.gen++; }
  function syncMonPoll() { if (monVisible()) { startMonPoll(); } else { stopMonPoll(); } }
  function onMonVisibility() { syncMonPoll(); if (monVisible()) { pollMonEvents(); } }
  async function pollMonEvents() {
    if (!monVisible()) { stopMonPoll(); return; }
    var gen = mon.gen, d;
    try { d = await VUI.getJSON(API + "/monitoring/events"); }
    catch (e) {
      if (e && (e.status === 401 || e.status === 404)) { stopMonPoll(); }  // signed out, or monitoring was switched off
      if (e && e.status === 401) { await refreshWho(); return; }
      var box = VUI.$("#mon-events");
      if (box && gen === mon.gen && !mon.loaded) {
        VUI.mount(box, h("div.card.cust-soon", { text: "Events could not be loaded just now. VIGIL tries again shortly." }));
      }
      return;                                             // keep what is shown; the next tick tries again
    }
    if (gen !== mon.gen || !monVisible()) { return; }     // the screen was left, hidden or signed out meanwhile
    var holder = VUI.$("#mon-events");
    if (!holder) { return; }
    mon.loaded = true;
    VUI.mount(holder, monEventsList(d && d.events));
  }

  // ---- Team (VIGIL_CUSTOMER_TEAM_UI): the workspace's members — add, change a role, remove -------------------------
  // Shown only while the edge writes data-team="1"; off, #/team is the "being wired" card it always was and nothing is
  // fetched. The SERVER decides everything: GET api/customer/members lists the session's workspace only, and only to
  // someone who may manage its team (anyone else gets the honest card below). Each change is one request for the
  // session's workspace — never an org this page names: member/add (an existing VIGIL account, named by its email),
  // member/grant (a new role) or member/revoke (Remove, confirmed in the page, never with a browser dialog) — and then
  // the list is read again. Only the roles a customer may grant are offered, and the founder's row has no buttons: only
  // VIGIL changes the founder.
  var TEAM_ON = pageFlag("team");
  var TEAM_ROLES = [["org_admin", "Admin"], ["analyst", "Analyst"], ["viewer", "Viewer"]];
  var ROLE_LABELS = { founder: "Founder", operator: "Operator", org_admin: "Admin", analyst: "Analyst", viewer: "Viewer" };
  function roleLabel(role) {
    var r = String(role || "");
    return Object.prototype.hasOwnProperty.call(ROLE_LABELS, r) ? ROLE_LABELS[r] : (r || "—");
  }
  function teamGrantable(role) {
    for (var i = 0; i < TEAM_ROLES.length; i++) { if (TEAM_ROLES[i][0] === role) return true; }
    return false;
  }
  function teamName(m) { return String((m && (m.email || m.username)) || ""); }
  // A role picker offering exactly the grantable roles. A current role a customer cannot grant (an Operator) is shown
  // as a first, unselectable option, so the row reads truthfully and any change is a deliberate choice.
  function teamRoleSelect(id, current, label) {
    var sel = h("select" + (id ? "#" + id : ""), label ? { "aria-label": label } : {});
    if (current && !teamGrantable(current)) {
      sel.appendChild(h("option", { value: "", text: roleLabel(current), disabled: true }));
    }
    TEAM_ROLES.forEach(function (r) { sel.appendChild(h("option", { value: r[0], text: r[1] })); });
    sel.value = teamGrantable(current) ? current : "";
    return sel;
  }
  // The server's own words for a refusal, without its "denied: " style prefix (while VIGIL restarts: the kit's words).
  function teamWhy(e) {
    var d = (e && e.data) || {};
    if (d.error === "updating") return String((e && e.message) || "");
    var s = String(d.error || "").replace(/^(denied|provision failed|bad request|request failed): /, "");
    return s ? s.charAt(0).toUpperCase() + s.slice(1) : "";
  }
  // True when no answer came back (a 5xx other than "updating", or no response at all): whether the change happened is
  // not known, so the page reads the list again. While VIGIL restarts the request reached nothing.
  function teamUnsure(e) {
    var status = e && e.status;
    return !status || (status >= 500 && !(status === 503 && e.data && e.data.error === "updating"));
  }
  // Why a change did not go through. The provisioner refuses before it writes anything, so a refusal says "Nothing was
  // changed."; when no answer came back that cannot be said — the list is read again instead.
  function teamRefusal(e, name) {
    var d = (e && e.data) || {}, status = e && e.status;
    if (status === 401 && d.step_up_required) {
      return "For your security, changing your team needs a fresh second-factor check. Verify with your "
        + "authenticator, then try again. Nothing was changed.";
    }
    if (status === 429) return "Too many team changes in a short time. Wait a minute, then try again. Nothing was changed.";
    if (teamUnsure(e)) return "VIGIL could not confirm the change. The list shows your team as it is now.";
    if (status === 503) return String(e.message);                      // "updating": the kit's own words
    var why = teamWhy(e);
    if (/last administrator/i.test(why)) {
      return name + " is the last person who can manage this workspace's team. Make another member an Admin first. "
        + "Nothing was changed.";
    }
    return (why ? why.replace(/\.?$/, ".") : "The change was refused.") + " Nothing was changed.";
  }
  function teamNoAccess() {
    return h("div.card.cust-soon", { text: "Only the workspace's founder and admins can see and change its team. Ask "
      + "one of them to add someone or to change a role." });
  }
  function teamRow(m, isMe, act) {
    var name = teamName(m);
    var rows = [
      h("div.cust-member-head", {}, [
        h("strong.cust-member-name", { text: name }),
        isMe ? h("span.chip", { text: "You" }) : null,
        h("span.cust-badge", { text: roleLabel(m.role) }),
      ]),
      m.since ? h("p.cust-muted", { text: "Role since " + fmtDate(m.since) }) : null,
    ];
    if (m.role === "founder") {
      rows.push(h("p.cust-muted", { text: "Only VIGIL changes or removes the founder." }));
      return h("div.card.cust-member", {}, rows);
    }
    if (m.role === "operator") {
      rows.push(h("p.cust-muted", { text: "Only VIGIL makes someone an Operator: after a change, only VIGIL can make "
        + "them one again." }));
    }
    var pick = teamRoleSelect(null, m.role, "New role for " + name);
    var change = h("button.btn", { type: "button", text: "Change role" });
    change.addEventListener("click", function () {
      var role = String(pick.value || "");
      if (!teamGrantable(role) || role === m.role) { act.say("Choose a new role for " + name + " first.", true); return; }
      act.change(m, role, change);
    });
    var ask = h("div.cust-member-confirm", {});
    ask.hidden = true;
    var remove = h("button.btn.danger", { type: "button", text: "Remove" });
    remove.addEventListener("click", function () {
      var yes = h("button.btn.danger", { type: "button", text: "Yes, remove" });
      yes.addEventListener("click", function () { act.remove(m, yes); });
      VUI.mount(ask, [
        h("p", { text: isMe ? "Remove yourself from this workspace? You lose access to it straight away."
                            : "Remove " + name + " from this workspace? They lose access to it straight away." }),
        h("div.cust-member-actions", {}, [yes, h("button.btn", { type: "button", text: "Cancel",
          onClick: function () { ask.hidden = true; VUI.clear(ask); } })]),
      ]);
      ask.hidden = false;
    });
    rows.push(h("div.cust-member-actions", {}, [pick, change, remove]), ask);
    return h("div.card.cust-member", {}, rows);
  }
  function teamMembers(list, act) {
    if (!list.length) return h("div.card.cust-soon", { text: "No members yet." });
    var me = String((state.get().who || {}).username || "");
    return h("div.cust-team-list", {}, list.map(function (m) { return teamRow(m, !!me && m.username === me, act); }));
  }
  function teamAddCard(act) {
    var email = h("input#team-add-email", { type: "email", autocomplete: "off", spellcheck: "false" });
    var role = teamRoleSelect("team-add-role", "viewer");
    var add = h("button.btn.primary", { type: "button", text: "Add member" });
    add.addEventListener("click", function () {
      var e = String(email.value || "").trim().toLowerCase(), r = String(role.value || "");   // as the list shows it
      if (!e) { act.say("Enter your teammate's work email.", true); return; }
      if (!teamGrantable(r)) { act.say("Choose a role: Admin, Analyst or Viewer.", true); return; }
      act.add(e, r, add);
    });
    return h("div.card.cust-team-add", {}, [
      h("h3", { text: "Add member" }),
      h("p.cust-muted", { text: "Your teammate needs a VIGIL account first. Enter the email they sign in to VIGIL with "
        + "and choose their role." }),
      h("label", { for: "team-add-email", text: "Work email" }), email,
      h("label", { for: "team-add-role", text: "Role" }), role,
      h("div.cust-member-actions", {}, [add]),
    ]);
  }
  function viewTeam() {
    var note = h("p.cust-team-msg", { role: "status", "aria-live": "polite" });
    var holder = h("div#cust-team", {}, loadingHolder("Loading…"));
    function say(text, bad) {
      note.textContent = text || "";
      note.className = "cust-team-msg" + (bad ? " bad" : "");
      if (bad) { try { note.scrollIntoView({ block: "nearest" }); } catch (e) { /* a convenience */ } }
    }
    async function load() {
      var d;
      try { d = await VUI.getJSON(API + "/members"); }
      catch (e) {
        if (here() !== "#/team") return;
        if (e && e.status === 401) { await refreshWho(); nav("#/login"); return; }
        if (e && e.status === 403) { VUI.mount(holder, teamNoAccess()); return; }
        VUI.mount(holder, h("div.card.cust-soon", { text: "Could not load your team"
          + (teamWhy(e) ? ": " + teamWhy(e) : ".") }));
        return;
      }
      if (here() !== "#/team") return;                 // the customer navigated away before the load resolved
      VUI.mount(holder, [teamMembers((d && d.members) || [], act), teamAddCard(act)]);
    }
    async function send(path, body, done, name, btn) {
      say("");
      if (btn) btn.disabled = true;
      try { await VUI.postJSON(API + path, body); }
      catch (e) {
        if (btn) btn.disabled = false;
        if (e && e.status === 401 && !(e.data && e.data.step_up_required)) { await refreshWho(); nav("#/login"); return; }
        say(teamRefusal(e, name), true);
        if (teamUnsure(e)) await load();
        return;
      }
      VUI.toast(done);
      await load();
    }
    var act = {
      say: say,
      add: function (email, role, btn) {
        return send("/member/add", { email: email, role: role }, email + " was added as " + roleLabel(role) + ".",
          email, btn);
      },
      change: function (m, role, btn) {
        return send("/member/grant", { member_username: m.username, role: role },
          teamName(m) + " is now " + roleLabel(role) + ".", teamName(m), btn);
      },
      remove: function (m, btn) {
        return send("/member/revoke", { member_username: m.username },
          teamName(m) + " was removed from this workspace.", teamName(m), btn);
      },
    };
    load();
    return shell(h("div", {}, [h("h2", { text: "Team" }), note, holder]), "#/team");
  }

  // ---- notification centre --------------------------------------------------------------------
  // A self-contained bell + unread badge + dropdown panel, fed by polling the tenant-scoped
  // GET api/customer/notifications (the server aggregates findings + billing standing + monitoring,
  // each behind its own permission, scoped to THIS session org — this UI never sends an org id).
  //
  // enable/disable + sound are per-viewer prefs in localStorage; read-state is a per-viewer set of
  // seen ids (namespaced by username so a shared browser never bleeds one account's read-state into
  // another). EVERY storage access is wrapped — the feature works fully with storage unavailable
  // (private window / blocked): prefs default ON, nothing is remembered, the bell still polls + chimes.
  var NTF_POLL_MS = 45000;
  var ntf = { items: [], count: 0, open: false, openUnread: null, started: false, loaded: false,
              timer: null, knownUnread: {}, gen: 0 };
  var _chime = null;

  function lsGet(k, dflt) { try { var v = localStorage.getItem(k); return v == null ? dflt : v; } catch (e) { return dflt; } }
  function lsSet(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* storage off: prefs hold for this load only */ } }
  function ntfEnabled() { return lsGet("vigil.ntf.enabled", "1") !== "0"; }
  function ntfSound() { return lsGet("vigil.ntf.sound", "1") !== "0"; }
  function setNtfEnabled(on) { lsSet("vigil.ntf.enabled", on ? "1" : "0"); }
  function setNtfSound(on) { lsSet("vigil.ntf.sound", on ? "1" : "0"); }
  function seenKey() { var w = state.get().who || {}; return "vigil.ntf.seen." + (w.username || "anon"); }
  function seenIds() { try { var a = JSON.parse(lsGet(seenKey(), "[]")); return Array.isArray(a) ? a : []; } catch (e) { return []; } }
  function seenSet() { var s = {}; seenIds().forEach(function (id) { s[id] = 1; }); return s; }
  function markSeen(ids) {
    var cur = seenIds(), have = {};
    cur.forEach(function (x) { have[x] = 1; });
    (ids || []).forEach(function (id) { if (id && !have[id]) { cur.push(id); have[id] = 1; } });
    if (cur.length > 300) { cur = cur.slice(cur.length - 300); }   // cap — read-state is a convenience, not a ledger
    lsSet(seenKey(), JSON.stringify(cur));
  }

  function sevBucket(sev) {
    var s = String(sev || "").toLowerCase();
    if (s === "critical" || s === "high") return "high";
    if (s === "low" || s === "info" || s === "informational") return "low";
    return "med";
  }
  function sevLabel(sev) { var s = String(sev || "medium").toLowerCase(); return s.charAt(0).toUpperCase() + s.slice(1); }

  function unreadCount() { var seen = seenSet(), n = 0; ntf.items.forEach(function (it) { if (it && it.id && !seen[it.id]) n++; }); return n; }

  function playChime() {
    if (!ntfSound()) return;
    try {
      if (!_chime) { _chime = new Audio("vigil-notify.wav"); _chime.preload = "auto"; }
      _chime.currentTime = 0;
      var p = _chime.play();                     // may reject under the browser autoplay policy until a gesture
      if (p && typeof p.catch === "function") { p.catch(function () {}); }   // the toast still shows — silent
    } catch (e) { /* no audio support: the visible toast + badge still fire */ }
  }

  function startNtf() { if (!ntf.timer) { ntf.timer = setInterval(function () { pollNtf(); }, NTF_POLL_MS); } }
  function stopNtf() { if (ntf.timer) { clearInterval(ntf.timer); ntf.timer = null; } }
  function resetNtf() {   // on logout / account switch — never carry one account's notifications into another
    stopNtf();
    ntf.gen++;            // invalidate any in-flight poll so its late result cannot repopulate ntf.items
    ntf.items = []; ntf.count = 0; ntf.open = false; ntf.openUnread = null;
    ntf.started = false; ntf.loaded = false; ntf.knownUnread = {};
  }
  // Mount/unmount with the session: start polling once signed in + enabled; stop when signed out or disabled.
  function syncNtf() {
    if (authed() && ntfEnabled()) { startNtf(); if (!ntf.started) { pollNtf(); } }
    else { stopNtf(); }
  }

  async function pollNtf() {
    if (!authed() || !ntfEnabled()) { return; }
    ntf.started = true;                           // gate the one auto-poll from syncNtf (the timer drives the rest)
    var gen = ntf.gen;                            // capture; a logout/disable/401 bumps ntf.gen to invalidate this
    var data;
    try { data = await VUI.getJSON(API + "/notifications"); }
    catch (e) {
      if (e && e.status === 401) { resetNtf(); await refreshWho(); }   // session died — boot flow unmounts
      return;                                     // transient error: keep last state, retry next tick (no toast spam)
    }
    // The /notifications read fans out to three upstream relays, so this await is routinely 100s of ms. Drop a
    // STALE response: if the account was signed out/switched or alerts disabled while it was in flight, this
    // result must NOT repopulate ntf.items (cross-account bleed on a shared browser) or chime after a disable.
    if (gen !== ntf.gen || !authed() || !ntfEnabled()) { return; }
    var items = (data && data.notifications) || [];
    var seen = seenSet(), fresh = [];
    items.forEach(function (n) {
      if (!n || !n.id) { return; }
      if (seen[n.id] || ntf.knownUnread[n.id]) { return; }   // already read, or already alerted this session
      fresh.push(n); ntf.knownUnread[n.id] = 1;
    });
    ntf.items = items;
    ntf.count = (data && typeof data.count === "number") ? data.count : items.length;
    if (ntf.loaded && fresh.length) {             // never chime on the first (silent) load after sign-in
      playChime();
      var top = fresh[0];                         // server returns most-severe-first
      VUI.toast(fresh.length > 1 ? (fresh.length + " new notifications") : ("New: " + (top.title || "notification")));
    }
    ntf.loaded = true;
    renderBell();
  }

  function toggleNtf() {
    var wasOpen = ntf.open;
    ntf.open = !wasOpen;
    if (ntf.open) {
      if (ntfEnabled()) {                         // opening = reading: snapshot what's unread NOW (for the
        var seen = seenSet(); ntf.openUnread = {};             // highlight), then clear the badge
        ntf.items.forEach(function (n) { if (n && n.id && !seen[n.id]) ntf.openUnread[n.id] = 1; });
        markSeen(ntf.items.map(function (n) { return n && n.id; }));
      }
    } else { ntf.openUnread = null; }
    renderBell();
  }
  function markAllRead() { markSeen(ntf.items.map(function (n) { return n && n.id; })); ntf.openUnread = {}; renderBell(); }

  function toggleRow(label, on, onChange, disabled) {
    var cb = h("input", { type: "checkbox" });
    cb.checked = !!on; if (disabled) { cb.disabled = true; }
    cb.addEventListener("change", function () { onChange(cb.checked); });
    return h("label.cust-ntf-toggle" + (disabled ? ".disabled" : ""), {}, [cb, h("span", { text: label })]);
  }

  function ntfPanel() {
    var enabled = ntfEnabled();
    var head = h("div.cust-ntf-head", {}, [
      h("strong", { text: "Notifications" }), h("span.spacer"),
      (enabled && ntf.items.length) ? h("button.cust-ntf-link", { type: "button", text: "Mark all read", onClick: markAllRead }) : null,
    ]);
    var prefs = h("div.cust-ntf-prefs", {}, [
      toggleRow("Enabled", enabled, function (on) {
        setNtfEnabled(on);
        // disable also bumps the generation so a poll already in flight cannot chime/toast after alerts are off
        if (on) { ntf.started = false; startNtf(); pollNtf(); } else { ntf.gen++; stopNtf(); }
        renderBell();
      }),
      toggleRow("Sound", ntfSound(), function (on) { setNtfSound(on); }, !enabled),
    ]);
    var body;
    if (!enabled) {
      body = h("div.cust-ntf-empty", { text: "Notifications are off. Turn them on to be alerted about findings, "
        + "assessment outcomes, billing and monitoring for this workspace." });
    } else if (!ntf.items.length) {
      body = h("div.cust-ntf-empty", { text: "You're all caught up." });
    } else {
      body = h("div.cust-ntf-list", {}, ntf.items.map(function (n) {
        var unread = ntf.openUnread ? !!ntf.openUnread[n.id] : false;
        return h("div.cust-ntf-item" + (unread ? ".unread" : ""), {}, [
          h("span.cust-ntf-sev.sev-" + sevBucket(n.severity), { text: sevLabel(n.severity) }),
          h("div.cust-ntf-txt", {}, [
            h("div.cust-ntf-title", { text: n.title || "Notification" }),
            n.body ? h("div.cust-ntf-body", { text: n.body }) : null,
            n.kind ? h("div.cust-ntf-kind", { text: String(n.kind) }) : null,
          ]),
        ]);
      }));
    }
    return h("div.cust-ntf-panel", { role: "dialog", "aria-label": "Notifications" }, [head, prefs, body]);
  }

  function ntfWidget() {
    if (!authed()) { return null; }
    var enabled = ntfEnabled();
    var unread = enabled ? unreadCount() : 0;
    var bell = h("button.cust-bell" + (enabled ? "" : ".off"), {
      type: "button", title: enabled ? "Notifications" : "Notifications are off",
      "aria-label": "Notifications" + (unread > 0 ? " (" + unread + " unread)" : ""),
      "aria-expanded": ntf.open ? "true" : "false", onClick: toggleNtf,
    }, [
      VUI.icon("bell"),
      (unread > 0) ? h("span.cust-bell-badge", { text: unread > 99 ? "99+" : String(unread) }) : null,
    ]);
    return h("div.cust-ntf" + (ntf.open ? ".open" : ""), { id: "cust-ntf" }, [bell, ntf.open ? ntfPanel() : null]);
  }

  // Keep --cust-topbar-h in sync with the real (possibly wrapped) topbar height, so the fixed panel always
  // drops just below the topbar at any viewport width. Cheap; called on render, on open, and on resize.
  function setTopbarVar() {
    try {
      var tb = VUI.$(".cust-topbar");
      document.documentElement.style.setProperty("--cust-topbar-h", (tb && tb.offsetHeight ? tb.offsetHeight : 64) + "px");
    } catch (e) { /* no DOM / detached: the CSS fallback (72px) still positions the panel */ }
  }

  // In-place refresh of ONLY the bell subtree (a poll must not re-render the whole page). shell() places
  // #cust-ntf; if it is not mounted (logged out), this is a no-op and the next full render handles it.
  function renderBell() {
    setTopbarVar();
    var host = VUI.$("#cust-ntf");
    if (!host || !host.parentNode) { return; }
    var w = ntfWidget();
    if (w) { host.parentNode.replaceChild(w, host); } else { host.remove(); }
  }

  // ---- shell --------------------------------------------------------------------------------------
  function navLink(label, hash) {
    var cur = (location.hash === hash || (hash === "#/" && (location.hash === "" || location.hash === "#")));
    var props = { type: "button", text: label, onClick: function () { nav(hash); } };
    if (cur) props["aria-current"] = "page";
    if (GUIDE_ON) props.dataset = { route: hash };          // the tour lights up the tab a step happens on
    return h("button.cust-nav-link", props);
  }

  function shell(inner, current) {
    var w = state.get().who || {};
    var links = authed()
      ? [navLink("Overview", "#/"), navLink("Billing", "#/billing"), navLink("Invoices", "#/invoices"),
         navLink("Assets", "#/assets"), navLink("Assessments", "#/assessments"), navLink("Team", "#/team")]
        .concat(MONITORING_ON ? [navLink("Monitoring", "#/monitoring")] : [])
        .concat(GUIDE_ON ? [navLink("Guide", "#/guide")] : [])
      : [];
    var right = authed()
      ? (SECURITY_ON ? accountLinks(w)
        : h("button.cust-nav-link", { type: "button", text: "Sign out (" + (w.username || "") + ")", onClick: doLogout }))
      : h("button.cust-nav-link", { type: "button", text: "Sign in", onClick: function () { nav("#/login"); } });
    return h("div.cust-shell", {}, [
      h("div.cust-topbar", {}, [
        // the owner's wordmark: white on the dark theme, the dark artwork on the light one (components.css)
        h("span.brand", {}, [
          h("img.vigil-logo.for-dark", { src: "brand/vigil-wordmark-white.svg", alt: "VIGIL", width: "99", height: "22" }),
          h("img.vigil-logo.for-light", { src: "brand/vigil-wordmark.svg", alt: "VIGIL", width: "99", height: "22" }),
        ]),
        h("nav", {}, links),
        h("span.spacer"),
        authed() ? ntfWidget() : null,
        right,
      ]),
      h("div#cust-main", {}, inner),
    ]);
  }

  // With the security screens on, the top bar's right side is the account's name (it opens Account security) and Sign out.
  function accountLinks(w) {
    var name = String(w.username || "");
    var me = navLink(name, "#/security");
    me.setAttribute("title", "Account security");
    me.setAttribute("aria-label", "Account security (" + name + ")");
    return [me, h("button.cust-nav-link", { type: "button", text: "Sign out", onClick: doLogout })];
  }

  async function doLogout() {
    var posted = true;
    try { await VUI.postJSON(API + "/logout", {}); } catch (e) { posted = false; }
    resetNtf();                                  // drop this account's notifications before reflecting the session
    // delete this origin's CacheStorage (the worker's shell): nothing of the app stays behind on a shared device
    var pwa = window.VIGIL_PWA;
    if (pwa && typeof pwa.clearCaches === "function") { try { await pwa.clearCaches(); } catch (e) { /* best effort */ } }
    await refreshWho();                          // reflect the ACTUAL server session — never assume it severed
    if (authed()) {
      // the logout POST did not take (network error / gate refusal / revoke error) and the cookie is STILL
      // live — do NOT show "Signed out": that would strand a live session on a shared machine. Tell the truth.
      nav("#/");
      err("Sign-out did not complete — you are still signed in. Please try again.");
    } else {
      nav("#/login");
      if (posted) { VUI.toast("Signed out"); }
    }
  }

  // ---- misc ---------------------------------------------------------------------------------------
  function clearErr() { if (VUI.clearErrorBanner) VUI.clearErrorBanner(); }   // kit API takes no arg
  function authMsg(e, fallback) {
    if (e && e.data && e.data.error) return String(e.data.error);
    if (e && e.status === 429) return "Too many attempts — wait a moment and try again.";
    return fallback;
  }

  // ---- router -------------------------------------------------------------------------------------
  var ROUTES = {
    "#/": function () { return authed() ? viewDashboard() : viewLogin(); },
    "#/login": function () { return authed() ? viewDashboard() : viewLogin(); },
    "#/signup": function () { return authed() ? viewDashboard() : viewSignup(); },
    "#/recover": function () { return authed() ? viewDashboard() : viewRecover(); },
    "#/google-code": function () { return authed() ? viewDashboard() : viewGoogleCode(); },
    "#/billing": function () { return authed() ? viewBilling() : viewLogin(); },
    "#/billing/return": function () { return authed() ? viewBillingReturn() : viewLogin(); },
    "#/invoices": function () { return authed() ? viewInvoices() : viewLogin(); },
    "#/assets": function () { return authed() ? viewAssets() : viewLogin(); },
    "#/assessments": function () { return authed() ? viewAssessments() : viewLogin(); },
    "#/team": function () { return authed() ? (TEAM_ON ? viewTeam() : viewSoon("Team")) : viewLogin(); },
    // monitoring off: #/monitoring is the home screen, exactly as any unknown route is
    "#/monitoring": function () { return authed() ? (MONITORING_ON ? viewMonitoring() : viewDashboard()) : viewLogin(); },
    // the guide off: #/guide is the home screen, exactly as any unknown route is
    "#/guide": function () { return authed() ? (GUIDE_ON ? viewGuideScreen() : viewDashboard()) : viewLogin(); },
    // the security screens off: #/security is the home screen, exactly as any unknown route is
    "#/security": function () { return authed() ? (SECURITY_ON ? viewSecurityScreen() : viewDashboard()) : viewLogin(); },
  };
  // The hash is user-controlled, so it never becomes the lookup key: routeFor() returns OUR OWN route name that
  // equals the hash's path (else home). Only a constant from this table ever indexes ROUTES, so a hostile hash
  // ("#constructor", "__proto__", "toString", ...) can never reach an inherited member (CodeQL
  // js/unvalidated-dynamic-method-call).
  var ROUTE_KEYS = Object.keys(ROUTES);
  function routeFor(path) {
    for (var i = 0; i < ROUTE_KEYS.length; i++) { if (ROUTE_KEYS[i] === path) return ROUTE_KEYS[i]; }
    return "#/";
  }

  // The edge sends a Google sign-in that did not complete back to the app root as #oidc=err (never why): say so
  // once and show the sign-in screen. The fragment is replaced, so a reload does not repeat the message.
  function googleError() {
    if (location.hash !== "#oidc=err") return false;
    try { history.replaceState(null, "", location.pathname + location.search + "#/login"); }
    catch (e) { location.hash = "#/login"; }
    err("Google sign-in did not complete. Try again, or sign in with your email and password.");
    return true;
  }

  function render() {
    if (!state.get().booted) { VUI.mount(root, h("div.cust-shell", {}, loadingHolder("Loading…"))); return; }
    googleError();
    var hash = location.hash || "#/";
    var key = hash.split("?")[0];
    var view = ROUTES[routeFor(key)];
    ntf.open = false;              // a route change closes any open panel (the shell is rebuilt below)
    VUI.mount(root, view());
    setTopbarVar();                // the topbar just (re)mounted — pin the notification panel below it
    syncNtf();                     // start/stop the notification poll to match the live session + pref
    syncMonPoll();                 // monitoring on: the events refresh only while their screen is in view
    maybeOpenTour();               // the guide on: the first-sign-in tour (once per account in this browser)
  }

  window.addEventListener("hashchange", render);
  // back in the installed app after Google sign-in finished in the browser: show the code box
  document.addEventListener("visibilitychange", function () { if (!document.hidden) resumeHandoff(); });
  window.addEventListener("pageshow", function () { resumeHandoff(); });
  window.addEventListener("resize", setTopbarVar);   // keep the fixed notification panel pinned below the topbar
  if (LAUNCH_ON) {                                   // C1a: the launch list refreshes only on a visible Assessments
    window.addEventListener("hashchange", onLaunchRoute);
    document.addEventListener("visibilitychange", onLaunchVisibility);
  }
  // monitoring on: the events stop refreshing while the page is hidden, and refresh at once when it is back in view
  if (MONITORING_ON) { document.addEventListener("visibilitychange", onMonVisibility); }
  state.sub(render);

  // ---- boot ---------------------------------------------------------------------------------------
  (async function boot() {
    render();            // "Loading…" shell (VUI is guaranteed present — guarded at module init above)
    await refreshWho();  // flips booted -> render() via the store subscription
    resumeHandoff();     // a Google sign-in started in this installed app and not yet finished: the code box
  })();
})();
