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
 */
(function () {
  "use strict";
  var VUI = window.VUI;
  // Cookie-auth plane: no embedded/sessionStorage token. VUI.postJSON still sends X-Requested-With + cookie.
  window.VIGIL_CFG = { token: "", api: {} };
  var API = "api/customer"; // relative to the mount

  var root = document.getElementById("app");
  var state = VUI.store({ who: null, booted: false });

  // ---- tiny helpers -------------------------------------------------------------------------------
  function h() { return VUI.h.apply(null, arguments); }
  function nav(hash) { if (location.hash === hash) render(); else location.hash = hash; }
  function authed() { var w = state.get().who; return !!(w && w.authenticated); }

  function field(id, label, type) {
    return [h("label", { for: id, text: label }),
            h("input#" + id, { type: type || "text", autocomplete: "off", spellcheck: "false" })];
  }
  function val(id) { var el = VUI.$("#" + id); return el ? String(el.value || "").trim() : ""; }
  function err(msg) { VUI.errorBanner(root, msg); }
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
      field("login-email", "Email", "email"),
      field("login-password", "Password", "password"),
      h("div.row", {}, [
        h("button.btn.btn-primary", { type: "button", text: "Sign in", onClick: doLogin }),
        h("button.cust-nav-link", { type: "button", text: "Create an account", onClick: function () { nav("#/signup"); } }),
      ]),
    ]);
    return shell(form, "#/login");
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
      h("p.muted", { text: "We email you a single-use verification link. Your account and workspace are "
        + "owner-signed on confirmation — this page never grants access by itself." }),
      field("su-email", "Work email", "email"),
      h("div.row", {}, [
        h("button.btn.btn-primary", { type: "button", text: "Send verification", onClick: doSignupRequest }),
        h("button.cust-nav-link", { type: "button", text: "Back to sign in", onClick: function () { nav("#/login"); } }),
      ]),
      h("div#su-confirm"),
    ]);
    return shell(form, "#/signup");
  }

  async function doSignupRequest() {
    clearErr();
    var email = val("su-email");
    if (!email) { return err("Enter your email."); }
    try {
      var r = await VUI.postJSON(API + "/signup/request", { email: email });
      // The token is delivered by email. A dev edge MAY echo it (explicit, governed flag) to speed local
      // testing; if present we prefill, otherwise we ask the customer to paste the link's token.
      var devToken = (r && (r.token || r.dev_token)) || "";
      VUI.mount(VUI.$("#su-confirm"), confirmBlock(devToken));
      VUI.toast("Check your email for the verification link.");
    } catch (e) { err(authMsg(e, "Could not start signup.")); }
  }

  function confirmBlock(devToken) {
    var box = h("div", {}, [
      h("hr"),
      h("p.muted", { text: "Paste the token from the email, pick a password, and name your workspace." }),
      field("su-token", "Verification token", "text"),
      field("su-password", "Choose a password", "password"),
      field("su-org", "Workspace name", "text"),
      h("div.row", {}, [
        h("button.btn.btn-primary", { type: "button", text: "Create account", onClick: doSignupConfirm }),
      ]),
    ]);
    if (devToken) { setTimeout(function () { var t = VUI.$("#su-token"); if (t) t.value = devToken; }, 0); }
    return box;
  }

  async function doSignupConfirm() {
    clearErr();
    var token = val("su-token"), password = val("su-password"), org = val("su-org");
    if (!token || !password || !org) { return err("Fill in the token, password, and workspace name."); }
    try {
      var r = await VUI.postJSON(API + "/signup/confirm", { token: token, password: password, org_name: org });
      if (r && r.username) { await refreshWho(); nav("#/"); VUI.toast("Welcome to VIGIL"); }
      else { err("Could not complete signup."); }
    } catch (e) { err(authMsg(e, "Could not complete signup.")); }
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
    var holder = h("div#cust-data", {}, h("p.cust-muted", { text: "Loading…" }));
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
      ]);
    });
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

  // ---- shell --------------------------------------------------------------------------------------
  function navLink(label, hash) {
    var cur = (location.hash === hash || (hash === "#/" && (location.hash === "" || location.hash === "#")));
    var props = { type: "button", text: label, onClick: function () { nav(hash); } };
    if (cur) props["aria-current"] = "page";
    return h("button.cust-nav-link", props);
  }

  function shell(inner, current) {
    var w = state.get().who || {};
    var links = authed()
      ? [navLink("Overview", "#/"), navLink("Billing", "#/billing"), navLink("Invoices", "#/invoices"),
         navLink("Assets", "#/assets"), navLink("Assessments", "#/assessments"), navLink("Team", "#/team")]
      : [];
    var right = authed()
      ? h("button.cust-nav-link", { type: "button", text: "Sign out (" + (w.username || "") + ")", onClick: doLogout })
      : h("button.cust-nav-link", { type: "button", text: "Sign in", onClick: function () { nav("#/login"); } });
    return h("div.cust-shell", {}, [
      h("div.cust-topbar", {}, [
        h("span.brand", { text: "VIGIL" }),
        h("nav", {}, links),
        h("span.spacer"),
        right,
      ]),
      h("div#cust-main", {}, inner),
    ]);
  }

  async function doLogout() {
    try { await VUI.postJSON(API + "/logout", {}); } catch (e) { /* best-effort */ }
    await refreshWho();
    nav("#/login");
    VUI.toast("Signed out");
  }

  // ---- misc ---------------------------------------------------------------------------------------
  function clearErr() { if (VUI.clearErrorBanner) VUI.clearErrorBanner(root); }
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
    "#/billing": function () { return authed() ? viewBilling() : viewLogin(); },
    "#/invoices": function () { return authed() ? viewInvoices() : viewLogin(); },
    "#/assets": function () { return authed() ? viewSoon("Assets") : viewLogin(); },
    "#/assessments": function () { return authed() ? viewSoon("Assessments") : viewLogin(); },
    "#/team": function () { return authed() ? viewSoon("Team") : viewLogin(); },
  };

  function render() {
    if (!state.get().booted) { VUI.mount(root, h("div.cust-shell", {}, h("p.cust-muted", { text: "Loading…" }))); return; }
    var hash = location.hash || "#/";
    var key = hash.split("?")[0];
    var view = ROUTES[key] || ROUTES["#/"];
    VUI.mount(root, view());
  }

  window.addEventListener("hashchange", render);
  state.sub(render);

  // ---- boot ---------------------------------------------------------------------------------------
  (async function boot() {
    if (!VUI) { root.textContent = "VIGIL could not load its UI kit."; return; }
    render();            // "Loading…" shell
    await refreshWho();  // flips booted -> render() via the store subscription
  })();
})();
