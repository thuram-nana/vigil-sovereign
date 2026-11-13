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
  var root = document.getElementById("app");
  // Fail-to-DEGRADE before the first VUI.* dereference: if the shared kit (ui.js) did not load/parse, VUI is
  // undefined and the very next VUI call (store(), below) would throw at module init, aborting the whole IIFE
  // and leaving a blank page (noscript does not fire with JS enabled). Show the honest message and stop.
  if (!VUI) { if (root) { root.textContent = "VIGIL could not load its interface. Please reload."; } return; }
  // Cookie-auth plane: no embedded/sessionStorage token. VUI.postJSON still sends X-Requested-With + cookie.
  window.VIGIL_CFG = { token: "", api: {} };
  var API = "api/customer"; // relative to the mount
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
  function offerLine(o) {
    if (o.kind === TOPUP) return (o.credits != null ? String(o.credits) + " credits" : "Credit top-up");
    var per = o.period_days ? " every " + String(o.period_days) + " days" : "";
    return "Plan: " + String(o.allotment != null ? o.allotment : "") + " credits" + per;
  }
  async function startCheckout(o, btn) {
    btn.disabled = true;
    try {
      var r = await VUI.postJSON(API + "/billing/checkout", { price_id: o.price_id });
      if (!r || !isCheckoutUrl(r.checkout_url)) {
        err("The payment link we received was not a secure https link, so we did not open it. Nothing was charged.");
        btn.disabled = false; return;
      }
      location.assign(r.checkout_url);            // leave for the processor's hosted page
    } catch (e) {
      btn.disabled = false;
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
      // a live plan, or a plan checkout still in progress (not yet drained): checkout refuses a second plan.
      var noPlan = !!(d && (d.has_active_plan || d.plan_checkout_pending));
      var offers = ((d && d.offers) || []).filter(function (o) { return !(noPlan && o.kind !== TOPUP); });
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

  // ---- Assessments: read-only results (operator-role only; org_admin sees the honest 403 card). Launching a
  //      NEW assessment arrives with the run driver (K4), so it is not offered here yet. --------------------
  function viewAssessments() {
    return dataView("#/assessments", "Assessments", API + "/assessments", function (d) {
      var items = (d && d.assessments) || [];
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
    VUI.mount(holder, h("p.cust-muted", { text: "Loading findings for " + host + "…" }));
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
        authed() ? ntfWidget() : null,
        right,
      ]),
      h("div#cust-main", {}, inner),
    ]);
  }

  async function doLogout() {
    var posted = true;
    try { await VUI.postJSON(API + "/logout", {}); } catch (e) { posted = false; }
    resetNtf();                                  // drop this account's notifications before reflecting the session
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
    "#/billing": function () { return authed() ? viewBilling() : viewLogin(); },
    "#/billing/return": function () { return authed() ? viewBillingReturn() : viewLogin(); },
    "#/invoices": function () { return authed() ? viewInvoices() : viewLogin(); },
    "#/assets": function () { return authed() ? viewAssets() : viewLogin(); },
    "#/assessments": function () { return authed() ? viewAssessments() : viewLogin(); },
    "#/team": function () { return authed() ? viewSoon("Team") : viewLogin(); },
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

  function render() {
    if (!state.get().booted) { VUI.mount(root, h("div.cust-shell", {}, h("p.cust-muted", { text: "Loading…" }))); return; }
    var hash = location.hash || "#/";
    var key = hash.split("?")[0];
    var view = ROUTES[routeFor(key)];
    ntf.open = false;              // a route change closes any open panel (the shell is rebuilt below)
    VUI.mount(root, view());
    setTopbarVar();                // the topbar just (re)mounted — pin the notification panel below it
    syncNtf();                     // start/stop the notification poll to match the live session + pref
  }

  window.addEventListener("hashchange", render);
  window.addEventListener("resize", setTopbarVar);   // keep the fixed notification panel pinned below the topbar
  state.sub(render);

  // ---- boot ---------------------------------------------------------------------------------------
  (async function boot() {
    render();            // "Loading…" shell (VUI is guaranteed present — guarded at module init above)
    await refreshWho();  // flips booted -> render() via the store subscription
  })();
})();
