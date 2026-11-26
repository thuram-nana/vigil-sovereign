/* VIGIL customer app — Data rights (legal/governance S3): a Settings sub-screen that states the customer's data
 * rights in the EXISTING published words of the Privacy notice and Terms of Service, names the 30-day response SLA and
 * the data-subject contact, lets the customer EXPORT their own workspace's non-secret records, and RECORD a
 * close-account / deletion request.
 *
 * Shown only while the edge writes data-data-rights="1" into the page (VIGIL_CUSTOMER_DATA_RIGHTS, default OFF); app.js
 * decides that and calls in here. Like security.js and guide.js, this file only DEFINES things: nothing runs at load,
 * nothing is fetched, nothing is stored. Every element is built with the UI kit's h() (passed in) or DOM calls — no
 * HTML string is ever parsed, no inline script or style — so the strict CSP holds.
 *
 * The rights copy below is quoted VERBATIM from VIGIL's published Privacy notice and Terms of Service — it is not a
 * reworded or invented restatement. The only new, owner-decided copy is the 30-day response SLA, passed in from the
 * server (config.CUSTOMER_DATA_RIGHTS_SLA_DAYS) so the screen, the recorded request and the owner notification all
 * state the same figure.
 *
 * NO NEW AUTHORITY, NO MUTATION OF ORG DATA. "Export my data" is a READ (GET api/customer/data-rights/export) of the
 * same tenant-scoped, redacted invoices / usage / findings the other screens show — it changes nothing and leaks no
 * secret. "Request account deletion" records ONE owner-signed append-only request (POST api/customer/data-rights/
 * request); it unlocks nothing by itself and does NOT erase the immutable signed history — that is the owner-gated
 * hard-prune (VAULT-PRUNE) process, which the screen says plainly.
 */
(function () {
  "use strict";

  var API_DEFAULT = "api/customer";
  var SLA_DEFAULT = 30;
  var CONTACT_DEFAULT = "info@sigilsovereign.com";

  function kit(env) { return (env && env.VUI) || window.VUI; }
  function api(env) { return (env && env.api) || API_DEFAULT; }

  // The published rights copy, quoted VERBATIM from the source documents (never reworded here).
  var QUOTES = [
    { from: "From VIGIL's Privacy notice (Your rights):",
      text: "You can ask us for access to, correction of, or deletion of your personal data at "
        + CONTACT_DEFAULT + "." },
    { from: "From VIGIL's Terms of Service, section 14:",
      text: "You may stop using the Service at any time, and you may ask us to close your account by contacting "
        + CONTACT_DEFAULT + ". Cancel any plan first so that it does not renew." },
    { from: "From VIGIL's Privacy notice (Retention, and after your account closes):",
      text: "Your other data is not deleted automatically when the workspace closes. Ask us at " + CONTACT_DEFAULT
        + " to delete it: we will delete the data that can be deleted, and tell you what we kept and why." },
    { from: "From VIGIL's Privacy notice (Retention, and after your account closes):",
      text: "The workspace's billing records (its credit ledger, invoices and usage records) are kept as append-only, "
        + "signed history, so that they cannot be silently changed; no customer can read them through the Service any "
        + "more. Other records of accounts and findings are kept in the same kind of ledger and cannot be deleted one "
        + "by one." },
  ];

  /** A generated idempotency key for a request (so a double-submit records ONE row). crypto.randomUUID where it
   * exists, else a timestamp + random fallback; the server treats it only as an opaque idempotency key. */
  function newRequestId() {
    try {
      if (window.crypto && typeof window.crypto.randomUUID === "function") { return window.crypto.randomUUID(); }
    } catch (e) { /* fall through */ }
    return "req-" + Date.now() + "-" + Math.floor(Math.random() * 1e9).toString(36);
  }

  function viewDataRights(env) {
    var h = (env && env.h) || window.VUI.h, VUI = kit(env), API = api(env);
    var nav = (env && env.nav) || function () {};
    var loading = (env && env.loading) || function (t) { return h("p", { text: t || "Loading…" }); };
    var slaDays = SLA_DEFAULT, contact = CONTACT_DEFAULT;

    // ---- the published rights (verbatim quotes) + the owner-decided SLA -------------------------------------------
    function rightsCard() {
      var rows = [h("h3", { text: "Your data rights" }),
        h("p.cust-muted", { text: "In VIGIL's own published words:" })];
      QUOTES.forEach(function (q) {
        rows.push(h("figure.cust-data-rights-quote", {}, [
          h("blockquote", { text: q.text }),
          h("figcaption.cust-muted", { text: q.from }),
        ]));
      });
      return h("div.card.cust-data-rights-rights", {}, rows);
    }
    function slaCard() {
      return h("div.card.cust-data-rights-sla", {}, [
        h("h3", { text: "How to exercise them" }),
        h("p.cust-data-rights-sla-line", { text: "VIGIL responds to a data-rights request — access, correction, "
          + "deletion or export — within " + slaDays + " days." }),
        h("p", {}, [h("span", { text: "Contact: " }),
          h("a.cust-data-rights-contact", { href: "mailto:" + contact, text: contact })]),
        h("p.cust-muted", { text: "Deleting records from our immutable, signed history is the owner-gated hard-prune "
          + "(VAULT-PRUNE) process, not an instant erase. Recording a request here does not erase the spine; it is "
          + "what we act on." }),
      ]);
    }

    // ---- Export my data: a READ of the workspace's own non-secret records, offered as a download -----------------
    async function doExport(btn) {
      if (btn) { btn.disabled = true; }
      try {
        var r = await VUI.getJSON(API + "/data-rights/export");
        offerDownload(r);
        VUI.toast("Your data export is ready");
      } catch (e) {
        if (e && e.status === 401) { if (env && env.onAuthLost) { env.onAuthLost(); } return; }
        if (e && e.status === 429) { VUI.toast("Too many export requests — wait a moment and try again.", true); return; }
        VUI.toast("Your data could not be exported right now. Please try again.", true);
      } finally {
        if (btn) { btn.disabled = false; }
      }
    }
    // Hand the JSON to the browser as a file, without any network: a Blob + object URL on an <a download>. Guarded so a
    // browser (or the test DOM) without these APIs simply shows the data inline instead of crashing.
    function offerDownload(data) {
      var text = JSON.stringify(data, null, 2);
      try {
        var blob = new Blob([text], { type: "application/json" });
        var url = URL.createObjectURL(blob);
        var a = document.createElement("a");
        a.href = url; a.download = "vigil-data-export.json";
        document.body.appendChild(a); a.click(); a.remove();
        setTimeout(function () { try { URL.revokeObjectURL(url); } catch (e) { /* best effort */ } }, 0);
      } catch (e) {
        var holder = VUI.$(".cust-data-rights-export-out");
        if (holder) { VUI.mount(holder, h("pre.cust-data-rights-export-text", { text: text })); }
      }
    }

    // ---- Request account deletion: record ONE owner-signed append-only request ------------------------------------
    function actionsCard() {
      var confirmHolder = h("div.cust-data-rights-confirm", {});
      var exportOut = h("div.cust-data-rights-export-out", {});
      var exportBtn = h("button.btn.cust-data-rights-export",
        { type: "button", text: "Export my data", onClick: function () { return doExport(exportBtn); } });
      var deleteBtn = h("button.btn.cust-data-rights-delete",
        { type: "button", text: "Request account deletion", onClick: function () { askConfirm(confirmHolder); } });
      return h("div.card.cust-data-rights-actions", {}, [
        h("h3", { text: "Do it now" }),
        h("p.cust-muted", { text: "Export your workspace's own non-secret records (invoices, usage and findings), or "
          + "record a close-account / deletion request for us to act on." }),
        h("div.row", {}, [exportBtn, deleteBtn]),
        exportOut,
        confirmHolder,
      ]);
    }
    // The confirm step appears only after a click (never in the initial render): a short inline confirmation, so a
    // mis-click never records a deletion request.
    function askConfirm(holder) {
      var yes = h("button.btn.cust-data-rights-delete-confirm", { type: "button", text: "Confirm deletion request",
        onClick: function () { return doDeleteRequest(holder, yes); } });
      var no = h("button.btn.cust-data-rights-delete-cancel", { type: "button", text: "Cancel",
        onClick: function () { VUI.mount(holder, h("span")); } });
      VUI.mount(holder, h("div.cust-data-rights-confirm-box", {}, [
        h("p", { text: "Record a request to close this account and delete your data? We will respond within "
          + slaDays + " days. This does not erase the signed history by itself." }),
        h("div.row", {}, [yes, no]),
      ]));
    }
    async function doDeleteRequest(holder, btn) {
      if (btn) { btn.disabled = true; }
      try {
        var r = await VUI.postJSON(API + "/data-rights/request",
          { kind: "close_account", request_id: newRequestId() });
        var note = (r && r.note) || ("Your request is recorded. We will respond within " + slaDays + " days.");
        VUI.mount(holder, h("p.cust-data-rights-recorded", { role: "status", text: note }));
        VUI.toast(r && r.recorded === false ? "Request already recorded" : "Deletion request recorded");
        loadRequests();                              // reflect the new row in the list
      } catch (e) {
        if (btn) { btn.disabled = false; }
        if (e && e.status === 401) { if (env && env.onAuthLost) { env.onAuthLost(); } return; }
        VUI.toast("Your request could not be recorded. Please try again.", true);
      }
    }

    // ---- prior requests (the one read the screen fires on arrival) -------------------------------------------------
    var requestsHolder = h("div.cust-data-rights-requests", {});
    function renderRequests(reqs) {
      if (!reqs || !reqs.length) {
        return h("p.cust-muted", { text: "You have not recorded any data-rights requests yet." });
      }
      return h("ul.cust-data-rights-request-list", {}, reqs.map(function (q) {
        var when = q && q.created_at ? new Date(q.created_at * 1000).toISOString().slice(0, 10) : "";
        var label = (q && q.kind === "close_account") ? "Close-account / deletion request" : "Data export";
        return h("li.cust-data-rights-request", {}, [
          h("span.cust-data-rights-request-kind", { text: label }),
          when ? h("span.cust-muted", { text: " — " + when }) : null,
        ]);
      }));
    }
    async function loadRequests() {
      try {
        var r = await VUI.getJSON(API + "/data-rights");
        if (r && typeof r.sla_days === "number") { slaDays = r.sla_days; }
        if (r && typeof r.contact === "string" && r.contact) { contact = r.contact; }
        VUI.mount(requestsHolder, renderRequests(r && r.requests));
      } catch (e) {
        if (e && e.status === 401) { if (env && env.onAuthLost) { env.onAuthLost(); } return; }
        VUI.mount(requestsHolder, h("p.cust-muted", { text: "Your previous requests could not be loaded." }));
      }
    }
    VUI.mount(requestsHolder, loading("Loading your requests…"));
    loadRequests();                                  // the one read on arrival (GET api/customer/data-rights)

    return h("div.cust-data-rights", {}, [
      rightsCard(),
      slaCard(),
      actionsCard(),
      h("div.card.cust-data-rights-history", {}, [h("h3", { text: "Your previous requests" }), requestsHolder]),
    ]);
  }

  window.VIGIL_DATA_RIGHTS = { viewDataRights: viewDataRights };
}());
