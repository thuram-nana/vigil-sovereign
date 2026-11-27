/* VIGIL Security & Trust Center - access-request form enhancement.
 *
 * Same-origin, self script (the strict CSP forbids inline handlers and remote script). Progressive
 * enhancement: without this file the form still works (it posts to the same-origin endpoint, which
 * returns a small acknowledgement page) and the data-protection contact is shown for no-JS visitors.
 * With it, the form submits via fetch(), validates inline, and shows the server's neutral response
 * without leaving the page. It never claims access was granted or a document delivered.
 */
(function () {
  "use strict";
  var form = document.getElementById("access-form");
  if (!form) { return; }

  var FIELDS = ["full_name", "organisation", "email", "job_title", "reason"];
  var MAXLEN = { full_name: 200, organisation: 200, email: 254, job_title: 120, reason: 2000 };
  var EMAIL_RE = /^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$/;
  var statusEl = document.getElementById("access-status");
  var submitBtn = document.getElementById("access-submit");

  function el(id) { return document.getElementById(id); }

  function setErr(name, msg) {
    var e = el("err-" + name);
    var input = el(name);
    if (!e || !input) { return; }
    if (msg) {
      e.textContent = msg;
      e.hidden = false;
      input.setAttribute("aria-invalid", "true");
      input.setAttribute("aria-describedby", "err-" + name);
    } else {
      e.textContent = "";
      e.hidden = true;
      input.removeAttribute("aria-invalid");
      input.removeAttribute("aria-describedby");
    }
  }

  function clearErrors() { FIELDS.forEach(function (n) { setErr(n, ""); }); }

  function readValue(name) {
    var input = el(name);
    return input ? String(input.value || "").trim() : "";
  }

  function validateLocal() {
    var ok = true;
    var first = null;
    FIELDS.forEach(function (name) {
      var v = readValue(name);
      var msg = "";
      if (!v) { msg = "This field is required."; }
      else if (v.length > MAXLEN[name]) { msg = "Keep this to " + MAXLEN[name] + " characters or fewer."; }
      else if (name === "email" && !EMAIL_RE.test(v)) { msg = "Enter a valid email address."; }
      setErr(name, msg);
      if (msg && ok) { ok = false; first = el(name); }
    });
    if (first) { try { first.focus(); } catch (e) {} }
    return ok;
  }

  function setStatus(msg, kind) {
    if (!statusEl) { return; }
    statusEl.textContent = msg;
    statusEl.hidden = !msg;
    statusEl.classList.remove("is-ok", "is-err");
    if (kind) { statusEl.classList.add(kind); }
  }

  form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    clearErrors();
    setStatus("", null);
    if (!validateLocal()) {
      setStatus("Please check the highlighted fields.", "is-err");
      return;
    }
    var payload = {};
    FIELDS.forEach(function (name) { payload[name] = readValue(name); });

    if (submitBtn) { submitBtn.disabled = true; }
    setStatus("Sending your request...", null);

    fetch(form.getAttribute("action"), {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify(payload),
      credentials: "same-origin"
    }).then(function (resp) {
      return resp.json().then(function (data) { return { status: resp.status, data: data }; });
    }).then(function (res) {
      var data = res.data || {};
      if (res.status === 200 && data.ok) {
        form.classList.add("is-done");
        if (submitBtn) { submitBtn.disabled = true; }
        setStatus(data.message || "Request received.", "is-ok");
        return;
      }
      if (submitBtn) { submitBtn.disabled = false; }
      if (res.status === 400 && data.fields) {
        Object.keys(data.fields).forEach(function (name) {
          if (FIELDS.indexOf(name) !== -1) { setErr(name, humanize(data.fields[name])); }
        });
        setStatus("Please check the highlighted fields.", "is-err");
        return;
      }
      if (res.status === 429) {
        setStatus(data.message || "Too many requests. Please try again later.", "is-err");
        return;
      }
      setStatus((data.message) ? data.message
        : "We could not record your request right now. Please email info@sigilsovereign.com.", "is-err");
    }).catch(function () {
      if (submitBtn) { submitBtn.disabled = false; }
      setStatus("Something went wrong sending your request. Please email info@sigilsovereign.com.", "is-err");
    });
  });

  function humanize(s) {
    s = String(s || "This field needs attention.");
    return s.charAt(0).toUpperCase() + s.slice(1) + (/[.!?]$/.test(s) ? "" : ".");
  }
})();
