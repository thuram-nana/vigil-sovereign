/* VIGIL CVSS v3.1 base calculator — pure client-side, re-derived from the public FIRST.org spec.
   No network, no inline handlers (strict-CSP native). Base metrics only. */
(function () {
  "use strict";

  // Base metric definitions in vector order: {id, name, options:[{v,label}]}
  var METRICS = [
    { id: "AV", name: "Attack Vector", opts: [["N", "Network"], ["A", "Adjacent"], ["L", "Local"], ["P", "Physical"]] },
    { id: "AC", name: "Attack Complexity", opts: [["L", "Low"], ["H", "High"]] },
    { id: "PR", name: "Privileges Required", opts: [["N", "None"], ["L", "Low"], ["H", "High"]] },
    { id: "UI", name: "User Interaction", opts: [["N", "None"], ["R", "Required"]] },
    { id: "S", name: "Scope", opts: [["U", "Unchanged"], ["C", "Changed"]] },
    { id: "C", name: "Confidentiality", opts: [["N", "None"], ["L", "Low"], ["H", "High"]] },
    { id: "I", name: "Integrity", opts: [["N", "None"], ["L", "Low"], ["H", "High"]] },
    { id: "A", name: "Availability", opts: [["N", "None"], ["L", "Low"], ["H", "High"]] },
  ];
  var ORDER = METRICS.map(function (m) { return m.id; });
  var VALID = {}; METRICS.forEach(function (m) { VALID[m.id] = m.opts.map(function (o) { return o[0]; }); });

  // weight tables (FIRST.org CVSS 3.1)
  var W = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
    AC: { L: 0.77, H: 0.44 },
    UI: { N: 0.85, R: 0.62 },
    C: { N: 0, L: 0.22, H: 0.56 }, I: { N: 0, L: 0.22, H: 0.56 }, A: { N: 0, L: 0.22, H: 0.56 },
    PR: { U: { N: 0.85, L: 0.62, H: 0.27 }, C: { N: 0.85, L: 0.68, H: 0.5 } },
  };

  function roundup(x) {                 // the exact CVSS 3.1 roundup (to 1 decimal)
    var i = Math.round(x * 100000);
    return (i % 10000 === 0) ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
  }

  function score(sel) {
    var iss = 1 - (1 - W.C[sel.C]) * (1 - W.I[sel.I]) * (1 - W.A[sel.A]);
    var impact = sel.S === "U" ? 6.42 * iss
      : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
    var expl = 8.22 * W.AV[sel.AV] * W.AC[sel.AC] * W.PR[sel.S][sel.PR] * W.UI[sel.UI];
    var base = impact <= 0 ? 0
      : roundup(Math.min((sel.S === "C" ? 1.08 : 1) * (impact + expl), 10));
    return { base: base, impact: Math.round(impact * 10) / 10, expl: Math.round(expl * 10) / 10 };
  }

  function severity(s) {
    if (s <= 0) return ["None", "info"];
    if (s < 4) return ["Low", "low"];
    if (s < 7) return ["Medium", "medium"];
    if (s < 9) return ["High", "high"];
    return ["Critical", "critical"];
  }

  function vector(sel) {
    return "CVSS:3.1/" + ORDER.map(function (id) { return id + ":" + sel[id]; }).join("/");
  }

  function parseVector(str) {
    var sel = {}, parts = String(str || "").replace(/^CVSS:3\.1\//i, "").split("/");
    parts.forEach(function (p) {
      var kv = p.split(":"), id = (kv[0] || "").toUpperCase(), v = (kv[1] || "").toUpperCase();
      if (VALID[id] && VALID[id].indexOf(v) !== -1) sel[id] = v;
    });
    return sel;
  }

  // --- state + render ---
  var sel = {}; METRICS.forEach(function (m) { sel[m.id] = m.opts[0][0]; });  // default: first option each
  var form = document.getElementById("cvss-form");
  var elScore = document.getElementById("cvss-score");
  var elSev = document.getElementById("cvss-sev");
  var elVec = document.getElementById("cvss-vector-str");
  var elSub = document.getElementById("cvss-sub");
  var groups = {};

  function render() {
    var r = score(sel), sv = severity(r.base);
    elScore.textContent = r.base.toFixed(1);
    elScore.style.color = "var(--sev-" + sv[1] + ")";
    elSev.textContent = sv[0];
    elSev.style.color = "var(--sev-" + sv[1] + ")";
    elSev.style.borderColor = "var(--sev-" + sv[1] + ")";
    elVec.value = vector(sel);
    elSub.textContent = "Impact " + r.impact.toFixed(1) + " · Exploitability " + r.expl.toFixed(1);
    Object.keys(groups).forEach(function (id) {
      groups[id].forEach(function (btn) {
        btn.setAttribute("aria-pressed", btn.dataset.val === sel[id] ? "true" : "false");
      });
    });
  }

  function buildGroups() {
    METRICS.forEach(function (m) {
      var g = document.createElement("fieldset"); g.className = "cvss__group";
      var lg = document.createElement("legend"); lg.textContent = m.name; g.appendChild(lg);
      var row = document.createElement("div"); row.className = "cvss__opts";
      groups[m.id] = [];
      m.opts.forEach(function (o) {
        var b = document.createElement("button");
        b.type = "button"; b.className = "cvss__opt"; b.textContent = o[1];
        b.dataset.metric = m.id; b.dataset.val = o[0]; b.setAttribute("aria-pressed", "false");
        b.title = m.id + ":" + o[0];
        b.addEventListener("click", function () { sel[m.id] = o[0]; sync(); render(); });
        row.appendChild(b); groups[m.id].push(b);
      });
      g.appendChild(row); form.appendChild(g);
    });
  }

  function sync() {                      // reflect state into the URL (shareable, no reload)
    try {
      var u = new URL(window.location.href);
      u.searchParams.set("vector", vector(sel));
      window.history.replaceState(null, "", u);
    } catch (e) { /* history API unavailable — the copy-link button still works */ }
  }

  function copy(text, btn) {
    var done = function () { var t = btn.textContent; btn.textContent = "Copied"; setTimeout(function () { btn.textContent = t; }, 1200); };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text, done); });
    } else { fallbackCopy(text, done); }
  }
  function fallbackCopy(text, done) {
    try { elVec.focus(); elVec.select(); document.execCommand("copy"); done(); } catch (e) { /* no-op */ }
  }

  // init
  buildGroups();
  (function fromUrl() {
    try {
      var v = new URL(window.location.href).searchParams.get("vector");
      if (v) { var p = parseVector(v); Object.keys(p).forEach(function (id) { sel[id] = p[id]; }); }
    } catch (e) { /* no URL — defaults stand */ }
  })();
  document.getElementById("cvss-copy").addEventListener("click", function () { copy(vector(sel), this); });
  document.getElementById("cvss-link").addEventListener("click", function () {
    var u; try { u = new URL(window.location.href); u.searchParams.set("vector", vector(sel)); u = u.toString(); }
    catch (e) { u = window.location.href; } copy(u, this);
  });
  document.getElementById("cvss-reset").addEventListener("click", function () {
    METRICS.forEach(function (m) { sel[m.id] = m.opts[0][0]; }); sync(); render();
  });
  render();
})();
