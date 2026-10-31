/* VIGIL public CVE browser — client-side, same-origin fetch of /api/cve. No inline handlers (strict CSP);
   all feed-derived text is set via textContent (never innerHTML) so a hostile feed string can't inject. */
(function () {
  "use strict";

  function el(tag, attrs, children) {
    var e = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      if (k === "class") e.className = attrs[k];
      else if (k === "text") e.textContent = attrs[k];
      else if (k === "href" || k === "type" || k === "value" || k === "aria-label" || k === "rel" || k === "target")
        e.setAttribute(k, attrs[k]);
      else e.setAttribute(k, attrs[k]);
    });
    (children || []).forEach(function (c) { if (c != null) e.appendChild(typeof c === "string" ? document.createTextNode(c) : c); });
    return e;
  }
  function api(path) {
    return fetch(path, { headers: { "Accept": "application/json" } }).then(function (r) { return r.json(); });
  }
  function qs() { try { return new URL(window.location.href).searchParams; } catch (e) { return new URLSearchParams(); } }
  function sevClass(s) { return ({ critical: "critical", high: "high", medium: "medium", low: "low", none: "info" })[s] || "info"; }

  function chips(rec) {
    var row = el("span", { class: "cve-chips" }, []);
    if (rec.severity) {
      var c = el("span", { class: "chip" }, [ (rec.cvss_base != null ? (rec.cvss_base + " ") : "") + rec.severity ]);
      c.style.color = "var(--sev-" + sevClass(rec.severity) + ")";
      c.style.borderColor = "var(--sev-" + sevClass(rec.severity) + ")";
      row.appendChild(c);
    }
    if (rec.kev) row.appendChild(el("span", { class: "chip chip--kev", text: "KEV · exploited" }));
    if (rec.ransomware) row.appendChild(el("span", { class: "chip chip--ransom", text: "ransomware" }));
    if (rec.epss_score != null) row.appendChild(el("span", { class: "chip", text: "EPSS " + Math.round(rec.epss_score * 100) + "%" }));
    if (rec.vigil_exploit) row.appendChild(el("span", { class: "chip chip--fact", text: "VIGIL-proven" }));
    return row;
  }

  // ---- listing ----
  function renderList(mount, pager, fixed) {
    var p = qs();
    var params = new URLSearchParams();
    params.set("page", p.get("page") || "1");
    params.set("per_page", "25");
    if (fixed && fixed.year) params.set("year", fixed.year);
    else if (p.get("year")) params.set("year", p.get("year"));
    ["severity", "q", "order"].forEach(function (k) { if (p.get(k)) params.set(k, p.get(k)); });
    if (p.get("kev")) params.set("kev", p.get("kev"));
    mount.textContent = "";
    mount.appendChild(el("p", { class: "muted", text: "Loading…" }));
    api("/api/cve?" + params.toString()).then(function (res) {
      mount.textContent = "";
      if (res.populated === false) {
        mount.appendChild(el("div", { class: "card" }, [
          el("h3", { text: "Catalog not yet populated" }),
          el("p", { class: "muted", text: "Run `vigil cve ingest` to pull the public CVE feeds (CISA-KEV, NVD, EPSS) into the catalog." })]));
        return;
      }
      if (!res.items.length) { mount.appendChild(el("p", { class: "muted", text: "No CVEs match these filters." })); return; }
      var list = el("div", { class: "cve-rows" }, []);
      res.items.forEach(function (rec) {
        var a = el("a", { class: "cve-row", href: "/cve/" + rec.id }, [
          el("div", { class: "cve-row__id" }, [rec.id]),
          el("div", { class: "cve-row__title", text: rec.title || rec.description || "—" }),
          chips(rec)]);
        list.appendChild(a);
      });
      mount.appendChild(list);
      renderPager(pager, res, fixed);
    }).catch(function () { mount.textContent = ""; mount.appendChild(el("p", { class: "muted", text: "Could not load CVEs." })); });
  }

  function renderPager(pager, res, fixed) {
    if (!pager) return;
    pager.textContent = "";
    var base = fixed && fixed.year ? ("/cve/year/" + fixed.year) : "/cve";
    function link(label, page, disabled) {
      if (disabled) return el("span", { class: "btn btn--ghost cve-pg-off", text: label });
      var p = qs(); p.set("page", page);
      return el("a", { class: "btn btn--ghost", href: base + "?" + p.toString() }, [label]);
    }
    pager.appendChild(link("‹ Prev", Math.max(1, res.page - 1), res.page <= 1));
    pager.appendChild(el("span", { class: "muted cve-pg-info", text: "Page " + res.page + " of " + res.pages + " · " + res.total + " CVEs" }));
    pager.appendChild(link("Next ›", Math.min(res.pages, res.page + 1), res.page >= res.pages));
  }

  function renderStats(mount) {
    api("/api/cve/stats").then(function (s) {
      if (!mount || s.populated === false) return;
      function stat(n, l) { return el("div", { class: "stat" }, [el("div", { class: "n", text: String(n) }), el("div", { class: "l", text: l })]); }
      mount.appendChild(stat(s.total.toLocaleString(), "CVEs in catalog"));
      mount.appendChild(stat(s.kev.toLocaleString(), "Known exploited (KEV)"));
      if (s.vigil_proven) mount.appendChild(stat(s.vigil_proven.toLocaleString(), "VIGIL-proven affected"));
    }).catch(function () {});
  }

  function wireFilters() {
    var form = document.getElementById("cve-filters");
    if (!form) return;
    var p = qs();
    var f = { q: document.getElementById("f-q"), sev: document.getElementById("f-sev"),
              year: document.getElementById("f-year"), order: document.getElementById("f-order"),
              kev: document.getElementById("f-kev") };
    if (f.q) f.q.value = p.get("q") || "";
    if (f.sev) f.sev.value = p.get("severity") || "";
    if (f.order) f.order.value = p.get("order") || "published_desc";
    if (f.kev) f.kev.checked = p.get("kev") === "1";
    // populate years
    if (f.year) api("/api/cve/years").then(function (r) {
      (r.years || []).forEach(function (y) { f.year.appendChild(el("option", { value: String(y.year), text: y.year + " (" + y.count + ")" })); });
      f.year.value = p.get("year") || "";
    }).catch(function () {});
    function apply() {
      var np = new URLSearchParams();
      if (f.q && f.q.value.trim()) np.set("q", f.q.value.trim());
      if (f.sev && f.sev.value) np.set("severity", f.sev.value);
      if (f.year && f.year.value) np.set("year", f.year.value);
      if (f.order && f.order.value) np.set("order", f.order.value);
      if (f.kev && f.kev.checked) np.set("kev", "1");
      np.set("page", "1");
      try { var u = new URL(window.location.href); u.search = np.toString(); window.history.replaceState(null, "", u); } catch (e) {}
      renderList(document.getElementById("cve-list"), document.getElementById("cve-pager"), null);
    }
    form.addEventListener("submit", function (e) { e.preventDefault(); apply(); });
    ["f-sev", "f-year", "f-order", "f-kev"].forEach(function (id) { var e = document.getElementById(id); if (e) e.addEventListener("change", apply); });
    if (f.q) f.q.addEventListener("keydown", function (e) { if (e.key === "Enter") { e.preventDefault(); apply(); } });
  }

  // ---- detail ----
  function kvRow(dl, k, v) { if (v == null || v === "") return; dl.appendChild(el("dt", { text: k })); dl.appendChild(el("dd", { text: String(v) })); }

  function renderDetail(mount) {
    var m = window.location.pathname.match(/\/cve\/(CVE-\d{4}-\d{4,})/i);
    if (!m) { mount.textContent = ""; mount.appendChild(el("p", { class: "muted", text: "Invalid CVE id." })); return; }
    var id = m[1].toUpperCase();
    api("/api/cve/" + id).then(function (rec) {
      mount.textContent = "";
      if (!rec || rec.error) {
        mount.appendChild(el("p", { class: "eyebrow", text: "CVE database" }));
        mount.appendChild(el("h1", { text: id }));
        mount.appendChild(el("p", { class: "muted", text: "Not found in the catalog. It may not be in the ingested feeds yet." }));
        return;
      }
      mount.appendChild(el("p", { class: "eyebrow" }, [el("a", { class: "muted", href: "/cve" }, ["CVE database"]), " › " + id]));
      mount.appendChild(el("h1", { class: "cve-detail__id", text: rec.title || id }));
      mount.appendChild(el("div", { class: "cve-detail__id-sub muted", text: id }));
      var cr = chips(rec); cr.style.margin = "var(--sp-3) 0"; mount.appendChild(cr);
      if (rec.description) mount.appendChild(el("p", { class: "cve-detail__desc", text: rec.description }));
      var dl = el("dl", { class: "kv" }, []);
      kvRow(dl, "Published", rec.published);
      kvRow(dl, "Last modified", rec.last_modified);
      kvRow(dl, "Status", rec.status);
      if (rec.cvss_base != null) kvRow(dl, "CVSS", rec.cvss_base + (rec.cvss_version ? (" (v" + rec.cvss_version + ")") : ""));
      if (rec.epss_score != null) kvRow(dl, "EPSS", Math.round(rec.epss_score * 1000) / 10 + "% probability (p" + Math.round((rec.epss_pct || 0) * 100) + ")");
      if (rec.kev) kvRow(dl, "CISA-KEV", "Added " + (rec.kev_date || "—") + (rec.ransomware ? " · used in ransomware" : ""));
      if (rec.cwes && rec.cwes.length) kvRow(dl, "Weaknesses", rec.cwes.join(", "));
      mount.appendChild(dl);
      if (rec.cvss_vector) {
        var vp = el("p", {}, [el("a", { class: "btn btn--ghost", href: "/tools/cvss-calculator?vector=" + encodeURIComponent(rec.cvss_vector) }, ["Open vector in the CVSS calculator →"])]);
        mount.appendChild(vp);
      }
      if (rec.affected && rec.affected.length) {
        mount.appendChild(el("h2", { class: "cve-detail__h2", text: "Affected" }));
        var ul = el("ul", {}, []);
        rec.affected.forEach(function (a) { ul.appendChild(el("li", { text: [a.vendor, a.product, a.ecosystem, a.name].filter(Boolean).join(" / ") || "—" })); });
        mount.appendChild(ul);
      }
      if (rec.refs && rec.refs.length) {
        mount.appendChild(el("h2", { class: "cve-detail__h2", text: "References" }));
        var rl = el("ul", {}, []);
        rec.refs.slice(0, 40).forEach(function (r) { if (r && r.url) rl.appendChild(el("li", {}, [el("a", { href: r.url, rel: "noopener noreferrer nofollow", target: "_blank", text: r.url })])); });
        mount.appendChild(rl);
      }
      mount.appendChild(el("p", { class: "muted cve-detail__note", text: "Intel is a lead, not a verdict: VIGIL mints a FACT only when an oracle proves a specific version exploitable in your stack." }));
    }).catch(function () { mount.textContent = ""; mount.appendChild(el("p", { class: "muted", text: "Could not load this CVE." })); });
  }

  // ---- boot ----
  document.addEventListener("DOMContentLoaded", function () {
    var detail = document.getElementById("cve-detail");
    if (detail) { renderDetail(detail); return; }
    var ym = window.location.pathname.match(/\/cve\/year\/(\d{4})/);
    var list = document.getElementById("cve-list");
    if (ym) {
      var lbl = document.getElementById("cve-year-label"), h1 = document.getElementById("cve-year-h1");
      if (lbl) lbl.textContent = ym[1];
      if (h1) h1.textContent = "CVEs published in " + ym[1];
      if (list) renderList(list, document.getElementById("cve-pager"), { year: ym[1] });
      return;
    }
    renderStats(document.getElementById("cve-stats"));
    wireFilters();
    if (list) renderList(list, document.getElementById("cve-pager"), null);
  });
})();
