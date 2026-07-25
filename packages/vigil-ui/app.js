"use strict";
/* ==========================================================================
   VIGIL COMMAND — app.js : the unified shell + Home (P1).
   Federates two same-origin backends via a reverse proxy:
     window.VIGIL_CFG = { token, api: { sovereign: "/sovereign", offense: "/offense" } }
   Screens beyond Home are registered as guided stubs in P1; P2+ fill them in.
   CSP-native: built entirely with VUI.h (no inline handlers, no eval).
   ========================================================================== */
(function () {
  const V = window.VUI;
  const h = V.h;
  const CFG = window.VIGIL_CFG || (window.VIGIL_CFG = { token: "", api: { sovereign: "/sovereign", offense: "/offense" } });
  const SOV = function (p) { return CFG.api.sovereign + p; };
  const OFF = function (p) { return CFG.api.offense + p; };

  const app = V.store({ plane: "all", nav: [], counts: { agents: 0, tools: 0, findings: 0 }, live: "idle", waiting: 0, killed: false });

  // -- navigation model (every capability has a home; P1 marks not-yet-built) --
  const NAV = [
    { group: "DO", items: [
      { id: "home", label: "Home", icon: "home", ready: true },
      { id: "assess", label: "New Assessment", icon: "assess", phase: "P2" },
      { id: "live", label: "Live", icon: "live", phase: "P2" },
      { id: "findings", label: "Findings", icon: "find", phase: "P3" },
      { id: "fixes", label: "Fixes", icon: "fixes", phase: "P6" },
      { id: "defense", label: "Defense (AEGIS)", icon: "shield", phase: "P5" },
    ]},
    { group: "MANAGE", items: [
      { id: "safety", label: "Approvals & Safety", icon: "key", owner: true, phase: "P4" },
      { id: "brain", label: "Brain", icon: "brain", phase: "P7" },
      { id: "settings", label: "Settings", icon: "gear", owner: true, phase: "P4" },
    ]},
    { group: "LEARN", items: [
      { id: "manual", label: "Manual", icon: "book", ready: true },
    ]},
  ];

  // ---- shell -----------------------------------------------------------------
  function topbar() {
    const seg = h("div.segmented", null, ["all", "offense", "defense"].map(function (p) {
      return h("button" + (app.get().plane === p ? ".on" : ""), { dataset: { plane: p },
        onClick: function () { app.set({ plane: p }); renderNav(); } }, p[0].toUpperCase() + p.slice(1));
    }));
    const cmdk = h("div.cmdk", { title: "Command palette (⌘K)", onClick: openPalette },
      [V.icon("search"), "Search or run a command", h("span.kbd", null, "⌘K")]);
    const s = app.get();
    const live = s.killed ? V.pill("Kill-switch", "danger", null)
      : (s.live === "live" ? V.pill("Live", "live", null) : V.pill("Idle", "idle", null));
    const counts = h("div.counts", null, [
      h("span.count", null, [V.icon("brain"), h("b", null, String(s.counts.agents)), " agents"]),
      h("span.count", null, [V.icon("bolt"), h("b", null, String(s.counts.tools)), " tools"]),
      h("span.count", null, [V.icon("find"), h("b", null, String(s.counts.findings)), " findings"]),
    ]);
    const safety = s.killed
      ? h("button.safety.tripped", { onClick: function () { location.hash = "#/safety"; } }, "KILL-SWITCH TRIPPED")
      : (s.waiting > 0
        ? h("button.safety.waiting", { onClick: function () { location.hash = "#/safety"; } }, [V.icon("key"), s.waiting + " waiting for you"])
        : h("button.safety.clear", { onClick: function () { location.hash = "#/safety"; } }, [V.icon("check"), "Safe · 0 waiting"]));
    const themeBtn = h("button.iconbtn", { title: "Toggle theme", onClick: toggleTheme }, V.icon("dot"));
    const cta = h("button.btn.primary", { onClick: function () { location.hash = "#/assess"; } }, [V.icon("bolt"), "New Assessment"]);
    return h("div#topbar", null, [seg, cmdk, h("div.spacer"), counts, live, safety, themeBtn, cta]);
  }

  function renderNav() {
    const nav = V.$("#nav"); if (!nav) return;
    const plane = app.get().plane;
    const visible = function (it) {
      if (plane === "all") return true;
      if (it.id === "defense") return plane === "defense";
      if (["assess", "live", "findings", "fixes"].indexOf(it.id) >= 0) return plane === "offense";
      return true; // home + manage always
    };
    V.mount(nav, NAV.map(function (grp) {
      return [h("div.nav-group.label", null, grp.group),
        grp.items.filter(visible).map(function (it) { return navItem(it); })];
    }));
  }
  function navItem(it) {
    const active = current() === it.id;
    const badge = it.id === "safety" && app.get().waiting > 0
      ? h("span.badge-count.owner", null, String(app.get().waiting)) : null;
    return h("div.nav-item" + (it.owner ? ".owner" : "") + (active ? ".active" : ""),
      { dataset: { nav: it.id }, onClick: function () { location.hash = "#/" + it.id; } },
      [V.icon(it.icon), h("span.txt", null, it.label), badge]);
  }
  function current() { return (location.hash || "#/home").slice(2).split("?")[0] || "home"; }

  function shell() {
    document.body.appendChild(h("div#app", null, [
      h("div#brand", null, [h("span.logo", null, "V"), h("span.name", null, "VIGIL COMMAND")]),
      topbar(),
      h("div#nav"),
      h("div#main", null, h("div.wrap#screen")),
    ]));
    document.body.appendChild(h("div#drawer", null, [h("div.dh", null, [h("h2#drawer-title", null, "Detail"),
      h("button.iconbtn", { onClick: closeDrawer }, V.icon("x"))]), h("div.db#drawer-body")]));
    renderNav();
  }

  // ---- drawer ----------------------------------------------------------------
  function openDrawer(title, body) {
    V.$("#drawer-title").textContent = title || "Detail";
    V.mount(V.$("#drawer-body"), body);
    V.$("#drawer").classList.add("open");
  }
  function closeDrawer() { V.$("#drawer").classList.remove("open"); }

  function toggleTheme() {
    const cur = document.documentElement.getAttribute("data-theme");
    const next = cur === "light" ? "dark" : (cur === "dark" ? "light" : (matchMedia("(prefers-color-scheme: dark)").matches ? "light" : "dark"));
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("vigil-theme", next); } catch (e) {}
  }
  function openPalette() { V.toast("Command palette arrives in P2 — every action becomes searchable here."); }

  // ---- Home screen -----------------------------------------------------------
  async function renderHome(screen) {
    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "Command"),
        h("span.sub", null, "One place to run, watch, and govern every VIGIL assessment.")]),
      h("div.grid.cols-4#home-tiles"),
      h("div.grid.cols-2", { style: { marginTop: "16px", alignItems: "start" } }, [
        V.card("Quick start", "DO", quickStart(), false),
        V.card("Recent activity", "LIVE", h("div.feed#home-feed", null, h("div.empty", null, "Connecting to the live feed…")), false),
      ]),
    ]);
    // live data from both planes (fail-soft: a plane being down never blanks the page)
    let snap = null, ostat = null;
    try { snap = await V.getJSON(SOV("/api/snapshot")); } catch (e) { /* sovereign offline */ }
    try { ostat = await V.getJSON(OFF("/api/status")); } catch (e) { /* offense offline */ }
    const waiting = (snap && (snap.pending_approvals || []).length) || 0;
    const killed = !!(snap && snap.kill_switch && (snap.kill_switch.engaged || snap.kill_switch === "engaged"));
    const findings = (ostat && (ostat.findings_confirmed != null ? ostat.findings_confirmed : (ostat.findings || 0))) || 0;
    const runs = (ostat && (ostat.active_runs != null ? ostat.active_runs : 0)) || 0;
    app.set({ waiting: waiting, killed: killed, live: runs > 0 ? "live" : "idle",
      counts: { agents: (ostat && ostat.agents) || 0, tools: (ostat && ostat.tools) || 0, findings: findings } });
    refreshTopbar();
    V.mount(V.$("#home-tiles"), [
      V.tile("Active runs", String(runs), runs ? "in progress" : "nothing running"),
      V.tile("Waiting for you", String(waiting), waiting ? "needs approval" : "all clear", waiting ? "down" : "up"),
      V.tile("Confirmed findings", String(findings), "proven by oracle"),
      V.tile("Budget today", (snap && snap.budget_today != null ? "$" + snap.budget_today : "—"), "spend so far"),
    ]);
    // merged recent activity (sovereign spine snapshot has recent_by_agent / recent_decisions)
    const rows = [];
    if (snap && snap.recent_decisions) snap.recent_decisions.slice(0, 8).forEach(function (d) {
      rows.push(feedRow("decision", d.text || d.choice || "decision", d.ts || ""));
    });
    if (!rows.length) rows.push(h("div.empty", null, [h("div.big", null, "Nothing yet"),
      "Run your first assessment and every action shows up here, live."]));
    V.mount(V.$("#home-feed"), rows);
  }
  function quickStart() {
    const items = [
      { t: "Scan a codebase", d: "Point at a path or repo; the AI reads and reasons over it.", go: "#/assess" },
      { t: "Scan a website", d: "Give a URL; VIGIL crawls and safely probes it.", go: "#/assess" },
      { t: "Defend an app", d: "Watch your own app for AI attacks (AEGIS).", go: "#/defense" },
    ];
    return h("div.stack", null, items.map(function (it) {
      return h("button.choice", { onClick: function () { location.hash = it.go; } },
        [h("span.cico", null, V.icon("play")), h("div", null, [h("div.ct", null, it.t), h("div.cd", null, it.d)])]);
    }));
  }
  function feedRow(kind, text, ts) {
    return h("div.trow.kind-" + kind, null, [
      h("div.ico", null, V.icon(kind === "finding" ? "check" : (kind === "refusal" ? "x" : "dot"))),
      h("div.body", null, [h("div.k", null, kind), h("div.m", null, text)]),
      h("div.meta", null, [h("span.t", null, String(ts || ""))]),
    ]);
  }

  function refreshTopbar() {
    const bar = V.$("#topbar"); if (!bar) return;
    const fresh = topbar();
    bar.parentNode.replaceChild(fresh, bar);
    renderNav();
  }

  // ---- Manual (in-app documentation; real content, no runtime data) ---------
  function renderManual(screen) {
    const sections = window.VIGIL_MANUAL || [];
    const index = h("div.card", { style: { position: "sticky", top: "0", alignSelf: "start" } },
      [h("span.label", null, "CONTENTS"),
       h("div.stack", { style: { gap: "2px", marginTop: "8px" } }, sections.map(function (s) {
         return h("a.nav-item", { href: "#/manual", onClick: function (e) {
           e.preventDefault(); const t = document.getElementById("man-" + s.id);
           if (t) t.scrollIntoView({ behavior: "smooth", block: "start" });
         } }, [h("span.txt", null, s.title)]);
       }))]);
    const content = h("div.stack", null, sections.map(function (s) {
      return h("div.card", { id: "man-" + s.id }, [
        h("h3", { style: { fontSize: "var(--fs-xl)", marginBottom: "12px" } }, s.title),
        s.blocks.map(function (b) { return manualBlock(b); }),
      ]);
    }));
    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "Manual"),
        h("span.sub", null, "How every part of VIGIL works — in plain language.")]),
      h("div", { style: { display: "grid", gridTemplateColumns: "260px 1fr", gap: "24px", alignItems: "start" } },
        [index, content]),
    ]);
  }
  function manualBlock(b) {
    if (b.h) return h("h4", { style: { marginTop: "16px", marginBottom: "6px", fontSize: "var(--fs-lg)" } }, b.h);
    if (b.p) return h("p", { class: "muted", style: { margin: "8px 0", maxWidth: "72ch", lineHeight: "1.6" } }, b.p);
    if (b.note) return h("div.legend", { style: { margin: "12px 0" } }, [V.icon("info"), b.note]);
    if (b.list) return h("div.stack", { style: { gap: "10px", margin: "10px 0" } }, b.list.map(function (row) {
      return h("div", { style: { display: "grid", gridTemplateColumns: "180px 1fr", gap: "14px" } },
        [h("b", null, row[0]), h("span.muted", null, row[1])]);
    }));
    return null;
  }

  // ---- guided stub for not-yet-built screens --------------------------------
  function renderStub(screen, item) {
    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, item.label),
        h("span.sub", null, "This surface is part of the plan.")]),
      h("div.empty", null, [
        h("div.big", null, item.label + " — arriving in " + item.phase),
        h("p", null, "The design system and shell are live now (P1). This screen is wired next; the plan builds it in " + item.phase + "."),
        h("button.btn.primary", { style: { marginTop: "16px" }, onClick: function () { location.hash = "#/home"; } }, "Back to Command"),
      ]),
    ]);
  }

  // ---- boot ------------------------------------------------------------------
  function route() {
    const id = current();
    renderNav();
    const screen = V.$("#screen"); if (!screen) return;
    if (id === "home") { renderHome(screen); return; }
    if (id === "manual") { renderManual(screen); return; }
    let item = null;
    NAV.forEach(function (g) { g.items.forEach(function (it) { if (it.id === id) item = it; }); });
    if (item && item.ready) renderHome(screen); else renderStub(screen, item || { label: "Not found", phase: "—" });
  }

  function boot() {
    // config comes from the server-injected <body> data-attributes (CSP-native; no inline script).
    const ds = document.body.dataset;
    if (ds.token && ds.token !== "__VIGIL_TOKEN__") CFG.token = ds.token;
    if (ds.sovereign != null && ds.sovereign !== "__VIGIL_SOVEREIGN__") CFG.api.sovereign = ds.sovereign;
    if (ds.offense != null && ds.offense !== "__VIGIL_OFFENSE__") CFG.api.offense = ds.offense;
    try { const t = localStorage.getItem("vigil-theme"); if (t) document.documentElement.setAttribute("data-theme", t); } catch (e) {}
    shell();
    window.addEventListener("hashchange", route);
    if (!location.hash) location.hash = "#/home";
    route();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();
